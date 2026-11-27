"""The checker against the designers' own numbers. Run: python -m pytest tests -q"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checker"))

from keccak import RC64, crunchy_hash, nominal_rounds, sponge  # noqa: E402
from verify import judge  # noqa: E402

PUBLISHED = json.loads((ROOT / "tests" / "published.json").read_text(encoding="utf-8"))
SAT_FOUND = json.loads((ROOT / "tests" / "sat_found.json").read_text(encoding="utf-8"))
CELLS = json.loads((ROOT / "RECORDS.json").read_text(encoding="utf-8"))["cells"]


def suffixed(msg: bytes, suffix: int = 0b10, k: int = 2) -> tuple[bytes, int]:
    """msg followed by FIPS 202's domain bits (SHA-3: 0 then 1; SHAKE: 1111), before pad10*1."""
    n = len(msg) * 8
    v = int.from_bytes(msg, "little") | (suffix << n)
    return v.to_bytes((n + k + 7) // 8, "little"), n + k


@pytest.mark.parametrize("msg", [b"", b"abc", bytes(range(256)) * 3])
def test_full_keccak_f1600_matches_sha3(msg):
    m, bits = suffixed(msg)
    assert sponge(1600, 1088, 0, 24, m, bits, 256) == hashlib.sha3_256(msg).digest()
    assert sponge(1600, 576, 0, 24, m, bits, 512) == hashlib.sha3_512(msg).digest()
    m, bits = suffixed(msg, 0b1111, 4)
    assert sponge(1600, 1344, 0, 24, m, bits, 1344 * 2) == hashlib.shake_128(msg).digest(336)


def test_keccak256_of_empty():
    # Keccak-256 (the pre-FIPS padding Ethereum uses) of the empty string.
    assert sponge(1600, 1088, 0, 24, b"", 0, 256).hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_round_constants_and_nominal_rounds():
    assert RC64[0] == 0x1 and RC64[1] == 0x8082 and RC64[23] == 0x8000000080008008
    assert [nominal_rounds(b) for b in (200, 400, 800, 1600)] == [18, 20, 22, 24]


def test_every_published_solution_verifies():
    """43 solutions from KeccakCrunchyContest.cpp and keccak.team/crunchy_mails, all widths, first rounds
    and later ones (start 3, 5, 9, 14), outside the nominal rounds (93, 73), and messages whose length is
    not a whole number of bytes (117, 517, 17275 bits)."""
    assert len(PUBLISHED) >= 40
    starts = {v["start"] for v in PUBLISHED}
    assert {0, 3, 5, 9, 14, 73, 93} <= starts
    for v in PUBLISHED:
        sol = {k: v[k] for k in ("kind", "width", "rounds", "start", "messages")}
        out = judge(sol)
        assert out["verdict"] == "VALID", v["source"]


def test_solutions_found_by_the_sat_baseline_verify():
    for sol in SAT_FOUND:
        assert judge(sol)["verdict"] == "VALID"


def test_corruptions_fail():
    pre = next(v for v in PUBLISHED if v["kind"] == "preimage" and v["width"] == 200)
    coll = next(v for v in PUBLISHED if v["kind"] == "collision" and v["width"] == 200)
    for v in (pre, coll):
        sol = {k: v[k] for k in ("kind", "width", "rounds", "start", "messages")}
        assert judge(sol)["verdict"] == "VALID"
        flipped = json.loads(json.dumps(sol))
        h = bytearray.fromhex(flipped["messages"][0]["hex"])
        h[0] ^= 1
        flipped["messages"][0]["hex"] = h.hex()
        assert judge(flipped)["verdict"] == "INVALID"
        shifted = dict(sol, start=sol["start"] + 1)
        assert judge(shifted)["verdict"] == "INVALID"
    same = {k: coll[k] for k in ("kind", "width", "rounds", "start")}
    same["messages"] = [coll["messages"][0], coll["messages"][0]]
    assert judge(same)["verdict"] == "INVALID"  # a message does not collide with itself


def test_strict_shapes():
    good = {k: SAT_FOUND[0][k] for k in ("kind", "width", "rounds", "start", "messages")}
    bad = [
        dict(good, width=1601), dict(good, width=True), dict(good, rounds=13), dict(good, rounds=0),
        dict(good, start=-1), dict(good, start=255), dict(good, kind="second-preimage"),
        dict(good, messages=good["messages"] * 2), dict(good, extra=1),
        dict(good, messages=[{"hex": good["messages"][0]["hex"].upper(), "bits": good["messages"][0]["bits"]}]),
        dict(good, messages=[{"hex": good["messages"][0]["hex"] + "00", "bits": good["messages"][0]["bits"]}]),
        dict(good, messages=[{"hex": "ff", "bits": 3}]),  # unused high bits must be zero
        dict(good, messages=[{"hex": "", "bits": 1 << 17}]),
    ]
    for b in bad:
        with pytest.raises(ValueError):
            judge(b)


def test_huge_inputs_are_refused_fast():
    good = {k: SAT_FOUND[0][k] for k in ("kind", "width", "rounds", "start", "messages")}
    t0 = time.time()
    with pytest.raises(ValueError):
        judge(dict(good, messages=[{"hex": "00" * 9000, "bits": 72000}]))
    assert time.time() - t0 < 1
    # The largest message the checker takes, on the slowest width, stays well inside the time limit.
    t0 = time.time()
    crunchy_hash(200, 0, 12, bytes(8192), 1 << 16, 160)
    assert time.time() - t0 < 5


def test_records_cover_every_cell():
    assert len(CELLS) == 96
    keys = {(c["kind"], c["width"], c["rounds"]) for c in CELLS}
    assert len(keys) == 96
    assert all(len(c["target"]) == 20 for c in CELLS if c["kind"] == "preimage")
    assert {c["status"] for c in CELLS} == {"open", "solved", "closed"}


def run_check(tmp_path: Path, files: dict[str, dict], open_cells=()) -> subprocess.CompletedProcess:
    copy = tmp_path / f"pool{len(list(tmp_path.iterdir()))}"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    for f in (copy / "solutions").glob("*.json"):
        f.unlink()
    for name, sol in files.items():
        (copy / "solutions" / name).write_text(json.dumps(sol), encoding="utf-8")
    if open_cells:
        rec = json.loads((copy / "RECORDS.json").read_text(encoding="utf-8"))
        for c in rec["cells"]:
            if (c["kind"], c["width"], c["rounds"]) in open_cells:
                c["status"] = "open"
        (copy / "RECORDS.json").write_text(json.dumps(rec), encoding="utf-8")
    return subprocess.run([sys.executable, "-I", "checker/check_all.py"], cwd=copy, capture_output=True, text=True)


def published(source_prefix: str) -> dict:
    v = next(v for v in PUBLISHED if v["source"].startswith(source_prefix))
    return {k: v[k] for k in ("kind", "width", "rounds", "start", "messages")}


def test_check_all_credits_only_open_cells(tmp_path):
    warm = published("coll-r2-w200")
    r = run_check(tmp_path, {"warm.json": warm})
    assert r.returncode == 1, r.stdout            # a solved cell is a warm-up
    assert "warm-up" in r.stdout
    r = run_check(tmp_path, {"warm.json": warm}, open_cells={("collision", 200, 2)})
    assert r.returncode == 0, r.stdout            # the same file passes once its cell is open


def test_outside_the_nominal_rounds_is_never_credited(tmp_path):
    # Liu et al.'s 3-round width-200 preimage uses rounds 93-95; the designers keep the cell open.
    liu = next(v for v in PUBLISHED if v["width"] == 200 and v["rounds"] == 3)
    sol = {k: liu[k] for k in ("kind", "width", "rounds", "start", "messages")}
    out = judge(sol)
    assert out["verdict"] == "VALID" and out["nominal"] is False
    r = run_check(tmp_path, {"liu.json": sol})
    assert r.returncode == 1 and "outside" in r.stdout, r.stdout


def test_one_bad_file_fails_the_check(tmp_path):
    warm = published("coll-r2-w200")
    broken = json.loads(json.dumps(warm))
    broken["messages"][1] = broken["messages"][0]
    r = run_check(tmp_path, {"warm.json": warm, "broken.json": broken}, open_cells={("collision", 200, 2)})
    assert r.returncode == 1


def test_the_tree_must_be_the_pools(tmp_path):
    r = run_check(tmp_path, {"warm.json": published("coll-r2-w200")}, open_cells={("collision", 200, 2)})
    assert r.returncode == 0
    copy = tmp_path / "pool0"
    (copy / "solutions" / "sitecustomize.py").write_text("raise SystemExit(0)\n")
    r = subprocess.run([sys.executable, "-I", "checker/check_all.py"], cwd=copy, capture_output=True, text=True)
    assert r.returncode == 1 and "not the pool" in r.stdout
