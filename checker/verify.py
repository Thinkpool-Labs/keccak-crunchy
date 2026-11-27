"""Judge one solution file.

    python checker/verify.py solutions/<file>.json

A solution is
    {"kind": "collision" | "preimage", "width": 200 | 400 | 800 | 1600, "rounds": 1..12, "start": 0..254,
     "messages": [{"hex": "...", "bits": n}, ...],   # two for a collision, one for a preimage
     "authors": "...", "method": "..."}             # free text, optional, shown to the host only

A message is `bits` bits, written as exactly ceil(bits / 8) bytes of lower-case hex with bit k of the
message in bit k % 8 of byte k // 8 (KeccakTools' order). The unused high bits of the last byte must be
zero, so each message has one spelling.

VALID means: for a preimage, the first 80 output bits equal the challenge's target; for a collision,
the two messages differ and their first 160 output bits are equal. `nominal` says whether the rounds
lie within Keccak-f[b]'s own (0 <= start, start + rounds <= 12 + 2l), which the contest requires.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from keccak import WIDTHS, crunchy_hash, nominal_rounds  # noqa: E402

MAX_BITS = 1 << 16            # 8 KiB a message; the longest published solution is 28,798 bits
HEX = re.compile(r"^(?:[0-9a-f]{2}){0,8192}$")
KEYS = {"kind", "width", "rounds", "start", "messages", "authors", "method"}
OUT_BITS = {"collision": 160, "preimage": 80}

_RECORDS = Path(__file__).resolve().parents[1] / "RECORDS.json"


def targets() -> dict[tuple[int, int], str]:
    cells = json.loads(_RECORDS.read_text(encoding="utf-8"))["cells"]
    return {(c["width"], c["rounds"]): c["target"] for c in cells if c["kind"] == "preimage"}


def _int(v, name: str, lo: int, hi: int) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise ValueError(f"{name} must be an integer from {lo} to {hi}")
    return v


def _message(m) -> tuple[bytes, int]:
    if not isinstance(m, dict) or set(m) != {"hex", "bits"}:
        raise ValueError('each message is {"hex": "...", "bits": n}')
    bits = _int(m["bits"], "bits", 0, MAX_BITS)
    h = m["hex"]
    if not isinstance(h, str) or not HEX.match(h):
        raise ValueError("hex must be lower-case hex digits, two per byte")
    data = bytes.fromhex(h)
    if len(data) != (bits + 7) // 8:
        raise ValueError("hex must hold exactly ceil(bits / 8) bytes")
    if bits % 8 and data[-1] >> (bits % 8):
        raise ValueError("the unused high bits of the last byte must be zero")
    return data, bits


def judge(sol) -> dict:
    if not isinstance(sol, dict) or not {"kind", "width", "rounds", "start", "messages"} <= set(sol) <= KEYS:
        raise ValueError(f"a solution has the keys kind, width, rounds, start, messages (and optionally authors, method)")
    for k in ("authors", "method"):
        if k in sol and (not isinstance(sol[k], str) or len(sol[k]) > 2000):
            raise ValueError(f"{k} is text of at most 2000 characters")
    kind = sol["kind"]
    if kind not in OUT_BITS:
        raise ValueError('kind is "collision" or "preimage"')
    width = sol["width"]
    if type(width) is not int or width not in WIDTHS:
        raise ValueError("width is 200, 400, 800 or 1600")
    rounds = _int(sol["rounds"], "rounds", 1, 12)
    start = _int(sol["start"], "start", 0, 254)
    msgs = sol["messages"]
    want = 2 if kind == "collision" else 1
    if not isinstance(msgs, list) or len(msgs) != want:
        raise ValueError(f"a {kind} has {want} message{'s' if want > 1 else ''}")
    parsed = [_message(m) for m in msgs]
    outs = [crunchy_hash(width, start, rounds, d, b, OUT_BITS[kind]) for d, b in parsed]
    if kind == "collision":
        ok = parsed[0] != parsed[1] and outs[0] == outs[1]
    else:
        ok = outs[0].hex() == targets()[(width, rounds)]
    return {"verdict": "VALID" if ok else "INVALID", "kind": kind, "width": width, "rounds": rounds,
            "start": start, "nominal": start + rounds <= nominal_rounds(width),
            "output": outs[0].hex()}


if __name__ == "__main__":
    print(json.dumps(judge(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))))
