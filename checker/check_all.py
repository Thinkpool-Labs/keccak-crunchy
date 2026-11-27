"""The pool's check: every solution is valid, and at least one solves an open cell.

    python checker/check_all.py

Exit 0 when every file in solutions/ is VALID and at least one is, within the nominal rounds, a
solution for a cell RECORDS.json lists as open. Thinkpool runs this without and with a contribution's
diff: a new solution fails before and passes after. Solutions for solved or closed cells, and
solutions whose rounds lie outside Keccak-f[b]'s own, are checked and printed but never credited:
they are how you learn the attacks. Exit 1 otherwise. Prints one JSON line per file, then a summary.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checker"))

from hygiene import problems  # noqa: E402
from verify import judge  # noqa: E402

MAX_FILES = 100


def main() -> int:
    bad = problems(ROOT, "solutions")
    if bad:
        print(json.dumps({"summary": "the tree is not the pool's", "problems": bad[:20]}))
        return 1
    cells = json.loads((ROOT / "RECORDS.json").read_text(encoding="utf-8"))["cells"]
    status = {(c["kind"], c["width"], c["rounds"]): c["status"] for c in cells}
    files = sorted((ROOT / "solutions").glob("*.json"))
    if len(files) > MAX_FILES:
        print(json.dumps({"summary": "too many solution files", "limit": MAX_FILES}))
        return 1
    ok, new = True, []
    for f in files:
        try:
            if f.is_symlink() or not f.is_file():
                raise ValueError("not a regular file")
            out = judge(json.loads(f.read_text(encoding="utf-8")))
        except Exception as e:
            out = {"verdict": "MALFORMED", "reason": str(e)}
        out["file"] = f.name
        if out["verdict"] == "VALID":
            cell = status[(out["kind"], out["width"], out["rounds"])]
            if not out["nominal"]:
                out["credit"] = "none: the rounds lie outside Keccak-f[b]'s own, which the contest excludes"
            elif cell != "open":
                out["credit"] = f"none: the cell is {cell} (a warm-up)"
            else:
                out["credit"] = "an open cell"
                new.append({"file": f.name, "kind": out["kind"], "width": out["width"], "rounds": out["rounds"],
                            "start": out["start"]})
        else:
            ok = False
        print(json.dumps(out))
    print(json.dumps({"summary": "ok" if ok and new else "no open cell solved" if ok else "a solution is not valid",
                      "new": new}))
    return 0 if ok and new else 1


if __name__ == "__main__":
    sys.exit(main())
