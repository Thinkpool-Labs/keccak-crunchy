"""Turn the designers' published solutions into test vectors.

    python baselines/extract_published.py KeccakCrunchyContest.cpp crunchy_mails/*.txt > tests/published.json

Reads every verifyPreimageChallenge(...) and verifyCollisionChallenge(...) call in KeccakTools'
KeccakCrunchyContest.cpp and in the solution mails keccak.team publishes (crunchy_mails/), with C's
string rules: adjacent literals concatenate, and a \\x escape takes every hex digit that follows.
Placeholder calls ("???") are skipped.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CALL = re.compile(r"verify(Preimage|Collision)Challenge\s*\(")


def c_literal(body: str) -> bytes:
    out, i = bytearray(), 0
    simple = {"n": 10, "t": 9, "r": 13, "0": 0, "\\": 92, '"': 34, "'": 39}
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out += ch.encode("latin-1")
            i += 1
            continue
        nxt = body[i + 1]
        if nxt == "x":
            j = i + 2
            while j < len(body) and body[j] in "0123456789abcdefABCDEF":
                j += 1
            v = int(body[i + 2:j], 16)
            if v > 255:
                raise ValueError(f"hex escape out of range: {body[i:j]}")
            out.append(v)
            i = j
        elif nxt in "01234567":
            j = i + 1
            while j < len(body) and j < i + 4 and body[j] in "01234567":
                j += 1
            out.append(int(body[i + 1:j], 8))
            i = j
        else:
            out.append(simple[nxt])
            i += 2
    return bytes(out)


def args_of(text: str, pos: int) -> tuple[list, int]:
    """Top-level arguments of the call whose '(' ends at pos."""
    args, cur, depth, i = [], [], 0, pos
    while True:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            cur.append(("s", text[i + 1:j]))
            i = j + 1
            continue
        if ch == "/" and text[i + 1] == "/":
            i = text.index("\n", i)
            continue
        if ch == "/" and text[i + 1] == "*":
            i = text.index("*/", i) + 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                args.append(cur)
                return args, i
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(cur)
            cur = []
            i += 1
            continue
        cur.append(("c", ch))
        i += 1


def value(arg: list):
    strings = [s for k, s in arg if k == "s"]
    if strings:
        return b"".join(c_literal(s) for s in strings)
    code = "".join(c for k, c in arg if k == "c")
    code = re.sub(r"\(\s*const\s+UINT8\s*\*\s*\)", "", code).strip()
    # A mail client may have wrapped a // comment, leaving words in front of the number.
    tail = re.search(r"[-+*/()\s0-9xXa-fA-F]*$", code).group(0).strip()
    while tail and not tail[0].isdigit() and tail[0] not in "-(":
        tail = tail[1:].lstrip()
    return arith(tail) if tail else None


def arith(code: str) -> int:
    """An integer expression of literals and + - * / ( ), as some mails write lengths (2*1440-8)."""
    import ast
    import operator
    ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.floordiv,
           ast.FloorDiv: operator.floordiv}

    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in ops:
            return ops[type(n.op)](ev(n.left), ev(n.right))
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub):
            return -ev(n.operand)
        raise ValueError(f"not an integer expression: {code!r}")
    return ev(ast.parse(code.replace("0x", "0x"), mode="eval").body)


def extract(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for m in CALL.finditer(text):
        if text[: m.start()].rstrip().endswith(("int", "void")):
            continue  # the function's own definition
        args, _ = args_of(text, m.end())
        try:
            vals = [v for v in (value(a) for a in args) if v is not None]
            want = 7 if m.group(1) == "Preimage" else 8
            old_api = len(vals) == want - 1  # the 2011 validator had no start index: the first rounds
            if old_api:
                vals.insert(4 if m.group(1) == "Preimage" else 3, 0)
            if len(vals) != want:
                raise ValueError(f"{len(vals)} arguments, expected {want}")
        except ValueError as e:
            line = text.count(chr(10), 0, m.start()) + 1
            print(f"skipped {path.name}:{line}: {e}", file=sys.stderr)
            continue
        width = vals[0] + vals[1]
        if m.group(1) == "Preimage":
            r, c, nr, image, start, msg, bits = vals
            if msg in (b"???",):
                continue
            out.append({"kind": "preimage", "width": width, "rounds": nr, "start": start,
                        "target": image.hex(), "messages": [{"hex": msg.hex(), "bits": bits}],
                        "source": path.name})
        else:
            r, c, nr, start, m1, b1, m2, b2 = vals
            if m1 in (b"???",):
                continue
            out.append({"kind": "collision", "width": width, "rounds": nr, "start": start,
                        "messages": [{"hex": m1.hex(), "bits": b1}, {"hex": m2.hex(), "bits": b2}],
                        "source": path.name})
    return out


if __name__ == "__main__":
    found = [v for p in sys.argv[1:] for v in extract(Path(p))]
    print(json.dumps(found, indent=1))
