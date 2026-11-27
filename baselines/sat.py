"""A plain SAT encoding of a Crunchy Contest challenge, and a solver run over it.

    python baselines/sat.py preimage 1600 1 --dimacs p.cnf              # write DIMACS for kissat, CryptoMiniSat...
    python baselines/sat.py preimage 1600 1 --solve --timeout 60 > solutions/try.json
    python baselines/sat.py collision 400 1 --start 0 --blocks 1 --solve

The encoding is the obvious one: one variable per message bit, Tseitin variables for each XOR of two
bits and for each chi AND, round constants folded in as negated literals, the pad10*1 bits fixed. A
message is `blocks` blocks of r bits less the two padding bits, so it fills its last block exactly.
For width 200 (r = 40) a preimage needs at least 3 blocks (80 target bits against 38 free bits a
block) and the 160-bit collision output takes four squeezes.

This is a baseline. It reproduces 1-round cells in seconds and is hopeless at 3 or more rounds as
written: see SOLVING.md for what the published attacks add (linear structures, connectors, XOR-aware
solvers). --solve needs `pip install python-sat`; it writes a solution file and checks it with the
pool's own checker first.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "checker"))

from keccak import CAPACITY, RC64, _rho_offsets, crunchy_hash  # noqa: E402

T = 1  # variable 1 is constant true


class CNF:
    def __init__(self):
        self.n = 1
        self.clauses = [[T]]

    def var(self) -> int:
        self.n += 1
        return self.n

    def xor2(self, a: int, b: int) -> int:
        if abs(a) == T:
            return -b if a == T else b          # true ^ b = not b ; false ^ b = b
        if abs(b) == T:
            return -a if b == T else a
        if a == b:
            return -T
        if a == -b:
            return T
        v = self.var()
        self.clauses += [[-v, a, b], [-v, -a, -b], [v, -a, b], [v, a, -b]]
        return v

    def xorn(self, lits: list[int]) -> int:
        acc = -T
        for x in lits:
            acc = self.xor2(acc, x)
        return acc

    def andnot(self, a: int, b: int) -> int:
        """(not a) and b."""
        if a == T or b == -T:
            return -T
        if a == -T:
            return b
        if b == T:
            return -a
        v = self.var()
        self.clauses += [[-v, -a], [-v, b], [v, a, -b]]
        return v


def permute(cnf: CNF, s: list[int], w: int, start: int, nr: int) -> list[int]:
    """s is the state as bit literals in KeccakTools' order: bit z of lane (x, y) is s[(5y + x) w + z]."""
    rho = _rho_offsets(w)
    A = [[[s[(5 * y + x) * w + z] for z in range(w)] for y in range(5)] for x in range(5)]
    for i in range(start, start + nr):
        C = [[cnf.xorn([A[x][y][z] for y in range(5)]) for z in range(w)] for x in range(5)]
        D = [[cnf.xor2(C[(x - 1) % 5][z], C[(x + 1) % 5][(z - 1) % w]) for z in range(w)] for x in range(5)]
        A = [[[cnf.xor2(A[x][y][z], D[x][z]) for z in range(w)] for y in range(5)] for x in range(5)]
        B = [[None] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                off = rho[x][y]
                B[y][(2 * x + 3 * y) % 5] = [A[x][y][(z - off) % w] for z in range(w)]
        A = [[[cnf.xor2(B[x][y][z], cnf.andnot(B[(x + 1) % 5][y][z], B[(x + 2) % 5][y][z])) for z in range(w)]
              for y in range(5)] for x in range(5)]
        rc = RC64[i % 255]
        for z in range(w):
            if rc >> z & 1:
                A[0][0][z] = -A[0][0][z]
    return [A[k // w % 5][k // w // 5][k % w] for k in range(25 * w)]


def sponge(cnf: CNF, width: int, start: int, nr: int, blocks: int, out_bits: int):
    w, r = width // 25, width - CAPACITY
    nbits = blocks * r - 2
    msg = [cnf.var() for _ in range(nbits)]
    padded = msg + [T, T]
    s = [-T] * width
    for b in range(blocks):
        s = [cnf.xor2(s[k], padded[b * r + k]) if k < r else s[k] for k in range(width)]
        s = permute(cnf, s, w, start, nr)
    out = []
    while len(out) < out_bits:
        out += s[:r]
        if len(out) < out_bits:
            s = permute(cnf, s, w, start, nr)
    return msg, out[:out_bits]


def build(kind: str, width: int, nr: int, start: int, blocks: int, target: str | None):
    cnf = CNF()
    if kind == "preimage":
        msg, out = sponge(cnf, width, start, nr, blocks, 80)
        t = int.from_bytes(bytes.fromhex(target), "little")
        cnf.clauses += [[o if t >> k & 1 else -o] for k, o in enumerate(out)]
        return cnf, [msg]
    m1, o1 = sponge(cnf, width, start, nr, blocks, 160)
    m2, o2 = sponge(cnf, width, start, nr, blocks, 160)
    for a, b in zip(o1, o2):
        cnf.clauses += [[-a, b], [a, -b]]
    cnf.clauses.append([cnf.xor2(a, b) for a, b in zip(m1, m2)])  # the messages differ somewhere
    return cnf, [m1, m2]


def lit_value(model: set[int], lit: int) -> int:
    return 1 if lit in model else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["preimage", "collision"])
    ap.add_argument("width", type=int, choices=[200, 400, 800, 1600])
    ap.add_argument("rounds", type=int)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--blocks", type=int, default=None)
    ap.add_argument("--dimacs")
    ap.add_argument("--solve", action="store_true")
    ap.add_argument("--timeout", type=float, default=60, help="seconds; solvers that can't be interrupted "
                    "(CaDiCaL in pysat) ignore it, so wrap the run in `timeout`")
    ap.add_argument("--solver", default="cadical153", help="any pysat solver name, e.g. glucose4, minisat22")
    a = ap.parse_args()
    blocks = a.blocks or (3 if a.width == 200 else 1)
    target = None
    if a.kind == "preimage":
        cells = json.loads((Path(__file__).resolve().parents[1] / "RECORDS.json").read_text(encoding="utf-8"))["cells"]
        target = next(c["target"] for c in cells if c["kind"] == "preimage" and c["width"] == a.width
                      and c["rounds"] == a.rounds)
    t0 = time.time()
    cnf, msgs = build(a.kind, a.width, a.rounds, a.start, blocks, target)
    print(f"{cnf.n} variables, {len(cnf.clauses)} clauses, built in {time.time() - t0:.1f}s", file=sys.stderr)
    if a.dimacs:
        with open(a.dimacs, "w") as f:
            f.write(f"p cnf {cnf.n} {len(cnf.clauses)}\n")
            f.writelines(" ".join(map(str, c)) + " 0\n" for c in cnf.clauses)
    if not a.solve:
        return 0
    from pysat.solvers import Solver
    with Solver(name=a.solver, bootstrap_with=cnf.clauses) as s:
        timer = threading.Timer(a.timeout, s.interrupt)
        timer.start()
        t0 = time.time()
        res = s.solve_limited(expect_interrupt=True)
        timer.cancel()
        print(f"solver: {res} in {time.time() - t0:.1f}s", file=sys.stderr)
        if not res:
            return 1
        model = {l for l in s.get_model() if l > 0}
    out = []
    for m in msgs:
        bits = [lit_value(model, l) for l in m]
        n = len(bits)
        v = sum(b << k for k, b in enumerate(bits))
        out.append({"hex": v.to_bytes((n + 7) // 8, "little").hex(), "bits": n})
    sol = {"kind": a.kind, "width": a.width, "rounds": a.rounds, "start": a.start, "messages": out,
           "method": f"baselines/sat.py, {blocks} block(s), {a.solver}"}
    # Check with the pool's own hash before printing.
    hs = [crunchy_hash(a.width, a.start, a.rounds, bytes.fromhex(m["hex"]), m["bits"], 80 if target else 160) for m in out]
    assert (hs[0].hex() == target) if target else (hs[0] == hs[1]), "the encoding disagrees with the checker"
    print(json.dumps(sol, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
