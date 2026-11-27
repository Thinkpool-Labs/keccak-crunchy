# Keccak Crunchy

**Collisions and preimages for reduced-round Keccak, the designers' own open challenges.**
A Prometheus pool on Thinkpool.

The Keccak team (who designed SHA-3) runs the
[Crunchy Crypto Collision and Pre-image Contest](https://keccak.team/crunchy_contest.html) on purpose-weakened
instances: Keccak[r = b - 160, c = 160] built on 1 to 12 consecutive rounds of Keccak-f[b], for widths
b = 200, 400, 800 and 1600. For each instance there are two challenges: two messages whose first 160
output bits agree (a collision), and a message whose first 80 output bits equal a published target (a
preimage). Generic attacks cost 2^80, so every solution so far has come from an idea: differential trails,
linear structures, algebraic solving.

Full Keccak-f[1600] has 24 rounds. The best results stand at 6 rounds for collisions and 5 for
preimages. Nothing here says anything about SHA-3 itself: say "N of 24 rounds", never "SHA-3 broken".

The frontier, from `RECORDS.json` (the designers' page on 2026-11-27; 61 of 96 cells open):

| | width 200 | 400 | 800 | 1600 |
| --- | --- | --- | --- | --- |
| lowest open preimage | 3 rounds | 5 | 6 | 6 |
| lowest open collision | 3 rounds | 6 | 7 | 7 |

The smallest width is the hardest. Its rate is 40 bits, so the 160-bit collision output is squeezed in
four blocks with the permutation between them, and the 80-bit preimage target in two: the last output
bits sit behind two, three or four times nr rounds. And there is less freedom against the same 160-bit
capacity. Three cells were solved in October and November 2026, so strong teams are working on this now.

## Run the checker

```sh
python checker/verify.py solutions/warmup-collision-w200-r2-westfeld.json
python checker/check_all.py
python baselines/sat.py preimage 1600 2 --solve > solutions/my-try.json     # pip install python-sat
python -m pytest tests -q
```

`checker/keccak.py` mirrors KeccakTools, the code the designers validate with
(`KeccakCrunchyContest.cpp`). The tests prove it matches: full Keccak-f[1600] against Python's SHA-3 and
SHAKE, and all 43 distinct solutions the designers have published (in KeccakTools and in their solution
mails), across every width, first rounds and later ones, rounds outside the nominal range, and messages
whose length is not a whole number of bytes. `baselines/extract_published.py` rebuilds that list.

## What a contribution is

A JSON file in `solutions/`:

```json
{"kind": "collision", "width": 200, "rounds": 3, "start": 0,
 "messages": [{"hex": "…", "bits": 318}, {"hex": "…", "bits": 318}],
 "authors": "names and affiliations", "method": "how you found it"}
```

- `start` is the index of the first round, 0-based as in Keccak-f[b]. The contest lets you pick any
  consecutive rounds, which changes the round constants, but they must lie within Keccak-f[b]'s own
  (`start + rounds` at most 18, 20, 22 or 24).
- A message is `bits` bits in exactly ceil(bits / 8) bytes of lower-case hex, bit k of the message in
  bit k % 8 of byte k // 8 (KeccakTools' order), with the unused high bits of the last byte zero.
- The check passes when every file is valid and one solves a cell `RECORDS.json` lists as **open**.
  Solutions for solved or closed cells are warm-ups: checked, printed, never credited. So are solutions
  outside the nominal rounds (the designers keep such a cell open: see width 200, 3 rounds).

## Credit, prizes and the order of things

- **The prize is the designers', not ours.** It is nr x 10 euros per challenge, to the first solution
  they receive, by email to all@keccak.team with the subject `[CRUNCHY CONTEST] nr rounds, width b,
  challenge type`, your names and affiliations, the first round's index, the messages in hex, and a
  summary of the method. Their validation is the one that counts; this pool does not replace it.
- **Email the designers before you open a pull request.** A pull request is public at once, and the
  first solution they receive wins. Say in the pull request when you sent it.
- **Here,** an open cell solved is credited by name in `RECORDS.json`, which only the host writes, and the
  cell's status becomes solved. Priority goes to the earliest pull request or Thinkpool submission that
  carries it. Contributions add files; they never change or remove one.
- A result found by a team on Thinkpool belongs to the people who found it. Before anyone writes it up,
  the authors agree who is on the paper.

## Licence and sources

Code Apache-2.0. The challenge definitions and targets are the Keccak team's
(https://keccak.team/crunchy_contest.html, snapshot 2026-11-27); the published solutions in
`tests/published.json` are the solvers', as the designers publish them. KeccakTools is CC0.
