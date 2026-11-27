# How these cells get solved, and how a swarm could try

This is an attack plan, written to be split. The honest summary first: every open cell is research
grade. The teams that solved the last ones publish at CRYPTO, EUROCRYPT and ASIACRYPT, and three cells
fell in October and November 2026, so they are still at it. Days of a swarm's effort will most likely
produce tools, surveys and negative results, not a solved cell. A solved cell would be a real result,
recognised by the designers. Plan for the first and aim at the second.

## 1. What the instance is, exactly

Keccak[r = b - 160, c = 160] with pad10*1 (no SHA-3 domain bits), on nr consecutive rounds of
Keccak-f[b] from a start index you choose, within the nominal 12 + 2l rounds (18, 20, 22, 24). Lanes are
b/25 = 8, 16, 32 or 64 bits. The checker in `checker/keccak.py` matches all 43 solutions the designers
have published, so it is the definition to work against.

Three facts shape every attack:

- **The rate is small at width 200.** r = 40, so a collision must agree on four 40-bit output blocks,
  read after nr, 2nr, 3nr and 4nr rounds of the permutation (the sponge permutes between squeezes). A
  preimage must match two blocks, after nr and 2nr rounds. So "3 rounds at width 200" constrains bits
  that are 6, 9 and 12 rounds deep. At widths 400 and above the whole output is in the first block.
- **Freedom.** Each block gives r - 2 free bits at most (the last block loses two to padding). Width 200
  gives 38 a block against 80 or 160 target bits: an attack needs several blocks, and the first blocks
  only choose the inner state the last block starts from.
- **The start index is a free parameter.** It changes only the round constants (iota), which break
  symmetry. Liu and colleagues solved the 3-round width-200 preimage with rounds 93 to 95, outside the
  nominal range, which the designers do not accept (the cell stays open). Whether some start in 0..15
  suits their method is a question anyone can test.

## 2. What solved the cells so far

| cells | method | where to read |
| --- | --- | --- |
| 1-2 rounds, widths 400-1600 (2011) | SAT solvers on the straightforward encoding | Morawiecki and Srebrny, "A SAT-based preimage analysis of reduced Keccak hash functions" (IPL 2013) |
| 1-2 round collisions, width 1600 (2011) | unaligned rebound | Duc, Guo, Peyrin, Wei, "Unaligned rebound attack: application to Keccak" (FSE 2012) |
| 3-4 round collisions, width 1600 (2011) | 3-round differential characteristics plus the target difference algorithm, which uses the first round's freedom | Dinur, Dunkelman, Shamir, "New attacks on Keccak-224 and Keccak-256" (FSE 2012) |
| 4-round collisions, widths 400, 800 (2013) | automated differential search over the small permutations | Kölbl, Mendel, Nad, Schläffer, "Differential cryptanalysis of Keccak variants" (IMA CC 2013) |
| 3-4 round preimages, widths 800, 1600 (2016) | linear structures: keep a subspace of inputs linear through 1-2 rounds, solve the rest by linear algebra | Guo, Liu, Song, "Linear structures: applications to cryptanalysis of round-reduced Keccak" (ASIACRYPT 2016) |
| 5-round collisions, widths 800, 1600 (2016) | S-box linearization: a 2-round connector built by linearizing chi where the difference sits, joined to a 3-round trail | Qiao, Song, Liu, Guo, "New collision attacks on round-reduced Keccak" (EUROCRYPT 2017) |
| 6-round collision, width 1600 (2017) | non-full S-box linearization, 3-round connectors | Song, Liao, Guo, "Non-full Sbox linearization: applications to collision attacks on round-reduced Keccak" (CRYPTO 2017) |
| 1-2 rounds, width 200 (2013, 2017, 2023) | both 2-round solutions start at round 3, not 0 | the mails linked from `RECORDS.json` say how |
| 3-5 round preimages, widths 400-1600 (2017-2026) | linear structures extended, allocating approaches, MILP or SAT models of the middle rounds | Li and Sun's allocating approach (EUROCRYPT 2019) and the mails in `RECORDS.json` for each cell |
| 5-6 round collisions, widths 400, 800 (2026) | the mails linked from `RECORDS.json` | read them before starting on a neighbouring cell |

For collision attacks also read Guo, Liao, Liu, Liu, Qiao, Song, "Practical collision attacks against
round-reduced SHA-3" (Journal of Cryptology, 2020), which collects the connector method, and for algebraic
attacks Dinur's polynomial method ("Cryptanalytic applications of the polynomial method for solving
multivariate equation systems over GF(2)", EUROCRYPT 2021). Every solution mail is linked from its cell in
`RECORDS.json`, and most name the paper behind them.

## 3. The cells most worth trying, and why

1. **Width 200, 3 rounds, preimage.** The one cell where someone has a working method, just at the
   wrong rounds. Task: reproduce Liu et al.'s idea (their mail gives the message and the rounds), find
   what made rounds 93-95 work, and test starts 0 to 15.
2. **Width 200, 3 rounds, collision.** The four output blocks sit 3, 6, 9 and 12 rounds deep, so a
   differential attack has to control the inner state across several squeezes. Multi-block freedom and
   internal (inner-state) collisions are the alternative: an inner-state collision after any block
   gives a full-output collision for free, but that is a 160-bit target, so it needs structure, not search.
3. **Width 400, 5-round preimage; width 400, 6-round collision.** The neighbours at width 800 fell in
   2025 and 2026. Adapting those methods to 16-bit lanes is the most direct line. Expect the smaller rate
   (240 bits) to cost freedom.
4. **Width 800 or 1600, 6-round preimage; 7-round collision.** The headline cells. Each would extend the
   best known result by a round; that has not happened for collisions since 2017.

## 4. Swarm-sized tasks

Each is a day or less and leaves something checkable behind even when the cell stays open.

**Tooling (useful at once)**
- Make width 200, 1 round, solve with `baselines/sat.py` (it times out now): XOR clauses for
  CryptoMiniSat, a better choice of blocks and free bits, or linearize chi in the first round.
- An equation generator: the ANF of the output bits for any (width, start, rounds, blocks), with chosen
  variables fixed, for Gröbner bases, XL, or the polynomial method.
- A trail-core library for Keccak-f[200] and [400]: the best 2- and 3-round trail cores and their
  weights, using KeccakTools' search (`Keccak-fTrailCore3Rounds.cpp`), saved as data.

**Analysis (each a note with numbers)**
- Linear structures at widths 200 and 400: the largest number of message bits that stay linear through
  1 and 2 rounds given capacity and padding, and how many degrees of freedom remain.
- The start-index survey: for each open cell's leading method, which round constants help or hurt.
- Degree bounds: for width 200 and 3 rounds, the algebraic degree of each output block in the last
  block's free bits, which bounds what linearization can do.

**Attempts (likely negative, worth recording)**
- A 3-round width-200 collision via a 2-round connector and a 1-round trail, block by block.
- A meet-in-the-middle preimage at width 200 across the two squeezed blocks.
- The 5-round width-400 preimage with the width-800 2025 method, scaled down.

## 5. Odds, plainly

Tasks in section 4 succeed. A solved open cell within a few days of swarm effort is unlikely: perhaps
the width-200 3-round preimage, if the start-index question has a good answer. Treat any claim of a
solution as false until `checker/check_all.py` passes, and remember to email the designers before
anything goes public.
