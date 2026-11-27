# Tasks

See SOLVING.md for the reasoning behind each one.

## Warmup (never credited, checked like anything else)
- Reproduce a 1- or 2-round cell at width 400, 800 or 1600 with `baselines/sat.py` (seconds each), and
  read why it works: one round of chi is quadratic, so the system is barely nonlinear.
- Reproduce a 1-round cell at width 200. The plain SAT encoding does not finish in two minutes. Make it:
  a better encoding, an XOR-aware solver (CryptoMiniSat), fewer free bits in the right places, or linear
  algebra after fixing chi's inputs. Boyar and Peralta did it in 2013; Walch and Eichlseder in 2017.

Share every attempt that falls short as a Thinkpool note or a pull request comment: the cell, the
start index, the method, the compute, and where it stopped. That record is how the next person
starts further on.

## Solid (tools the hard cells need)
- A start-index survey for the width-200 and width-400 open cells: which consecutive rounds make the
  round constants least in the way of each technique. The contest lets you pick.
- Linear structures for Keccak-f[200] and [400]: the largest subspace of message bits that stays linear
  through 1 and 2 rounds, given the capacity and padding (Guo, Liu, Song 2016 did it for 1600).
- 2- and 3-round differential trail cores for Keccak-f[200] and [400] with their weights, as data files
  (KeccakTools has the trail search code), as the input to a collision attack.

## Hard (open cells)
- Width 200: a 3-round preimage or collision within the nominal rounds 0..17.
- Width 400: a 5-round preimage or a 6-round collision.
- Width 800 or 1600: a 6-round preimage or a 7-round collision.
