"""Reduced-round Keccak exactly as the Keccak team's contest validator computes it.

The contest instances are Keccak[r = b - 160, c = 160] built on nr consecutive rounds of Keccak-f[b],
for a width b in {200, 400, 800, 1600}. This file mirrors KeccakTools (github.com/KeccakTeam/KeccakTools,
Sources/Keccak-f.cpp, sponge.cpp, padding.cpp), the code KeccakCrunchyContest.cpp validates with:

- Rounds are indexed as in Keccak-f[b]: round i uses round constant RC[i mod 255], the 64-bit constant
  from the LFSR x^8 + x^6 + x^5 + x^4 + 1 truncated to the lane size. A solution names its first round
  index `start`; the contest wants 0 <= start and start + nr <= the nominal 12 + 2l rounds.
- The padding is Keccak's multi-rate pad10*1, with no SHA-3 domain bits.
- Bits are little-endian everywhere: message bit k is bit k % 8 of byte k // 8, so a message of a bit
  length that is not a multiple of 8 uses the low bits of its last byte. Lanes are little-endian bytes.
- The output is squeezed r bits at a time, so for b = 200 (r = 40) the 160-bit collision output takes
  four squeeze blocks with the permutation between them.

Plain Python integers, written to be read, not to be fast.
"""
from __future__ import annotations

WIDTHS = (200, 400, 800, 1600)
CAPACITY = 160


def nominal_rounds(b: int) -> int:
    lane = b // 25
    return 12 + 2 * (lane.bit_length() - 1)


def _round_constants() -> list[int]:
    out, lfsr = [], 1
    for _ in range(255):
        c = 0
        for j in range(7):
            if lfsr & 1:
                c |= 1 << ((1 << j) - 1)
            lfsr = ((lfsr << 1) ^ 0x71) & 0xFF if lfsr & 0x80 else (lfsr << 1)
        out.append(c)
    return out


RC64 = _round_constants()


def _rho_offsets(w: int) -> list[list[int]]:
    off = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        off[x][y] = ((t + 1) * (t + 2) // 2) % w
        x, y = y, (2 * x + 3 * y) % 5
    return off


def keccak_p(lanes: list[list[int]], w: int, start: int, nr: int) -> list[list[int]]:
    """nr rounds of Keccak-f[25w] from round index `start`, on lanes[x][y]."""
    mask = (1 << w) - 1
    rho = _rho_offsets(w)

    def rot(v: int, n: int) -> int:
        n %= w
        return ((v << n) | (v >> (w - n))) & mask if n else v

    a = [row[:] for row in lanes]
    for i in range(start, start + nr):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rot(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]           # theta
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = rot(a[x][y], rho[x][y])          # rho and pi
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & mask & b[(x + 2) % 5][y]) for y in range(5)]
             for x in range(5)]                                               # chi
        a[0][0] ^= RC64[i % 255] & mask                                       # iota
    return a


def _bytes_to_lanes(state: bytes, w: int) -> list[list[int]]:
    n = w // 8
    lanes = [[0] * 5 for _ in range(5)]
    for idx in range(25):
        x, y = idx % 5, idx // 5
        lanes[x][y] = int.from_bytes(state[idx * n:(idx + 1) * n], "little")
    return lanes


def _lanes_to_bytes(lanes: list[list[int]], w: int) -> bytes:
    n = w // 8
    return b"".join(lanes[idx % 5][idx // 5].to_bytes(n, "little") for idx in range(25))


def crunchy_hash(width: int, start: int, nr: int, message: bytes, bits: int, out_bits: int) -> bytes:
    """Keccak[r = width - 160, c = 160] on nr rounds from `start`: the first out_bits of output."""
    if width not in WIDTHS:
        raise ValueError("width must be 200, 400, 800 or 1600")
    return sponge(width, width - CAPACITY, start, nr, message, bits, out_bits)


def sponge(width: int, r: int, start: int, nr: int, message: bytes, bits: int, out_bits: int) -> bytes:
    """The Keccak sponge with pad10*1 on Keccak-f[width] reduced to nr rounds from `start`."""
    if bits < 0 or len(message) != (bits + 7) // 8:
        raise ValueError("the message's byte length must be ceil(bits / 8)")
    if out_bits % 8:
        raise ValueError("output length must be whole bytes")
    w = width // 25
    # Message bits, then pad10*1, as one integer read little-endian (bit k is bit k of the number).
    m = int.from_bytes(message, "little") & ((1 << bits) - 1)
    m |= 1 << bits
    total = bits + 1
    total += (r - 1 - total % r) % r
    m |= 1 << total
    total += 1
    assert total % r == 0
    state = bytes(width // 8)
    for blk in range(total // r):
        block = ((m >> (blk * r)) & ((1 << r) - 1)).to_bytes(r // 8, "little")
        state = bytes(s ^ t for s, t in zip(state, block + bytes(len(state) - len(block))))
        state = _lanes_to_bytes(keccak_p(_bytes_to_lanes(state, w), w, start, nr), w)
    out = b""
    while len(out) * 8 < out_bits:
        out += state[: r // 8]
        if len(out) * 8 < out_bits:
            state = _lanes_to_bytes(keccak_p(_bytes_to_lanes(state, w), w, start, nr), w)
    return out[: out_bits // 8]
