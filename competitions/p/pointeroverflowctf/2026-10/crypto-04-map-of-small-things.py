"""A Map of Small Things — Pointer Overflow CTF 2026.

The curve is y^2 = x^3 + x over F_p with p = 3 (mod 4), so it is
supersingular and #E(F_p) = p + 1.  The order is smooth:

    p + 1 = 2^2 * 38603 * 121123 * 949584469

That makes the elliptic-curve discrete logarithm solvable with
Pohlig-Hellman: solve k modulo each prime power with baby-step giant-step,
then combine the residues with CRT.

Run from the repository dev shell:

    nix develop
    uv run competitions/p/pointeroverflowctf/2026-10/crypto-04-map-of-small-things.py
"""

from __future__ import annotations

from math import isqrt

P = 17759930830448937043
A = 1
B = 0
G = (2, 2130375071143573863)
Q = (3021250187620952397, 10766220228950080733)

ORDER = P + 1
FACTORS = [(2, 2), (38603, 1), (121123, 1), (949584469, 1)]

Point = tuple[int, int] | None


def point_add(left: Point, right: Point) -> Point:
    """Add two points on y^2 = x^3 + x over F_p."""
    if left is None:
        return right
    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if left == right:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(scalar: int, point: Point) -> Point:
    """Multiply a point by an integer using double-and-add."""
    if scalar < 0:
        if point is None:
            return None
        return point_mul(-scalar, (point[0], (-point[1]) % P))

    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def bsgs(base: Point, target: Point, order: int) -> int:
    """Solve target = x * base for 0 <= x < order."""
    if base is None or target is None:
        raise ValueError("degenerate discrete logarithm")

    step = isqrt(order) + 1

    table: dict[Point, int] = {}
    current: Point = None
    for j in range(step):
        table.setdefault(current, j)
        current = point_add(current, base)

    giant = point_mul(step, base)
    giant_neg: Point = None if giant is None else (giant[0], (-giant[1]) % P)

    current = target
    for i in range(step + 1):
        if current in table:
            return i * step + table[current]
        current = point_add(current, giant_neg)

    raise ValueError("discrete logarithm not found")


def crt(residues: list[int], moduli: list[int]) -> int:
    """Combine residues with the Chinese remainder theorem."""
    value = 0
    modulus = 1
    for residue, next_modulus in zip(residues, moduli):
        adjustment = ((residue - value) * pow(modulus, -1, next_modulus)) % next_modulus
        value += modulus * adjustment
        modulus *= next_modulus
    return value % modulus


def main() -> None:
    assert point_mul(ORDER, G) is None, "G is not in the expected subgroup"
    assert B == 0

    residues: list[int] = []
    moduli: list[int] = []

    for prime, exponent in FACTORS:
        prime_power = prime**exponent
        cofactor = ORDER // prime_power

        base = point_mul(cofactor, G)
        target = point_mul(cofactor, Q)
        residue = bsgs(base, target, prime_power)

        assert point_mul(residue, base) == target
        print(f"{prime}^{exponent}: k = {residue} (mod {prime_power})")

        residues.append(residue)
        moduli.append(prime_power)

    k = crt(residues, moduli)
    assert point_mul(k, G) == Q

    print(f"order: {ORDER} = 2^2 * 38603 * 121123 * 949584469")
    print(f"k = {k}")
    print(f"flag = POCTF{{{k}}}")


if __name__ == "__main__":
    main()
