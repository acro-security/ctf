"""The Notary's Seal — Pointer Overflow CTF 2026.

Textbook RSA with e = 3 and no padding.  The message is short enough that
m**3 < n, so the seal never wrapped modulo n: it is an exact integer cube.
Recover the document by taking its integer cube root.

Run from the repository dev shell:

    nix develop
    uv run src/p/pointeroverflowctf/2026-10/crypto-04-notary-seal.py
"""

from __future__ import annotations

N = 0xc4a721a26ab81d5cd1a077535c82e3d8fd1336f96a8d794d77cb26311af8579e2b3fbf3b4760f5ea1e8e7956a8b3f52757ee59a6c89baf055f0c5f526ae286fe7e6c4e2b345d9fa1e4f2e22ac5597cd08d49de64c80d422fafa2013b4a247a0eb1276d4ea9e97cca1797dc48339803326cf7bc3bb71cd7a6ced12708ca8c5201e683a46c992822168b14c4fabcf801d539a5da7e635f65b933f92b308d0f0a7616470ed242dfc71f76447b938fdcf40328ede30e3a4ce9075099f50d4ea4b51087798085a5e432b0fe33983ba6a880c3eef03c7d0295ef0546609854b2428ca5d7e21d5173d51e21dd77d796096903f3ee96ed78d6a8f9af4714af4cb6081fb5

E = 3

SEAL = 0x7e74fc33f9eec5d02a252dd76954e0d93cf8f375d66f2cb7b7d76804ee416c3d01b6e74f8f5e5f9bbce97ee7a7829d3ca3d85cce9eb5d9a0b3539be4fb874435bdebdd1c7b1b428a2aa8a8336c6e9601fae796a2902a2d56580385360325979eaf411a846ae603c9119fb791dc9a5b0fb638ea4cdc7be11ec34614cdfa168aae9d136d4cfac90bb2d7afc53625305d1e601c99b3cd8123b3c1e51b7fc7b7a6e19639983b079f9c8eabe7e6b6465


def iroot(value: int, degree: int) -> int:
    """Return floor(value ** (1 / degree)) using binary search."""
    if value < 0:
        raise ValueError("value must be non-negative")
    if degree < 1:
        raise ValueError("degree must be positive")
    if value < 2:
        return value

    low = 1
    high = 1 << (value.bit_length() // degree + 1)
    while low < high:
        mid = (low + high + 1) // 2
        if mid**degree <= value:
            low = mid
        else:
            high = mid - 1
    return low


def main() -> None:
    print(f"n    = {N.bit_length()} bits")
    print(f"seal = {SEAL.bit_length()} bits")
    print(f"e    = {E}")

    if SEAL >= N:
        raise SystemExit(
            "seal >= n: the message wrapped modulo n. A plain cube root is "
            "not enough here (Coppersmith / Hastad territory)."
        )

    document_int = iroot(SEAL, E)
    if pow(document_int, E) != SEAL:
        raise SystemExit("seal is not an exact cube; the simple attack fails")

    document = document_int.to_bytes((document_int.bit_length() + 7) // 8, "big")
    print(f"m    = {document_int.bit_length()} bits")
    print(f"doc  = {document.decode()}")


if __name__ == "__main__":
    main()
