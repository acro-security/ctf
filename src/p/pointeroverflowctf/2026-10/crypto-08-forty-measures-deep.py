"""Forty Measures Deep — Pointer Overflow CTF 2026.

The MIDI track is a ciphertext: every note-on event is one character.  The
private musical alphabet maps 39 consecutive MIDI notes (53..91) to

    0123456789.{ABCDEFGHIJKLMNOPQRSTUVWXYZ}

so a note is decoded with `note - 53`.  The known plaintext "POCTF" fixes the
base of the mapping.

Run from the repository dev shell:

    nix develop
    uv run src/p/pointeroverflowctf/2026-10/crypto-08-forty-measures-deep.py
"""

from __future__ import annotations

from pathlib import Path

ALPHABET = "0123456789.{ABCDEFGHIJKLMNOPQRSTUVWXYZ}"
BASE_NOTE = 53
MIDI_PATH = Path(__file__).with_name("attachments") / "score.mid"


def read_vlq(data: bytes, offset: int) -> tuple[int, int]:
    """Read a MIDI variable-length quantity."""
    value = 0
    while True:
        byte = data[offset]
        offset += 1
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, offset


def note_numbers(path: Path) -> list[int]:
    """Return every note-on pitch in a Standard MIDI File."""
    data = path.read_bytes()
    if data[:4] != b"MThd":
        raise ValueError(f"{path} is not a Standard MIDI File")

    header_length = int.from_bytes(data[4:8], "big")
    offset = 8 + header_length
    notes: list[int] = []

    while offset < len(data):
        if data[offset:offset + 4] != b"MTrk":
            raise ValueError(f"expected MTrk at byte {offset}")
        track_length = int.from_bytes(data[offset + 4:offset + 8], "big")
        offset += 8
        track_end = offset + track_length
        status = 0

        while offset < track_end:
            _, offset = read_vlq(data, offset)
            event = data[offset]

            if event == 0xFF:  # meta event
                offset += 1
                offset += 1  # meta type
                length, offset = read_vlq(data, offset)
                offset += length
            elif event in (0xF0, 0xF7):  # sysex
                offset += 1
                length, offset = read_vlq(data, offset)
                offset += length
            else:
                if event & 0x80:
                    status = event
                    offset += 1
                event = status
                kind = event & 0xF0

                if kind in (0x80, 0x90, 0xA0, 0xB0, 0xE0):
                    first, second = data[offset], data[offset + 1]
                    offset += 2
                    if kind == 0x90 and second > 0:
                        notes.append(first)
                elif kind in (0xC0, 0xD0):
                    offset += 1
                else:
                    raise ValueError(f"unsupported MIDI event {event:#x}")

        offset = track_end

    return notes


def decode(notes: list[int]) -> str:
    characters = []
    for note in notes:
        index = note - BASE_NOTE
        if not 0 <= index < len(ALPHABET):
            raise ValueError(f"note {note} is outside the musical alphabet")
        characters.append(ALPHABET[index])
    return "".join(characters)


def main() -> None:
    notes = note_numbers(MIDI_PATH)
    plaintext = decode(notes)

    if not plaintext.startswith("POCTF{"):
        raise SystemExit("known-plaintext check failed")

    print(f"notes: {len(notes)}")
    print(f"flag:  {plaintext}")


if __name__ == "__main__":
    main()
