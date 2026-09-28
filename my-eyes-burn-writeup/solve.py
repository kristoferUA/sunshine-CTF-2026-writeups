#!/usr/bin/env python3
"""Recover the text encoded by the Boardwriter KLC dead-key chain."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

HEX = re.compile(r"[0-9a-fA-F]{4,6}")
OUTPUT = re.compile(r"([0-9a-fA-F]{4,6})(@?)")
FLAG = re.compile(r"[A-Za-z0-9_]+\{[^{}\r\n]+\}")


def parse_layout(path: Path) -> tuple[str, dict[tuple[str, str], tuple[str, bool]]]:
    section = ""
    state = ""
    start_state = None
    transitions: dict[tuple[str, str], tuple[str, bool]] = {}

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        fields = raw_line.strip().split()
        if not fields:
            continue

        if fields[0] == "LAYOUT":
            section = "layout"
            continue
        if fields[0] == "DEADKEY" and len(fields) == 2:
            section = "deadkey"
            state = fields[1].lower()
            continue
        if fields[0] == "ENDKBD":
            break

        if section == "layout" and len(fields) >= 4 and fields[1] == "OEM_3":
            for token in fields[3:]:
                match = OUTPUT.fullmatch(token)
                if match and match.group(2):
                    start_state = match.group(1).lower()
                    break
        elif section == "deadkey" and len(fields) == 2:
            if HEX.fullmatch(fields[0]):
                match = OUTPUT.fullmatch(fields[1])
                if match:
                    transitions[(state, fields[0].lower())] = (
                        match.group(1).lower(),
                        bool(match.group(2)),
                    )

    if start_state is None:
        raise ValueError("Could not find the OEM_3 starting state.")
    return start_state, transitions


def decode(path: Path) -> tuple[str, int]:
    state, transitions = parse_layout(path)
    recovered = []
    seen = set()

    for _ in range(256):
        options = [
            (character, result, continues)
            for (current_state, character), (result, continues) in transitions.items()
            if current_state == state
        ]
        if len(options) != 1:
            raise ValueError(
                f"Expected one transition from state {state}; found {len(options)}."
            )

        character, result, continues = options[0]
        step = (state, character)
        if step in seen:
            raise ValueError(f"Repeated transition at state {state}.")
        seen.add(step)
        recovered.append(chr(int(character, 16)))

        if not continues:
            return "".join(recovered), int(result, 16)
        state = result

    raise ValueError("The chain exceeded 256 transitions.")


def main() -> None:
    default_path = Path(__file__).resolve().parent / "challenge" / "boardwriter.klc"
    parser = argparse.ArgumentParser(description="Read a message from a KLC dead-key chain.")
    parser.add_argument("layout", nargs="?", type=Path, default=default_path)
    args = parser.parse_args()

    sequence, final_codepoint = decode(args.layout)
    print(f"Recovered sequence: {sequence}")
    print(f"Final character: {chr(final_codepoint)} (U+{final_codepoint:04X})")

    match = FLAG.search(sequence)
    if match:
        print(f"Flag: {match.group(0)}")


if __name__ == "__main__":
    main()