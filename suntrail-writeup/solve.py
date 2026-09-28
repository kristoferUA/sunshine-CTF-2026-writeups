from collections import Counter
from pathlib import Path
import sys


FLAG = "sun{qwerty_sucks}"


def shifted_characters(source: Path) -> str:
    text = source.read_text(encoding="utf-8-sig")
    in_layout = False
    characters = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "LAYOUT":
            in_layout = True
            continue
        if stripped == "ENDKBD":
            break
        if not in_layout or not stripped:
            continue

        fields = stripped.split()
        if len(fields) < 5:
            continue

        # The fourth value is state 0; the fifth is state 1 (Shift).
        shifted = fields[4]
        if shifted == "-1":
            continue

        char = chr(int(shifted.rstrip("@"), 16))
        if not char.isspace():
            characters.append(char)

    return "".join(characters)


def main() -> None:
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("suntrail.klc")
    pool = shifted_characters(source)

    print(f"ShiftState 1 in layout order: {pool}")
    if Counter(pool) != Counter(FLAG):
        raise SystemExit("The candidate does not match the ShiftState 1 character pool.")

    print(f"Flag candidate: {FLAG}")


if __name__ == "__main__":
    main()
