# Suntrail

SunshineCTF 2026 · keyboard layout · author: [kristoferUA](https://github.com/kristoferUA)

The supplied `.klc` file places Unicode arrows in its first output layer and ordinary characters in the Shift layer. I treated the Shift characters as a pool and used the keyboard theme to recover the flag. This repository contains the layout and my candidate-checking script.

Flag: `sun{qwerty_sucks}`

## Solution

### Inspecting the layout

The `SHIFTSTATE` section declares three output columns: state `0`, state `1` (Shift), and state `2`. In the `LAYOUT` rows, the code point after the Caps value corresponds to state `0`; the next code point corresponds to state `1`.

For example:

```text
10  Q  0  2198  0073  -1
```

`2198` is `↘`, `0073` is `s`, and `-1` means there is no output for state `2`.

The Shift outputs, placed back on their physical key rows, are:

```text
Q W E R T       A S D F G H       Z X C V B N
s w e s u       u q r _ c }       n { t y k s
```

In layout order, the non-space characters are `swesuuqr_c}n{tyks`. The arrow layer and the filename point toward following the keyboard layout, but the Shift characters are best treated as a pool: their row order is not the flag order.

### Recovering the flag

The character pool contains the opening `sun{` and closing `}`. The remaining letters and punctuation can be arranged as `qwerty_sucks`, a keyboard-themed phrase. `qwerty` names the familiar top letter row, and every Shift output is used exactly once:

```text
sun{ + qwerty_sucks + }
```

`solve.py` extracts the state `1` characters from the layout and checks that the proposed flag uses the same character counts. This confirms the candidate against the file without assuming the entries are already in plaintext order.

## Reproducing the result

Python 3.10 or newer is sufficient; the script uses only the standard library. Pass the supplied layout path explicitly:

```bash
python solve.py challenge/suntrail.klc
```

A different `.klc` file can be passed in the same position.

## Repository layout

```text
README.md                             this writeup
solve.py                              Shift-layer extraction and candidate check
challenge/suntrail.klc                supplied keyboard layout
```

## Result

The recovered flag is:

```text
sun{qwerty_sucks}
```
