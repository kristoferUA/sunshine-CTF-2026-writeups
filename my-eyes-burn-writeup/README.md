# My Eyes Burn

SunshineCTF 2026 · keyboard layout · author: [kristoferUA](https://github.com/kristoferUA)

The supplied `boardwriter.klc` is a Windows keyboard layout source. I found the hidden message in its `DEADKEY` composition records, which form a chain of states. This repository contains the source and my chain-following script.

Flag: `sun{praisethesun}`

## Solution

### Following the chain

The OEM_3 key starts the sequence with U+0060. Each DEADKEY row takes the current state and a character, then either moves to another state (marked with @) or emits a final character.

Starting from U+0060 and following the matching rows gives:

| State | Character | Next state or output |
| --- | --- | --- |
| 0060 | s | 02d0 |
| 02d0 | u | 02ed |
| 02ed | n | 02b4 |
| 02b4 | { | 02ef |
| 02ef | p | 02ba |
| 02ba | r | 02c9 |
| 02c9 | a | 02d3 |
| 02d3 | i | 02e9 |
| 02e9 | s | 02bd |
| 02bd | e | 02cd |
| 02cd | t | 02e4 |
| 02e4 | h | 02d8 |
| 02d8 | e | 02ee |
| 02ee | s | 02d4 |
| 02d4 | u | 02e1 |
| 02e1 | n | 02b0 |
| 02b0 | } | 2600 (☀) |

The input characters along the path spell `sun{praisethesun}`. The final mapping to U+2600 (the sun symbol) confirms the end of the chain.

## Reproducing the result

With Python 3 installed, run the included script from this directory:

```bash
python solve.py
```

The script reads `challenge/boardwriter.klc` by default. A different KLC file can be passed as an argument.

## Repository layout

```text
README.md                             this writeup
solve.py                              dead-key chain decoder
challenge/boardwriter.klc             supplied keyboard layout
```

## Result

The recovered flag is:

```text
sun{praisethesun}
```
