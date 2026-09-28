# Homemaker

SunshineCTF 2026 · pwn · author: [kristoferUA](https://github.com/kristoferUA)

The Model 7 accepts length-prefixed punch cards with a CRC byte. Its memory-write command checks the requested size, then copies one extra byte. I used that byte to enlarge the read limit, disclose the stack values needed for a return chain, and call `system` with a command that prints the flag. This repository contains my solver and the supplied binary.

Flag: `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}`

## Solution

### Card framing

Each card has this layout:

```text
ESC [ | body length (big-endian, 2 bytes) | body | CRC-8 | ESC \
```

The CRC starts at zero and uses polynomial `0x2f`, most-significant bit first. The first card must have body `01 13 37 c3 5f`: opcode `1` followed by the service key `0x1337c35f`.

Opcode `2` writes data to a 256-byte local area. The routine calculates `n = body_length - 1` and accepts `n <= capacity`, but its copy loop runs from zero through `n`, inclusive. It therefore copies one byte more than the size it checked.

### Raising the read limit

Send an opcode `2` card with a 257-byte body: the opcode and 256 data bytes. The copy writes those 256 bytes into the local area, then copies the card's CRC into the low byte of `capacity`, at offset `0x100`.

With 255 zero data bytes followed by `0x80`, the card CRC is `0xff`. The capacity changes from `0x100` to `0x1ff` (511 bytes). Opcode `3` returns that many bytes, including the stack canary, saved frame pointer, and return address:

| Offset from local area | Value |
| --- | --- |
| `0x108` | stack canary |
| `0x110` | saved frame pointer |
| `0x118` | return address at PIE offset `0x1a9f` |

Subtracting `0x1a9f` from the return address gives the PIE base. The saved frame pointer minus `0x110` gives the local area's address.

### Building the return chain

A second opcode `2` card has a 512-byte body. The same inclusive loop copies 512 bytes: 511 chosen bytes and the CRC. Its checked size is 511, so it fits the enlarged limit while reaching the saved return address.

The solver preserves the canary and frame pointer, then writes a short chain using three addresses in the PIE image:

| Address offset | Instruction |
| --- | --- |
| `0x12aa` | `pop rdi; ret` |
| `0x1158` | `ret` for stack alignment |
| `0x10c0` | `system@plt` |

The command string sits at local-area offset `0x180`, above the chain so `system`'s own stack use does not overwrite it. A four-byte invalid header ends the card loop; the function then returns through the new chain and runs `find` to print the flag file.

## Reproducing the result

The solver uses Python 3.8 or newer and only the standard library:

```bash
python solve.py
```

The default target is `sunshinectf.games:26008`. It can be overridden:

```bash
python solve.py --host sunshinectf.games --port 26008
```

Expected output:

```text
sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
```

## Repository layout

```text
README.md                             this writeup
solve.py                              card client and return-chain solver
challenge/homemaker                   supplied executable
```

## Result

The recovered flag is:

```text
sun{the_future_is_now_today_well_wait_how_are_you_reading_this}
```
