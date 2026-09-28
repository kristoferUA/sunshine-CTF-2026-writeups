# FlameOn

SunshineCTF 2026 · reverse engineering · author: [kristoferUA](https://github.com/kristoferUA)

The challenge provides a BPS patch for the NTSC version of *Super Mario World*. I recovered the flag from literal bytes in the patch, without needing a ROM image. This repository contains the patch and my decoder.

Flag: `sun{F1aM3_oN_M4r10}`

## Solution

### The encoded routine

The BPS header describes a 512 KiB input and a 1 MiB output. Among its patch actions is a 71-byte literal block placed at target offset `0x8000B`. The routine begins by reading bytes from `$8022,X`, stops at a zero byte, XORs each preceding byte with `0x5A`, and writes the result to `$7EC100,X`.

The encoded string starts 23 bytes into that block, at target offset `0x80022`:

```text
29 2F 34 21 1C 6B 3B 17 69 05 35 14 05 17 6E 28 6B 6A 27 00
```

The final `00` is the terminator. XORing the preceding bytes with `0x5A` gives the flag.

## Reproducing the result

The included script reads the BPS action stream, locates the literal routine, and decodes its zero-terminated string:

```bash
python solve.py challenge/ctf.bps
```

Expected output:

```text
Literal block at target offset 0x8000b
Ciphertext: 29 2f 34 21 1c 6b 3b 17 69 05 35 14 05 17 6e 28 6b 6a 27
Flag: sun{F1aM3_oN_M4r10}
```

## Repository layout

```text
README.md                             this writeup
solve.py                              BPS parser and string decoder
challenge/ctf.bps                     supplied patch
```

## Result

The recovered flag is:

```text
sun{F1aM3_oN_M4r10}
```
