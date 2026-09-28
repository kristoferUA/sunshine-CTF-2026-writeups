# Mad Libs

SunshineCTF 2026 · pwn · author: [kristoferUA](https://github.com/kristoferUA)

The game reads eight words and echoes each answer. The echo call treats the answer as a format string, which I used to leak the executable and library bases and redirect the writable `printf` entry to `system`. This repository contains my solver and the supplied binary and libraries.

Flag: `sun{f1ll_iN_th3_g0T_eNtry}`

## Solution

### The formatting bug

The program reads each line with `fgets` and then calls `printf(answer)`. The line fits in its stack buffer, so the issue is how the string is interpreted: tokens such as `%p` and `%s` make `printf` read additional arguments that the caller did not provide.

The executable is PIE and has partial RELRO. The latter leaves the `printf` entry in the Global Offset Table writable. The supplied `libc.so(1).6` provides the symbol offsets used below.

### Leaking the addresses

The 47th positional value points to code at offset `0x11c9` in the executable. Sending `%47$p` gives the PIE base:

```text
pie_base = leaked_code_address - 0x11c9
```

The `printf` GOT slot is at `pie_base + 0x4010`. The first qword of the input appears as positional argument 8, so an address placed at byte offset `0x80` is argument 24. Putting the GOT address there and using `%24$s` prints the pointer stored in the slot.

For the supplied library, `printf` is at offset `0x600f0` and `system` is at offset `0x58740`:

```text
libc_base = leaked_printf_address - 0x600f0
system    = libc_base + 0x58740
```

### Redirecting the echo call

The solver writes the low three 16-bit pieces of `system` into `printf@GOT` with `%hn`. It sorts the writes by value and pads the printed character count between them. The upper two bytes of the pointer are already zero, so three halfword writes complete the replacement.

On the next answer, the program calls `system` with the input line as its command. Sending `cat flag.txt` prints the flag from the challenge's working directory.

## Reproducing the result

The script uses only the Python standard library and connects to the challenge service:

```bash
python solve.py
```

The host and port can be overridden:

```bash
python solve.py --host chal.sunshinectf.games --port 26001
```

Expected output:

```text
sun{f1ll_iN_th3_g0T_eNtry}
```

## Repository layout

```text
README.md                             this writeup
solve.py                              format-string exploit
challenge/mad_libs                    supplied executable
challenge/libc.so(1).6                supplied C library
challenge/ld-linux-x86-64.so(1).2     supplied dynamic loader
```

## Result

The recovered flag is:

```text
sun{f1ll_iN_th3_g0T_eNtry}
```
