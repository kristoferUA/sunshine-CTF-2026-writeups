# Safe House

SunshineCTF 2026 · pwn · author: [kristoferUA](https://github.com/kristoferUA)

The service accepts notes and submissions at a front desk, then forwards requests to a restricted vault process. `SUBMIT` has a stack-based buffer overflow, and the vault's signed index check lets a negative public-record index reach a system file. This repository contains the original service binary and my solver.

Flag: `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}`

## Solution

### Reaching the return address

`SUBMIT <size>` reads from the connection into a 64-byte stack buffer. The read length is taken from the low byte of the requested size, so `SUBMIT 255` accepts enough data to overwrite the saved return address. It is `0x48` bytes from the start of that buffer.

The executable is non-PIE, so the internal helper routines have stable addresses. The solver uses a short ROP chain to call the service's own relay and frame-sending functions; it does not need a shell or a libc leak.

### Setting the frame length

The relay wrapper rejects operation `255`. In its error path it calls `write` with a length of 11 for `ERR bad op\n`. On return, `rdx` still contains 11. The ROP chain then calls the internal frame sender at `0x401d50` with request type `3` and an 11-byte note as its payload.

The first four payload bytes are `fc ff ff ff`, the little-endian representation of signed index `-4`. The remaining bytes are padding.

### Crossing into the vault

The vault keeps four system records before its public-record table. Its read handler converts the requested index to a signed integer, rejects only values greater than 15, and computes the record address as `table + index * 0x40c`. It never rejects negative values. Therefore, index `-4` points back four records from the public table to the first system record, which is the opened `flag.txt` file.

After sending the read request, the ROP chain calls the relay wrapper with operation `1`. That wrapper receives the pending vault response and prints the flag to the connection.

## Reproducing the result

Service: `nc chal.sunshinectf.games 26007`

Python 3 is sufficient; the solver uses only the standard library:

```bash
python solve.py
```

A different target can be supplied with `--host` and `--port`:

```bash
python solve.py --host chal.sunshinectf.games --port 26007
```

## Repository layout

```text
README.md                             this writeup
solve.py                              stack overflow and vault-request solver
challenge/service                     supplied executable
```

## Result

The recovered flag is:

```text
sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}
```
