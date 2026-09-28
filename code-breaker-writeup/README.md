# Code Breaker

SunshineCTF 2026 · pwn · author: [kristoferUA](https://github.com/kristoferUA)

Code Breaker presents itself as encrypted key-value storage. I used a dangling reference in its command handler to overwrite a callback and print the flag. This repository contains my solver and the supplied executable and runtime libraries.

Flag: `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}`

## Solution

### Rebuilding the handshake

Frames begin with a two-byte big-endian length. The service opens with a clear `01 || A` frame, where `A` is 16 bytes. I reply with `02 || B`, where `B` is a fresh 16-byte value.

The 256-byte lookup table starts at file offset `0x2040`. Starting with a zeroed 16-byte key, the solver applies four rounds over `A || B`:

```text
for round in 0..3:
    for i in 0..15:
        x = S[(A || B)[(i + 8*round) mod 32] xor key[i]]
        key[i] = rol8(x xor (A || B)[3*round + i], 3)
```

The handshake check is derived from that key:

```text
check[i] = key[(i + 5) mod 16] xor S[key[i]]
```

I send `03 || check` through the stream transform. For byte `i` and direction counter `c`, the transform is `byte xor S[(c + i + key[i mod 16]) mod 256]`. The service's encrypted `04 00` reply confirms the counters are synchronized.

### Following the dangling reference

The storage commands use one-byte operation codes. `10` creates an entry, `14` copies an existing entry into an empty slot, `13` frees an entry, and `11` reads it.

The copy operation leaves both slots pointing at the same allocation. Freeing the copy releases the allocation but leaves the original slot pointing to it. Reading the original slot then exposes the allocator's encoded null link. That value gives the freed chunk's page number.

I allocate a second chunk of the same size, free it, then free the first chunk again so the first chunk sits at the head of the size class. Updating through the stale slot replaces its encoded next link. Two same-size allocations then return the original chunk followed by the requested address.

### Reaching the callback

Operation `16` returns a global data block containing the callback pointer. It points to `base + 0x1390`, so subtracting `0x1390` recovers the PIE base. The callback slot is at `base + 0x40c0`; the executable's `system@plt` entry is at `base + 0x1150`.

The poisoned allocation writes `system@plt` into the callback slot. Operation `15` calls that pointer with the supplied text, so the solver asks it to print `/ctf/flag.txt` and collects the flag from the connection.

## Reproducing the result

The solver uses Python's standard library and reads the lookup table from `challenge/code_breaker`. The default service is `chal.sunshinectf.games:26005`:

```bash
python solve.py
```

A different target can be supplied with `--host` and `--port`:

```bash
python solve.py --host chal.sunshinectf.games --port 26005
```

## Repository layout

```text
README.md                             this writeup
solve.py                              network solver
challenge/code_breaker                supplied executable
challenge/libc.so(2).6                supplied C library
challenge/ld-linux-x86-64.so(2).2     supplied dynamic loader
```

## Result

The recovered flag is:

```text
sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}
```
