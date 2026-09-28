# Cache Money

SunshineCTF 2026 · pwn · author: [kristoferUA](https://github.com/kristoferUA)

The arcade keeps each wallet's transaction ledger in a heap allocation. A transfer leaves the destination holding a pointer to a freed ledger, which I used to steer later allocations into the wallet table and redirect a function call. This repository contains my solver and the supplied binary and libraries.

Flag: `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}`

## Solution

### The dangling ledger

The service offers 16 wallet slots. A wallet stores its name, balance, ledger pointer, ledger size, and active state. Ledger sizes from 32 to 256 bytes are accepted.

When a wallet is transferred, its ledger is freed and then assigned to the destination wallet. The source is cleared, but the destination still points to the freed allocation. Depositing through that destination edits the allocator's freed-chunk data. Repeating the transfer after clearing the tcache key puts the same chunk into the tcache list a second time.

### Leaking libc

Open eight pairs of wallets with 256-byte ledgers and transfer each even-numbered wallet into the next slot. A 256-byte request uses a `0x110` chunk. Seven freed chunks fill the tcache bin; the eighth is placed in the unsorted bin.

Withdrawing from wallet 15 prints the unsorted-bin link. For this libc, the leaked pointer is `libc_base + 0x203b20`, so:

```text
libc_base = leak - 0x203b20
system    = libc_base + 0x58740
```

### Steering a ledger allocation

The wallet pointer table lives at `0x4040c0`. A 112-byte ledger request uses a `0x80` chunk, which gives us a tcache size class to manipulate separately from the large ledgers.

1. Open a 112-byte ledger in slot 12 and transfer it to slot 1. Withdrawing from slot 1 reveals the safe-linked NULL value, `chunk_address >> 12`.
2. Close slot 12, clear the tcache key by depositing 112 zero bytes through slot 1, then transfer slot 1 into slot 3. This frees the same chunk again, making its tcache next pointer refer to itself.
3. Deposit the encoded value for `0x4040c0` through slot 3. Safe-linking encodes a pointer as `target ^ (chunk_address >> 12)`.
4. Open two more 112-byte ledgers. The first allocation returns the original chunk; the second returns the wallet table.

The allocator clears the first 112 bytes of a new ledger. Depositing 112 bytes through the second wallet lets me fill those bytes with two fake wallet records and their slot pointers.

### Redirecting the close operation

The fake wallet in slot 1 points its ledger at `free@GOT` (`0x404000`) and sets its ledger size to eight bytes. Depositing the calculated `system` address through this wallet replaces the function pointer.

The fake wallet in slot 0 has the name `sh` and a null ledger. Closing it skips the ledger release and calls the replaced function on the wallet name, starting `sh`. The solver then reads `/ctf/flag.txt`.

## Reproducing the result

Requires Python 3.8 or later and only uses the standard library:

```bash
python solve.py
```

The default target is `chal.sunshinectf.games:26004`. The host and port can be overridden with `--host` and `--port`. The libc offsets above match the challenge's supplied libc.

## Repository layout

```text
README.md                             this writeup
solve.py                              heap exploit and flag retrieval
challenge/cache_money                 supplied executable
challenge/libc.so.6                   supplied C library
challenge/ld-linux-x86-64.so.2        supplied dynamic loader
```

## Result

The recovered flag is:

```text
sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}
```
