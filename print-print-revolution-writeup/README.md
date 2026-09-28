# Print Print Revolution

SunshineCTF 2026 · pwn · author: [kristoferUA](https://github.com/kristoferUA)

The score renderer implements its own small printf-like language. Its positional `%w` conversion writes a qword through an argument pointer, while `%s` dereferences one. I used those primitives to walk the dynamic linker's `link_map`, find libc's `system`, and redirect `strcspn@GOT`. This repository contains my solver and the supplied executable.

Flag: `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}`

## Solution

### The renderer's primitives

The renderer accepts positional conversions such as `%7$s` and `%7$w`. The seventh argument is a pointer; `%7$s` prints the string at that address, while `%7$w` stores the eighth argument as a qword at the seventh argument's address.

The input buffer itself supplies the positional arguments. I put the format expression at the start of the line, terminate it with a NUL, and place packed qwords at the corresponding argument offsets. This gives a read primitive for an address and a write primitive for an address/value pair. The solver uses these to read memory without relying on a local copy of libc.

### Finding libc through `DT_DEBUG`

The executable's dynamic section keeps `DT_DEBUG` at `0x403eb0`. Once the loader starts the program, that entry points to an `_r_debug` structure. Its `r_map` field at offset `0x8` points to the first `link_map`.

Each `link_map` has the load address at offset `0`, its name pointer at `0x8`, its dynamic section at `0x10`, and the next link at `0x18`. Following those links until the name contains `libc.so` identifies the loaded libc and gives its load address.

### Resolving `system`

The libc dynamic section contains `DT_HASH`, `DT_STRTAB`, and `DT_SYMTAB`. The solver uses the SysV ELF hash of `system` to select a bucket, follows the bucket's chain, and compares symbol names in the string table. The matching `Elf64_Sym.st_value`, added to libc's load address, gives the runtime address of `system`.

### Replacing `strcspn`

The input routine calls `strcspn` to remove the trailing newline. Its GOT entry is at `0x404010`. Writing the resolved `system` address there changes the next newline-trimming call into `system(input)`.

I then send `cat /flag`. The service executes it and returns the flag.

## Reproducing the result

Python 3.8 or later is sufficient; the solver uses only the standard library:

```bash
python solve.py
```

The default target is `chal.sunshinectf.games:26002`. Override it with `--host` and `--port`:

```bash
python solve.py --host chal.sunshinectf.games --port 26002
```

## Repository layout

```text
README.md                             this writeup
solve.py                              dynamic-linker leak and GOT overwrite
challenge/revolution                  supplied executable
```

## Result

The recovered flag is:

```text
sun{cust0m_fmtstr_n0_t00ls_4ll0wed}
```
