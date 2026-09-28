# Total Recall

SunshineCTF 2026 · pwn · author: [kristoferUA](https://github.com/kristoferUA)

The supplied x86-64 ELF leaks eight stack bytes and then accepts an input large enough to replace a return address. I used the fixed `syscall; ret` instruction and Linux `rt_sigreturn` to read the flag file. This repository contains my solver and the original binary.

Flag: `sun{r3caLl_ev3Ry_reGist3r_sR0p}`

## Solution

### Reading the control flow

The entry point calls `0x401016`. That routine pushes the stack pointer and writes the pushed eight-byte value to standard output. The value is the stack address before the push; call it `L`.

The routine then reads `0x18` bytes into `[rsp-0x40]` and returns. The entry point makes a second call, to `0x40104f`:

```text
lea rsi, [rsp-0x80]
mov rdi, 0
mov rdx, 0x400
mov rax, 0
syscall
ret
```

At this second call, `rsp` is `L`, so the input buffer is `L-0x80`. Its saved return address is at `[L]`, exactly `0x80` bytes from the buffer start. The stack leak gives the address needed to place the return chain.

### Restoring registers with a signal frame

The binary does not provide short instructions for loading arbitrary syscall arguments. The useful sequence at `0x401031` starts with `pop rax`, then performs `read(0, rsp-0x40, 0x18)` and returns. The read result remains in `rax`.

The chain makes that read return exactly 15 bytes. On x86-64 Linux, syscall 15 is `rt_sigreturn`. The next return enters `0x401069` (`syscall; ret`), and the kernel restores the register values from the signal frame placed on the stack.

Three frames perform the file operations:

| Frame | Syscall | Arguments |
| --- | --- | --- |
| 1 | `openat` (257) | `AT_FDCWD`, `./flag.txt`, read-only |
| 2 | `read` (0) | file descriptor 3, 128-byte output area |
| 3 | `write` (1) | standard output, same output area |

The file descriptor is 3 because the service starts with the usual descriptors 0, 1, and 2 open. The solver spaces the three 15-byte reads so each returns 15, then extracts the `sun{...}` text from the response.

## Reproducing the result

Service: `nc chal.sunshinectf.games 26003`

The solver uses only the Python standard library. Python 3.8 or newer is sufficient:

```bash
python solve.py
```

The default target is `chal.sunshinectf.games:26003`. A different target or file path can be supplied:

```bash
python solve.py --host chal.sunshinectf.games --port 26003 --path ./flag.txt
```

## Repository layout

```text
README.md                             this writeup
solve.py                              stack leak and SROP exploit
challenge/total_recall                supplied executable
```

## Result

The recovered flag is:

```text
sun{r3caLl_ev3Ry_reGist3r_sR0p}
```
