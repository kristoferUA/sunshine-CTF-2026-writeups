# IntMod

SunshineCTF 2026 · reverse engineering · author: [kristoferUA](https://github.com/kristoferUA)

The challenge is a stripped x86-64 ELF. Its input check is hidden behind a signal-driven virtual machine that transforms 40 bytes and checks modular hashes. I traced the VM, converted its checks to equations, and reversed its prefix to recover the input.

Flag: `sun{I_L0v3_Int3rrupts&SelfMod!!!}`

## Solution

### 1. Follow the runtime code

The native entry point does not contain a direct flag comparison. Static inspection points toward a VM, but the useful instruction stream is decoded at runtime and is awkward to understand from the stripped binary alone. I used Ghidra to map the native control flow, then traced execution at signal boundaries and recorded the VM instruction buffer as the handler advanced its program counter.

The VM uses 16-byte instructions and has 170 instruction slots. The first 90 instructions are reversible operations over five 64-bit registers. The remaining 80 instructions form 40 hash-and-compare pairs. Capturing the decoded stream is the reverse-engineering step; `solve.py` below contains the recovered instruction and comparison constants so the algebra can be reproduced without the original trace files.

### 2. Turn the checks into equations

Each hash consumes the 40 bytes of the five-register state in reverse order. For a hash with multiplier `s` and offset `c`, its accumulator is:

```text
h = 0
for b in reversed(state_bytes):
    h = (h * (s mod 65521) + b) mod 65521
output = (h - c) mod 65521
```

The next VM instruction compares `output` with a constant `e`. Therefore:

```text
sum(state_bytes[j] * (s mod 65521)^j for j in 0..39)
    = (e + c) mod 65521
```

There are 40 unknown bytes and 40 independent equations over the prime field $\mathbb{F}_{65521}$. I built the corresponding 40×40 matrix and solved it with Gaussian elimination. The solution consists entirely of byte values, giving the state immediately before the final checks:

```text
6cafc8323d654776a8dd07eb9952338b9195bea30295dd826fa3c4066f926ed6f2df257bbf94a177
```

### 3. Undo the reversible prefix

The first 90 VM instructions use five operations:

| Opcode | Forward operation | Inverse used by the solver |
| --- | --- | --- |
| `0` | `r[a] += rol(r[b], rot)` | subtract the same rotated source |
| `1` | `r[a] ^= rol(r[b], rot)` | apply the same XOR again |
| `2` | `r[a] *= imm` modulo $2^{64}$ | multiply by `imm⁻¹` modulo $2^{64}$ |
| `3` | rotate `r[a]` left | rotate `r[a]` right |
| `4` | swap `r[a]` and `r[b]` | swap them again |

All multiplication constants are odd, so each has an inverse modulo $2^{64}$. Reversing the operations in descending program-counter order recovers the original 40-byte input block. The final seven bytes are `0x07` padding; removing them leaves the flag.

## Reproducing the result

Requires Python 3.8 or later. The solver is self-contained and uses only the Python standard library:

```bash
python solve.py
```

It solves the modular system, reverses the VM prefix, and checks both transformations before printing the recovered block and flag. It operates on the decoded VM data embedded in the script; reproducing the runtime trace from the challenge ELF is a separate step.

## Repository layout

```text
README.md                             this writeup
solve.py                              VM data and algebraic solver
challenge/intmod                      supplied ELF executable
```

## Result

The binary reports `Correct` for the flag followed by seven `0x07` padding bytes. The flag is:

```text
sun{I_L0v3_Int3rrupts&SelfMod!!!}
```
