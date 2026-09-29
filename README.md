# SunshineCTF 2026 writeups

Writeups prepared by [kristoferUA](https://github.com/kristoferUA) for SunshineCTF 2026. Each folder contains a writeup and any solver or challenge files kept with it.

| Challenge | Category | What the writeup covers |
| --- | --- | --- |
| [Cache Money](cache-money-writeup/README.md) | pwn | A dangling heap ledger, tcache poisoning, and a redirected function call. |
| [Code Breaker](code-breaker-writeup/README.md) | pwn | An encrypted protocol, a dangling entry, and callback replacement. |
| [FlameOn](flame-on-writeup/README.md) | reverse engineering | Recovering a flag from an XOR routine embedded in a BPS patch. |
| [Ghost in the Thread 1](ghost-in-the-thread-1-writeup/README.md) | forensics | Following an upload into a VM image and decoding a staged ELF payload. |
| [Homemaker](homemaker-writeup/README.md) | pwn | A punch-card copy error that expands a read and enables a return chain. |
| [IntMod](intmod-writeup/README.md) | reverse engineering | Tracing a virtual machine and solving its modular checks. |
| [Mad Libs](mad-libs-writeup/README.md) | pwn | A format-string leak and overwrite of `printf@GOT`. |
| [My Eyes Burn](my-eyes-burn-writeup/README.md) | keyboard layout | Following a dead-key state chain in a Windows layout file. |
| [NAS coal](NAS-coal-writeup/README.md) | forensics | Decoding a Base64 value from a presentation's VBA project. |
| [Print Print Revolution](print-print-revolution-writeup/README.md) | pwn | A custom format string, dynamic-linker symbol resolution, and a GOT overwrite. |
| [RoboCall](RoboCall-writeup/README.md) | pwn | Reassembling the flag from uninitialized stack values. |
| [Safe House](safe-house-writeup/README.md) | pwn | A stack overflow and negative record index in a vault service. |
| [Suntrail](suntrail-writeup/README.md) | keyboard layout | Recovering a flag from the Shift layer's character pool. |
| [Total Recall](total-recall-writeup/README.md) | pwn | Using a stack leak and signal frames to read the flag file. |
| [Vecnet](Vecnet-writeup/README.md) | web | Recovering service credentials and inverting an embedding to open an archive. |
| [Welcome Call!](welcome-call-writeup/README.md) | forensics | Extracting a spoken message from SIP and RTP traffic. |
| [You Cut Me Off](you-cut-me-off-writeup/README.md) | forensics | Restoring PNG rows hidden by an incorrect image height. |

The VM image used by **Ghost in the Thread 1** is stored separately; its writeup explains where to place it.

## License

The original writeups and solver code in this collection are available under the [MIT License](LICENSE). Files in `challenge/` were supplied with the tasks and are not covered by this license.
