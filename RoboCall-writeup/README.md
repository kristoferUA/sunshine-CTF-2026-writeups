# RoboCall

SunshineCTF 2026 · pwn · author: [kristoferUA](https://github.com/kristoferUA)

The service is an IVR maze with a stack leak in its cancellation flow. An empty answer leaves a local integer uninitialized, and the program prints its value as a decimal number. I used different menu depths to read the flag four bytes at a time.

Flag: `sun{you_must_be_some_sort_of_nimble_space_navigator}`

## Solution

### Finding the leak

At startup, `main` calls `place_flag()`. It copies the flag into thirteen four-byte chunks at known stack depths listed in `CHUNK_DEPTH`.

The cancellation path asks several questions and then prints a local integer. When the final confirmation is left empty, that integer is never assigned a new value. By choosing how deeply the IVR menus are nested before reaching cancellation, the integer lands on top of one of the flag chunks. The service prints the four bytes as a decimal integer.

The menu path for the first chunk is:

1. Enter `42` at the top menu to disable the artificial delay.
2. Choose **Call** (`1`), then **Report an outage** (`2`), and enter any address. This returns to a nested start menu at depth `0x400`.
3. From that menu choose **Call** (`1`), **Other inquiries** (`6`), then **Cancel** (`2`).
4. Give any phone number, address, and pet name. Leave both confirmation answers empty.

The cancellation prompt prints `2070836595`. This is the first four flag bytes, interpreted as a little-endian integer.

### Reassembling the chunks

Repeat the cancellation leak at each depth from `CHUNK_DEPTH`. Convert each printed integer to four little-endian bytes, then concatenate the chunks in table order:

| Depth | Decimal leak | Bytes (little-endian) | Text |
| --- | ---: | --- | --- |
| `0x400` | 2070836595 | `73 75 6e 7b` | `sun{` |
| `0x480` | 1601531769 | `79 6f 75 5f` | `you_` |
| `0x520` | 1953723757 | `6d 75 73 74` | `must` |
| `0x570` | 1600479839 | `5f 62 65 5f` | `_be_` |
| `0x5a0` | 1701670771 | `73 6f 6d 65` | `some` |
| `0x640` | 1919906655 | `5f 73 6f 72` | `_sor` |
| `0x690` | 1718574964 | `74 5f 6f 66` | `t_of` |
| `0x6c0` | 1835626079 | `5f 6e 69 6d` | `_nim` |
| `0x760` | 1600482402 | `62 6c 65 5f` | `ble_` |
| `0x7b0` | 1667330163 | `73 70 61 63` | `spac` |
| `0x7e0` | 1634623333 | `65 5f 6e 61` | `e_na` |
| `0x800` | 1634167158 | `76 69 67 61` | `viga` |
| `0x880` | 2104651636 | `74 6f 72 7d` | `tor}` |

## Reproducing the result

Connect to the challenge service:

```text
nc sunshinectf.games 26199
```

Follow the cancellation path at each depth listed above. The included decoder converts the observed decimal values into four-byte little-endian chunks:

```bash
python decode_leaks.py
```

## Repository layout

```text
README.md                             this writeup
decode_leaks.py                       converts captured leaks to text
challenge/robocall                    supplied executable
```

## Result

The recovered flag is:

```text
sun{you_must_be_some_sort_of_nimble_space_navigator}
```
