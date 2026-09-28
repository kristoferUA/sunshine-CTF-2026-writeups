# You Cut Me Off

SunshineCTF 2026 · forensics · author: [kristoferUA](https://github.com/kristoferUA)

The supplied `hereyougo.png` looks like an ordinary chat screenshot. Its header declares fewer rows than the image data contains. I restored the missing rows to reveal the flag in the input bar.

Flag: `sun{totallyoriginalchallengeidea}`

## Solution

### Checking the image dimensions

The PNG header declares a 492 × 382 image, with 8-bit RGBA pixels and no interlacing. Each row uses one filter byte followed by four bytes per pixel:

```text
1 + (492 × 4) = 1,969 bytes per row
```

The declared height accounts for 752,158 decompressed bytes. The concatenated `IDAT` data expands to 823,042 bytes, leaving 70,884 bytes:

```text
823,042 − 752,158 = 70,884
70,884 ÷ 1,969 = 36 extra rows
```

All 36 rows begin with filter type `0`, so they are complete RGBA rows. The `IHDR` height is the only thing preventing an image viewer from showing them.

### Restoring the missing rows

Set the `IHDR` height from 382 to 418 and recalculate that chunk's CRC32. The compressed `IDAT` data is already complete and can be left unchanged. Opening the corrected PNG reveals the bottom of the chat screenshot; the flag is in the input bar.

## Reproducing the result

Run the included script with Python 3.10 or newer from this directory. It uses only the standard library:

```bash
python solve.py
```

The script writes `challenge/hereyougo_unclipped.png` and reports the recovered dimensions. Open that image to read the flag in the input bar.

## Repository layout

```text
README.md                             this writeup
solve.py                              PNG height and CRC repair
challenge/hereyougo.png               supplied screenshot
```

## Result

The recovered flag is:

```text
sun{totallyoriginalchallengeidea}
```
