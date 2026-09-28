# NAS coal

SunshineCTF 2026 · forensics · author: [kristoferUA](https://github.com/kristoferUA)

The supplied `gem_collection.pptm` looks like a short meme deck. Slide 5 points to its VBA project, where I found a Base64 string containing the flag. This repository contains the presentation and my extraction script.

Flag: `sun{yup_issa_gem}`

## Solution

### Finding the source

A `.pptm` file is an Open XML ZIP package. Its VBA project is stored at `ppt/vbaProject.bin`. The project contains a module named `MediaCache`.

The module source defines an `encoded` string. Decoding that value as Base64 and then UTF-16LE reveals a PowerShell text block. The flag appears in the `$campaign` value:

```text
$campaign = 'sun{yup_issa_gem}'
```

`RefreshCache` only sends its assembled text to `Debug.Print`. The flag can be recovered by reading the project data; the presentation does not need to run its macro.

### Decoding the macro data

1. Open the presentation as a ZIP package and extract `ppt/vbaProject.bin`.
2. Read the VBA project directory and locate the `MediaCache` module source.
3. Decode the module source container and find the Base64 value assigned to `encoded`.
4. Decode that value using UTF-16LE and read the flag from `$campaign`.

The included `solve.py` performs these steps with Python's standard library.

## Reproducing the result

Python 3.10 or newer is recommended.

```bash
python solve.py
python solve.py challenge/gem_collection.pptm
```

Expected output:

```text
sun{yup_issa_gem}
```

## Repository layout

```text
README.md                             this writeup
solve.py                              standard-library VBA extractor
challenge/gem_collection.pptm         supplied presentation
```

## Result

The recovered flag is:

```text
sun{yup_issa_gem}
```
