# Ghost in the Thread 1

SunshineCTF 2026 · forensics · author: [kristoferUA](https://github.com/kristoferUA)

The challenge provides the last known imageboard posts as HTML and a separate virtual-machine image. I followed the server's upload trail into the VM and recovered a staged ELF payload that contains the flag.

Flag: `sun{tfw_hacked_by_offboarders}`

## Solution

### 1. Inspect the VM image

The OVA is a tar archive containing a stream-optimized sparse VMDK. `solve.py` expands its compressed grains into a sparse raw disk, reads the GPT, and locates the ext4 partition. It then walks the filesystem without mounting or executing anything from the image.

### 2. Follow the suspicious upload

The upload `/srv/sunchan/uploads/po_184726.pdf` is not a PDF: its content starts with a PostScript header. Its comments preserve the stage-two download destination and a SHA-256 digest:

```text
%%Document-ID: po-184726
%%Stage2-Destination: /var/tmp/sunchan-downloads/gs-resource.bin
%%Stage2-SHA256: 3cf1f62fe43202b9d0fc1ded2776fe7d40001d3fd6c8d23b53550d8edf0f3500
```

The corresponding file in the VM is an ELF executable. The solver checks the payload against the digest from the upload before decoding it.

### 3. Decode the payload

The ELF stores 30 encrypted bytes at file offset `0x2000`. The decoding key passes the payload's FNV-1a check (`0xDAC3D58D`); each byte is then decoded as:

```text
plaintext[i] = ciphertext[i] XOR key[i mod key_length] XOR 0x5a
```

The result is the SunshineCTF flag. The decoding key in the solver belongs to this payload layer; this writeup does not claim an answer to the separate planted-password prompt.

## Reproducing the result

Python 3.8 or newer is sufficient, and the solver uses only the standard library. The OVA is about 121 MiB and is stored separately. Download the original challenge image or [this copy](https://drive.google.com/file/d/1iVNBdkvBM9SV-QMaRvi8fQ-7inStrQtn/view?usp=sharing), then place it at `challenge/GhostInTheThread.ova`:

```bash
python solve.py
```

To use an OVA at another path:

```bash
python solve.py path/to/GhostInTheThread.ova
```

## Repository layout

```text
README.md                             this writeup
solve.py                              OVA, ext4, and payload decoder
challenge/sunchan.html                supplied imageboard posts
```

## Result

The recovered flag is:

```text
sun{tfw_hacked_by_offboarders}
```
