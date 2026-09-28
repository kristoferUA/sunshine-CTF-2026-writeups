# Vecnet

SunshineCTF 2026 · web · author: [kristoferUA](https://github.com/kristoferUA)

VecNet's public Git metadata exposed a removed configuration file with credentials for its internal services. I used those credentials to reach a MailHog inbox and a ChromaDB collection containing an embedded password hint. This repository contains the encrypted archive and my solver.

Flag: `sun{k33p_your_emb3ddings_secur3!}`

## Solution

### Recovering the service credentials

The website exposed `/.git/logs/HEAD`. Its history showed that an internal configuration file containing credentials had been added and then removed. Fetching the earlier Git object recovered the MailHog login and the ChromaDB API key. The current Git tree also revealed that `fetch.php` only accepts one hard-coded localhost URL, which can be supplied to download the encrypted `specs.7z` archive.

### Finding the password clues

The MailHog API on port `8025` was protected by the recovered credentials. One email gave the Vec2Text inversion settings, `num_steps=4` and `sequence_beam_width=5`, and described the password format.

The ChromaDB API on port `8000` accepted the recovered API key. In its `VecNetDB` collection, the `user_password_requirements` record had no document text, only a 768-dimensional embedding. Its metadata identified the model as `jxm/gtr__nq__32`. The same collection contained a SHA-256 password hash and the magic string `sunshinectf8_`.

### Recovering and cracking the password

I inverted the requirement embedding with Vec2Text and the settings from the email. It says the password is the user's first and last initials, followed by three special characters and the magic string. The leaked email identifies Greg Roberts, so the initials are `GR`.

The solver tries all printable ASCII punctuation triples after those initials and checks each candidate against the stored SHA-256 hash. The matching password decrypts `specs.7z`, revealing the flag.

## Reproducing the result

Python 3.10 or newer is recommended. The first run downloads the Vec2Text checkpoints.

```bash
python -m venv .venv
source .venv/bin/activate                 # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python solve.py
```

The solver connects to the live challenge, reads the exposed Git objects and internal services, downloads the archive, and prints the recovered flag.

## Repository layout

```text
README.md                             this writeup
solve.py                              credential and archive solver
requirements.txt                      Python dependencies
challenge/specs.7z                    encrypted challenge archive
```

## Result

The recovered flag is:

```text
sun{k33p_your_emb3ddings_secur3!}
```
