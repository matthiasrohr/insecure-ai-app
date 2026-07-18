"""Fetch the pinned GGUF model for `LLM_PROVIDER=local`.

Idempotent: re-running is a no-op once the file is present and its checksum
matches. Uses urllib so the local provider needs no extra download dependency.
"""

from __future__ import annotations

import hashlib
import sys
import urllib.request

from . import config


def _sha256(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _progress(count: int, block_size: int, total: int) -> None:
    if total <= 0:
        return
    done = min(count * block_size, total)
    sys.stderr.write(f"\r  {done / 1e6:6.0f} / {total / 1e6:.0f} MB")
    sys.stderr.flush()


def ensure_model() -> str:
    """Download the model unless it is already there. Returns its path."""
    if config.LOCAL_MODEL_PATH.exists():
        # Size check only -- hashing 1.1 GB on every start is not worth it, and
        # the .part/rename dance below rules out truncated files.
        if config.LOCAL_MODEL_PATH.stat().st_size == config.LOCAL_MODEL_BYTES:
            return str(config.LOCAL_MODEL_PATH)
        print("Unexpected size, re-downloading.", file=sys.stderr)
        config.LOCAL_MODEL_PATH.unlink()

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {config.LOCAL_MODEL_FILE} (~1.1 GB, one time)", file=sys.stderr)
    partial = config.LOCAL_MODEL_PATH.with_suffix(".part")
    try:
        urllib.request.urlretrieve(config.LOCAL_MODEL_URL, partial, _progress)
    except BaseException:
        partial.unlink(missing_ok=True)  # never leave a truncated file behind
        raise
    print(file=sys.stderr)

    actual = _sha256(partial)
    if actual != config.LOCAL_MODEL_SHA256:
        partial.unlink(missing_ok=True)
        raise SystemExit(f"Checksum mismatch: expected {config.LOCAL_MODEL_SHA256}, got {actual}")

    partial.rename(config.LOCAL_MODEL_PATH)
    return str(config.LOCAL_MODEL_PATH)


if __name__ == "__main__":
    print(ensure_model())
