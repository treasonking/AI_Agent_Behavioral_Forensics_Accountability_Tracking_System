import hashlib
import json
from typing import Any


def canonical_json(data: Any) -> str:
    """Serialize arbitrary data into a deterministic JSON string."""
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


def sha256_text(text: str) -> str:
    """Return a SHA-256 hash with a stable prefix."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def sha256_json(data: Any) -> str:
    """Hash JSON-compatible data after canonical serialization."""
    return sha256_text(canonical_json(data))
