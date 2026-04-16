from __future__ import annotations

import hashlib


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_hex(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized.startswith("sha256:"):
        return normalized.split(":", 1)[1]
    if normalized.startswith("vault:v"):
        parts = normalized.split(":", 2)
        if len(parts) == 3:
            return parts[2]
    return normalized
