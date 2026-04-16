from __future__ import annotations

import base64
import json
from typing import Any

from ..config import VBBI_STATEMENT_TYPE
from ..errors import ProvenanceVerificationError


def extract_json_objects(output: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            objects.append(parsed)
    return objects


def decode_attestation_payload(attestation_obj: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    payload_b64 = attestation_obj.get("payload")
    if not payload_b64:
        return None, None

    decoded = base64.b64decode(payload_b64).decode("utf-8")
    statement = json.loads(decoded)
    predicate_type = statement.get("predicateType")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return predicate_type, None
    return predicate_type, {
        "predicate": predicate,
        "subject": statement.get("subject", []) or [],
        "statementType": statement.get("_type", ""),
    }


def validate_vbbi_structure(voucher: dict[str, Any]) -> dict[str, Any]:
    predicate = voucher.get("predicate", {}) or {}
    subject = voucher.get("subject", []) or []
    statement_type = str(voucher.get("statementType", "")).strip()
    build_context = predicate.get("build_context", {}) or {}
    hmac_chain = predicate.get("hmac_chain", {}) or {}
    merkle_tree = predicate.get("merkle_tree", {}) or {}

    if statement_type != VBBI_STATEMENT_TYPE:
        raise ProvenanceVerificationError(
            f"Voucher statement type '{statement_type}' does not match required '{VBBI_STATEMENT_TYPE}'"
        )
    if not isinstance(subject, list) or not subject:
        raise ProvenanceVerificationError("Voucher must contain at least one subject entry")

    required_context = [
        "repository",
        "workflow",
        "run_id",
        "event",
        "issuer_oidc",
        "slsa_level",
        "image",
        "commit_sha",
    ]
    missing_context = [key for key in required_context if str(build_context.get(key, "")).strip() == ""]
    if missing_context:
        raise ProvenanceVerificationError(
            f"Voucher build_context is missing required fields: {', '.join(missing_context)}"
        )

    steps = hmac_chain.get("steps", []) or []
    leaves = merkle_tree.get("leaves", []) or []
    if not isinstance(steps, list) or not steps:
        raise ProvenanceVerificationError("Voucher must include a non-empty hmac_chain.steps array")
    if not isinstance(leaves, list) or not leaves:
        raise ProvenanceVerificationError("Voucher must include a non-empty merkle_tree.leaves array")
    if len(steps) != len(leaves):
        raise ProvenanceVerificationError("Voucher hmac_chain.steps and merkle_tree.leaves must have the same length")

    subject_digests: list[str] = []
    for index, item in enumerate(subject, start=1):
        if not isinstance(item, dict):
            raise ProvenanceVerificationError(f"Voucher subject entry {index} must be an object")
        name = str(item.get("name", "")).strip()
        digest = str((((item.get("digest", {}) or {}).get("sha256", "")) or "")).strip().lower()
        if not name or not digest:
            raise ProvenanceVerificationError(f"Voucher subject entry {index} must contain name and digest.sha256")
        subject_digests.append(digest)

    return {
        "statementType": statement_type,
        "stepCount": len(steps),
        "subjectCount": len(subject),
        "subjectDigests": subject_digests,
    }
