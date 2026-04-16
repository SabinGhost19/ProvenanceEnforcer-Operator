from __future__ import annotations

import hashlib
import hmac
from typing import Any

from ..config import VBBI_HMAC_MODE
from ..errors import ProvenanceVerificationError
from .hash_utils import normalize_hex
from .vault import compute_transit_hmac


def compute_step_hmac(metadata_hash: str, previous: str, secret_key: str) -> str:
    payload = f"{metadata_hash}{previous}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_chain_structure(chain: dict[str, Any]) -> tuple[list[dict[str, Any]], str, str, str]:
    provider = str(chain.get("provider", "shared-secret") or "shared-secret").strip().lower()
    algorithm = str(chain.get("algorithm", "") or "").strip().lower()
    seed = str(chain.get("h0_seed", "")).strip()
    final_voucher = str(chain.get("final_voucher", "")).strip()
    steps = chain.get("steps", []) or []

    if provider not in {"shared-secret", "vault-transit"}:
        raise ProvenanceVerificationError(f"Unsupported VBBI hmac_chain.provider '{provider}'")
    if algorithm not in {"sha256", "sha2-256"}:
        raise ProvenanceVerificationError(f"Unsupported VBBI hmac_chain.algorithm '{algorithm}'")
    if not seed:
        raise ProvenanceVerificationError("Voucher is missing predicate.hmac_chain.h0_seed")
    if not final_voucher:
        raise ProvenanceVerificationError("Voucher is missing predicate.hmac_chain.final_voucher")
    if not isinstance(steps, list) or not steps:
        raise ProvenanceVerificationError("Voucher is missing predicate.hmac_chain.steps")

    seen_step_names: set[str] = set()
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            raise ProvenanceVerificationError(f"Voucher step {index} must be an object")
        step_name = str(step.get("step_name", "")).strip()
        metadata_hash = str(step.get("metadata_hash", "")).strip()
        expected_result = str(step.get("hmac_result", "")).strip()
        position = int(step.get("position", index) or index)
        if not step_name or not metadata_hash or not expected_result:
            raise ProvenanceVerificationError(f"Voucher step {index} is missing step_name, metadata_hash or hmac_result")
        if position != index:
            raise ProvenanceVerificationError(f"Voucher step {step_name} has invalid position {position}, expected {index}")
        if step_name in seen_step_names:
            raise ProvenanceVerificationError(f"Voucher step_name '{step_name}' is duplicated")
        seen_step_names.add(step_name)

    return steps, seed, final_voucher, provider


def verify_hmac_chain(predicate: dict[str, Any], secret_key: str, enforce: bool = True) -> dict[str, Any]:
    chain = predicate.get("hmac_chain", {}) or {}
    if not enforce:
        return {"verified": False, "steps": 0, "reason": "hmac-chain-enforcement-disabled"}

    steps, seed, final_voucher, provider = verify_chain_structure(chain)
    configured_mode = VBBI_HMAC_MODE.strip().lower()
    if configured_mode != provider:
        raise ProvenanceVerificationError(
            f"Voucher requires hmac provider '{provider}' but operator is configured for '{configured_mode}'"
        )

    previous = normalize_hex(seed)
    for index, step in enumerate(steps, start=1):
        metadata_hash = normalize_hex(str(step.get("metadata_hash", "")).strip())
        expected_result = normalize_hex(str(step.get("hmac_result", "")).strip())
        if provider == "vault-transit":
            computed = normalize_hex(compute_transit_hmac(f"{metadata_hash}{previous}"))
        else:
            computed = compute_step_hmac(metadata_hash, previous, secret_key)
        if computed != expected_result:
            step_name = str(step.get("step_name", f"step-{index}"))
            raise ProvenanceVerificationError(f"HMAC chain mismatch at {step_name}")
        previous = computed

    if previous != normalize_hex(final_voucher):
        raise ProvenanceVerificationError("Final voucher does not match the last HMAC chain value")

    return {
        "verified": True,
        "steps": len(steps),
        "provider": provider,
        "finalVoucher": previous,
    }
