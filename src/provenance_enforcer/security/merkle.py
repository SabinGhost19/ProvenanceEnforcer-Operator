from __future__ import annotations

import hashlib
from typing import Any

from ..errors import ProvenanceVerificationError
from .hash_utils import normalize_hex, sha256_text


# RFC 6962 §2.1 — domain-separated Merkle hashing:
#   MTH({d(0)})           = SHA-256(0x00 || d(0))
#   MTH(D[n])             = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
# Prevents second-preimage attacks where a leaf can be forged from an
# adversarially-chosen internal node value.
def _merkle_leaf_hash(data_hex: str) -> str:
    return hashlib.sha256(b"\x00" + bytes.fromhex(data_hex)).hexdigest()


def _merkle_node_hash(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def compute_merkle_root(leaves: list[str], *, rfc6962: bool = True) -> str:
    if not leaves:
        raise ProvenanceVerificationError("Merkle tree requires at least one leaf")

    if rfc6962:
        nodes = [_merkle_leaf_hash(normalize_hex(leaf)) for leaf in leaves]
    else:
        nodes = [sha256_text(normalize_hex(leaf)) for leaf in leaves]

    while len(nodes) > 1:
        next_level: list[str] = []
        for index in range(0, len(nodes), 2):
            left = nodes[index]
            right = nodes[index + 1] if index + 1 < len(nodes) else left
            next_level.append(
                _merkle_node_hash(left, right) if rfc6962 else sha256_text(left + right)
            )
        nodes = next_level
    return nodes[0]


def verify_merkle_root(predicate: dict[str, Any]) -> dict[str, Any]:
    merkle = predicate.get("merkle_tree", {}) or {}
    if not merkle:
        chain = predicate.get("hmac_chain", {}) or {}
        merkle = {
            "root_hash": chain.get("root_hash"),
            "leaves": chain.get("leaves", []),
        }

    # Version negotiation: v2+ (and explicit `rfc6962-sha256` algorithm)
    # use RFC 6962 domain separation. Legacy vouchers (no version field,
    # or version == 1) fall back to plain concatenation hashing.
    version = int(merkle.get("version", 1) or 1)
    algorithm = str(merkle.get("algorithm", "") or "").strip().lower()
    rfc6962 = version >= 2 or algorithm == "rfc6962-sha256"

    leaves_raw = merkle.get("leaves", []) or []
    if not leaves_raw:
        raise ProvenanceVerificationError("Voucher is missing predicate.merkle_tree.leaves")

    leaves: list[str] = []
    step_names: list[str] = []
    for item in leaves_raw:
        if isinstance(item, dict):
            step_names.append(str(item.get("step", "")).strip())
            leaf_hash = str(item.get("hash", "")).strip()
            if leaf_hash:
                leaves.append(leaf_hash)
        else:
            leaf_hash = str(item).strip()
            if leaf_hash:
                leaves.append(leaf_hash)
                step_names.append("")

    if not leaves:
        raise ProvenanceVerificationError("Voucher predicate.merkle_tree.leaves is empty")

    chain_steps = (predicate.get("hmac_chain", {}) or {}).get("steps", []) or []
    if len(chain_steps) != len(leaves):
        raise ProvenanceVerificationError("Merkle tree leaf count does not match HMAC chain step count")

    for index, step in enumerate(chain_steps):
        step_name = str((step or {}).get("step_name", "")).strip()
        expected_leaf = normalize_hex(str((step or {}).get("hmac_result", "")).strip())
        if step_names[index] and step_names[index] != step_name:
            raise ProvenanceVerificationError("Merkle tree step ordering does not match HMAC chain")
        if normalize_hex(leaves[index]) != expected_leaf:
            raise ProvenanceVerificationError("Merkle tree leaf hash does not match HMAC chain result")

    computed_root = compute_merkle_root(leaves, rfc6962=rfc6962)
    expected_root = normalize_hex(str(merkle.get("root_hash", "")).strip())
    if not expected_root:
        raise ProvenanceVerificationError("Voucher is missing predicate.merkle_tree.root_hash")
    if computed_root != expected_root:
        raise ProvenanceVerificationError("Merkle root mismatch")

    return {
        "verified": True,
        "computedRoot": computed_root,
        "expectedRoot": expected_root,
        "leafCount": len(leaves),
        "merkleVersion": 2 if rfc6962 else 1,
        "merkleAlgorithm": "rfc6962-sha256" if rfc6962 else "plain-sha256",
    }
