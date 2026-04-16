from __future__ import annotations

from typing import Any

from ..errors import ProvenanceVerificationError
from .hash_utils import normalize_hex, sha256_text


def compute_merkle_root(leaves: list[str]) -> str:
    if not leaves:
        raise ProvenanceVerificationError("Merkle tree requires at least one leaf")

    nodes = [sha256_text(normalize_hex(leaf)) for leaf in leaves]
    while len(nodes) > 1:
        next_level: list[str] = []
        for index in range(0, len(nodes), 2):
            left = nodes[index]
            right = nodes[index + 1] if index + 1 < len(nodes) else left
            next_level.append(sha256_text(left + right))
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

    computed_root = compute_merkle_root(leaves)
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
    }
