from __future__ import annotations

import hashlib
import hmac
import json
import unittest

from provenance_enforcer.crypto import compute_merkle_root, verify_hmac_chain, verify_merkle_root
from provenance_enforcer.voucher import validate_vbbi_structure, validate_voucher_policy


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _metadata_hash(payload: dict[str, object]) -> str:
    return _sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _hmac_step(secret_key: str, metadata_hash: str, previous_hash: str) -> str:
    return hmac.new(
        secret_key.encode("utf-8"),
        f"{metadata_hash}{previous_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class SharedSecretVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret_key = "smoke-test-key"
        self.image = "ghcr.io/example/demo@sha256:" + "a" * 64
        self.commit_sha = "b" * 40
        self.repository = "example/demo"

        self.step_payloads = [
            ("linting", {"status": "ok", "violations": 0}),
            ("unit-tests", {"status": "ok", "passed": 8, "failed": 0}),
            ("image-build", {"status": "ok", "image": self.image}),
            ("vulnerability-scan", {"status": "ok", "critical": 0, "high": 0}),
        ]

        seed = _sha256_text(self.commit_sha)
        previous = seed
        steps: list[dict[str, object]] = []
        leaves: list[dict[str, str]] = []
        for index, (step_name, payload) in enumerate(self.step_payloads, start=1):
            metadata_hash = _metadata_hash(payload)
            current = _hmac_step(self.secret_key, metadata_hash, previous)
            steps.append(
                {
                    "position": index,
                    "step_name": step_name,
                    "metadata_hash": metadata_hash,
                    "hmac_result": current,
                }
            )
            leaves.append({"step": step_name, "hash": current})
            previous = current

        self.voucher = {
            "statementType": "https://in-toto.io/Statement/v1",
            "subject": [{"name": self.image, "digest": {"sha256": "a" * 64}}],
            "predicate": {
                "build_context": {
                    "repository": self.repository,
                    "workflow": "ci-cd",
                    "run_id": "12345",
                    "event": "push",
                    "issuer_oidc": "https://token.actions.githubusercontent.com",
                    "slsa_level": 3,
                    "image": self.image,
                    "commit_sha": self.commit_sha,
                },
                "hmac_chain": {
                    "provider": "shared-secret",
                    "algorithm": "sha256",
                    "h0_seed": seed,
                    "steps": steps,
                    "final_voucher": previous,
                },
                "merkle_tree": {
                    "leaves": leaves,
                    "root_hash": compute_merkle_root([item["hash"] for item in leaves]),
                },
            },
        }

    def test_structure_is_valid(self) -> None:
        info = validate_vbbi_structure(self.voucher)
        self.assertEqual(info["statementType"], "https://in-toto.io/Statement/v1")
        self.assertEqual(info["stepCount"], 4)
        self.assertEqual(info["subjectCount"], 1)

    def test_policy_validation_and_chain_verification_pass(self) -> None:
        policy = validate_voucher_policy(
            voucher=self.voucher,
            image=self.image,
            min_slsa_level=3,
            trusted_repositories=[self.repository],
        )
        chain = verify_hmac_chain(self.voucher["predicate"], self.secret_key, enforce=True)
        merkle = verify_merkle_root(self.voucher["predicate"])

        self.assertEqual(policy["repository"], self.repository)
        self.assertEqual(policy["stepCount"], 4)
        self.assertTrue(policy["subjectVerified"])
        self.assertTrue(chain["verified"])
        self.assertEqual(chain["provider"], "shared-secret")
        self.assertTrue(merkle["verified"])

    def test_tampered_leaf_fails_merkle_validation(self) -> None:
        tampered = json.loads(json.dumps(self.voucher))
        tampered["predicate"]["merkle_tree"]["leaves"][1]["hash"] = "0" * 64
        with self.assertRaisesRegex(Exception, "Merkle tree leaf hash does not match HMAC chain result"):
            verify_merkle_root(tampered["predicate"])

    def test_wrong_secret_fails_hmac_validation(self) -> None:
        with self.assertRaisesRegex(Exception, "HMAC chain mismatch"):
            verify_hmac_chain(self.voucher["predicate"], "wrong-key", enforce=True)


if __name__ == "__main__":
    unittest.main()