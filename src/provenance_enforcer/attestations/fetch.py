from __future__ import annotations

import subprocess

from ..config import COSIGN_BIN, DEFAULT_ISSUER, VBBI_ATTESTATION_TYPE, VERIFY_TIMEOUT_SECONDS
from ..errors import ProvenanceVerificationError
from .parser import decode_attestation_payload, extract_json_objects


def fetch_vbbi_attestation(image: str, trusted_issuers: list[str]) -> dict:
    last_error = ""
    for identity in trusted_issuers:
        cmd = [
            COSIGN_BIN,
            "verify-attestation",
            image,
            "--type",
            VBBI_ATTESTATION_TYPE,
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            DEFAULT_ISSUER,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_SECONDS)
        if result.returncode != 0:
            last_error = result.stderr or result.stdout
            continue

        for obj in extract_json_objects(result.stdout):
            predicate_type, payload = decode_attestation_payload(obj)
            if payload is not None and predicate_type == VBBI_ATTESTATION_TYPE:
                return payload

        last_error = "VBBI attestation output could not be parsed"

    raise ProvenanceVerificationError(
        f"Unable to verify VBBI attestation with trusted issuers. Last error: {last_error}"
    )
