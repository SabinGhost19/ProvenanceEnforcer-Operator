from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from kubernetes import client

from ..attestations.fetch import fetch_vbbi_attestation
from ..attestations.policy import validate_voucher_policy
from ..config import PLURAL, SCA_PLURAL, TRUST_UNTRUSTED, TRUST_VERIFIED, VBBI_HMAC_KEY
from ..errors import ProvenanceVerificationError
from ..k8s.policies import get_matching_policy
from ..k8s.status import default_provenance_state, patch_status
from ..security.hmac_chain import verify_hmac_chain
from ..security.merkle import verify_merkle_root


logger = logging.getLogger(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_context(namespace: str, name: str, image: str | None = None) -> dict[str, str]:
    context = {"namespace": namespace, "zta": name}
    if image:
        context["image"] = image
    return context


def format_context(**values: str) -> str:
    return " ".join(f"{key}={value}" for key, value in values.items() if value)


def evaluate_application(custom: client.CustomObjectsApi, item: dict[str, Any], version: str = "v1") -> None:
    metadata = item.get("metadata", {}) or {}
    namespace = str(metadata.get("namespace", ""))
    name = str(metadata.get("name", ""))
    labels = metadata.get("labels", {}) or {}
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    image = str(spec.get("image", "")).strip()

    trust_level = str(status.get("trustLevel", TRUST_UNTRUSTED) or TRUST_UNTRUSTED)
    provenance_status = status.get("provenance", {}) or {}

    logger.info("Starting provenance evaluation %s", format_context(**log_context(namespace=namespace, name=name, image=image)))

    policy = get_matching_policy(
        custom,
        version=version,
        plural=SCA_PLURAL,
        namespace=namespace,
        app_name=name,
        labels=labels,
        app_spec=spec,
    )
    provenance_policy = ((policy or {}).get("spec", {}) or {}).get("provenance", {}) or {}
    source_validation = ((policy or {}).get("spec", {}) or {}).get("sourceValidation", {}) or {}
    require_voucher = bool(provenance_policy.get("requireVoucher", False))

    logger.info(
        "Resolved provenance policy %s",
        format_context(
            **log_context(namespace=namespace, name=name, image=image),
            policy=str(((policy or {}).get("metadata", {}) or {}).get("name", "")),
            requireVoucher=str(require_voucher).lower(),
        ),
    )

    if not policy:
        logger.info(
            "No voucher required by policy; setting default trust state %s",
            format_context(**log_context(namespace=namespace, name=name, image=image)),
        )
        patch_status(
            custom,
            namespace,
            name,
            PLURAL,
            {
                "trustLevel": trust_level if trust_level == TRUST_VERIFIED else TRUST_UNTRUSTED,
                "provenance": {**default_provenance_state(False), **provenance_status},
            },
        )
        return

    if not require_voucher:
        logger.info(
            "Voucher not required by policy; setting default trust state %s",
            format_context(**log_context(namespace=namespace, name=name, image=image)),
        )
        patch_status(
            custom,
            namespace,
            name,
            PLURAL,
            {
                "trustLevel": trust_level if trust_level == TRUST_VERIFIED else TRUST_UNTRUSTED,
                "provenance": {**default_provenance_state(False), **provenance_status},
            },
        )
        return

    trusted_issuers = [
        str(item).strip()
        for item in (source_validation.get("trustedIssuers", []) or [])
        if str(item).strip()
    ]
    if not trusted_issuers:
        raise ValueError("SupplyChainAttestation.sourceValidation.trustedIssuers is empty")

    logger.info(
        "Fetching VBBI attestation %s",
        format_context(
            **log_context(namespace=namespace, name=name, image=image),
            trustedIssuers=",".join(trusted_issuers),
        ),
    )

    voucher = fetch_vbbi_attestation(image=image, trusted_issuers=trusted_issuers)
    logger.info(
        "VBBI attestation fetched successfully %s",
        format_context(**log_context(namespace=namespace, name=name, image=image)),
    )

    voucher_policy = validate_voucher_policy(
        voucher=voucher,
        image=image,
        min_slsa_level=int(provenance_policy.get("minSlsaLevel", 0) or 0),
        trusted_repositories=[
            str(item).strip()
            for item in (provenance_policy.get("trustedRepositories", []) or [])
            if str(item).strip()
        ],
    )
    logger.info(
        "Voucher policy validation passed %s",
        format_context(
            **log_context(namespace=namespace, name=name, image=image),
            repository=str(voucher_policy.get("repository", "")),
            slsaLevel=str(voucher_policy.get("slsaLevel", "")),
            stepCount=str(voucher_policy.get("stepCount", "")),
        ),
    )

    hmac_result = verify_hmac_chain(
        predicate=voucher.get("predicate", {}) or {},
        secret_key=VBBI_HMAC_KEY,
        enforce=bool(provenance_policy.get("enforceHmacChain", True)),
    )
    merkle_result = verify_merkle_root(predicate=voucher.get("predicate", {}) or {})

    logger.info(
        "Cryptographic verification passed %s",
        format_context(
            **log_context(namespace=namespace, name=name, image=image),
            hmacProvider=str(hmac_result.get("provider", "")),
            verifiedSteps=str(hmac_result.get("steps", "")),
            merkleRoot=str(merkle_result.get("computedRoot", "")),
        ),
    )

    patch_status(
        custom,
        namespace,
        name,
        PLURAL,
        {
            "trustLevel": TRUST_VERIFIED,
            "lastError": "",
            "provenance": {
                **default_provenance_state(True),
                "verifiedAt": utc_now(),
                "statementType": voucher_policy.get("statementType"),
                "stepCount": voucher_policy.get("stepCount"),
                "repository": voucher_policy.get("repository"),
                "slsaLevel": voucher_policy.get("slsaLevel"),
                "subjectVerified": voucher_policy.get("subjectVerified", False),
                "hmacChain": hmac_result,
                "merkle": merkle_result,
                "reason": "",
            },
        },
    )
    logger.info(
        "Provenance verification completed successfully %s",
        format_context(**log_context(namespace=namespace, name=name, image=image), trustLevel=TRUST_VERIFIED),
    )
