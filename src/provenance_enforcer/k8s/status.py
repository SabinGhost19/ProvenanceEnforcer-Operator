from __future__ import annotations

from typing import Any

from kubernetes import client

from ..config import GROUP, TRUST_UNTRUSTED_PROVENANCE, VBBI_HMAC_MODE


def patch_status(custom: client.CustomObjectsApi, namespace: str, name: str, plural: str, patch: dict[str, Any]) -> None:
    custom.patch_namespaced_custom_object_status(
        group=GROUP,
        version="v1",
        namespace=namespace,
        plural=plural,
        name=name,
        body={"status": patch},
    )


def default_provenance_state(required: bool) -> dict[str, Any]:
    return {
        "required": required,
        "verifiedAt": None,
        "attestationType": "https://devsecops.licenta.ro/VBBI/v1",
        "hmacMode": VBBI_HMAC_MODE,
    }


def set_failure_status(
    custom: client.CustomObjectsApi,
    namespace: str,
    name: str,
    plural: str,
    reason: str,
    provenance_patch: dict[str, Any] | None = None,
) -> None:
    patch = {
        "trustLevel": TRUST_UNTRUSTED_PROVENANCE,
        "lastError": reason,
        "provenance": {
            **default_provenance_state(True),
            "verifiedAt": None,
            "reason": reason,
        },
    }
    if provenance_patch:
        patch["provenance"].update(provenance_patch)
    patch_status(custom, namespace, name, plural, patch)
