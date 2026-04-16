from __future__ import annotations

from typing import Any

from kubernetes import client
from kubernetes.client.exceptions import ApiException

from ..config import GROUP
from ..errors import ProvenanceVerificationError


def security_policy_ref_name(spec: dict[str, Any] | None) -> str:
    if not spec:
        return ""
    policy_ref = (spec.get("securityPolicyRef", {}) or {})
    return str(policy_ref.get("name", "")).strip()


def get_policy_by_reference(
    custom: client.CustomObjectsApi,
    version: str,
    plural: str,
    app_spec: dict[str, Any] | None,
) -> dict[str, Any] | None:
    policy_name = security_policy_ref_name(app_spec)
    if not policy_name:
        return None
    try:
        return custom.get_cluster_custom_object(group=GROUP, version=version, plural=plural, name=policy_name)
    except ApiException as exc:
        if exc.status == 404:
            raise ProvenanceVerificationError(f"Referenced SupplyChainAttestation not found: {policy_name}") from exc
        raise


def policy_targets_zta(
    policy: dict[str, Any],
    namespace: str,
    app_name: str,
    labels: dict[str, str],
    app_spec: dict[str, Any] | None = None,
) -> bool:
    referenced_name = security_policy_ref_name(app_spec)
    if not referenced_name:
        return False
    policy_name = str((policy.get("metadata", {}) or {}).get("name", "")).strip()
    return policy_name == referenced_name


def get_matching_policy(
    custom: client.CustomObjectsApi,
    version: str,
    plural: str,
    namespace: str,
    app_name: str,
    labels: dict[str, str],
    app_spec: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    referenced_policy = get_policy_by_reference(custom, version=version, plural=plural, app_spec=app_spec)
    if referenced_policy is not None:
        return referenced_policy
    if security_policy_ref_name(app_spec):
        return None
    raise ProvenanceVerificationError("ZeroTrustApplication.spec.securityPolicyRef.name is required")
