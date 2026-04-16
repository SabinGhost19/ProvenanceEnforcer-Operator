from __future__ import annotations

import base64
import json
from typing import Any
from urllib import error, request

from ..config import (
    VAULT_ADDR,
    VAULT_AUTH_METHOD,
    VAULT_KUBERNETES_AUTH_MOUNT,
    VAULT_KUBERNETES_JWT_FILE,
    VAULT_KUBERNETES_ROLE,
    VAULT_NAMESPACE,
    VAULT_TOKEN,
    VAULT_TOKEN_FILE,
    VAULT_TRANSIT_ALGORITHM,
    VAULT_TRANSIT_KEY,
    VAULT_TRANSIT_MOUNT,
)
from ..errors import ProvenanceVerificationError


def read_text_file(path: str) -> str:
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as exc:
        raise ProvenanceVerificationError(f"Unable to read file '{path}': {exc}") from exc


def build_headers(token: str) -> dict[str, str]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    if VAULT_NAMESPACE:
        headers["X-Vault-Namespace"] = VAULT_NAMESPACE
    return headers


def send_request(path: str, payload: dict[str, Any], token: str) -> dict[str, Any]:
    if not VAULT_ADDR:
        raise ProvenanceVerificationError("VAULT_ADDR must be configured for vault-transit verification")

    req = request.Request(
        url=f"{VAULT_ADDR.rstrip('/')}/v1/{path.lstrip('/')}",
        data=json.dumps(payload).encode("utf-8"),
        headers=build_headers(token),
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=30) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise ProvenanceVerificationError(f"Vault request failed for {path}: {details}") from exc
    except error.URLError as exc:
        raise ProvenanceVerificationError(f"Vault request failed for {path}: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ProvenanceVerificationError(f"Vault response for {path} is not a JSON object")
    return parsed


def get_vault_token() -> str:
    auth_method = VAULT_AUTH_METHOD.strip().lower()
    if auth_method == "token":
        token = VAULT_TOKEN.strip() or read_text_file(VAULT_TOKEN_FILE)
        if not token:
            raise ProvenanceVerificationError("VAULT_TOKEN or VAULT_TOKEN_FILE must be configured for token auth")
        return token

    if auth_method == "kubernetes":
        if not VAULT_KUBERNETES_ROLE:
            raise ProvenanceVerificationError("VAULT_KUBERNETES_ROLE must be configured for Kubernetes auth")
        jwt = read_text_file(VAULT_KUBERNETES_JWT_FILE)
        if not jwt:
            raise ProvenanceVerificationError("Unable to read Kubernetes service account token for Vault auth")
        response = send_request(
            f"auth/{VAULT_KUBERNETES_AUTH_MOUNT}/login",
            {"role": VAULT_KUBERNETES_ROLE, "jwt": jwt},
            token="",
        )
        token = str(((response.get("auth", {}) or {}).get("client_token", "")) or "").strip()
        if not token:
            raise ProvenanceVerificationError("Vault Kubernetes auth did not return a client token")
        return token

    raise ProvenanceVerificationError(f"Unsupported VAULT_AUTH_METHOD '{VAULT_AUTH_METHOD}'")


def compute_transit_hmac(payload: str) -> str:
    if not VAULT_TRANSIT_KEY:
        raise ProvenanceVerificationError("VAULT_TRANSIT_KEY must be configured for vault-transit verification")

    response = send_request(
        f"{VAULT_TRANSIT_MOUNT}/hmac/{VAULT_TRANSIT_KEY}/{VAULT_TRANSIT_ALGORITHM}",
        {"input": base64.b64encode(payload.encode("utf-8")).decode("utf-8")},
        token=get_vault_token(),
    )
    digest = str(((response.get("data", {}) or {}).get("hmac", "")) or "").strip()
    if not digest:
        raise ProvenanceVerificationError("Vault Transit response did not contain data.hmac")
    return digest
