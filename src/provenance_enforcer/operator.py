from __future__ import annotations

from typing import Any

import kopf
from kubernetes import client
from .config import GROUP, PLURAL, SCA_PLURAL
from .services.reconcile import (
    load_kubernetes_config,
    reconcile_application,
    reconcile_policy_change as reconcile_policy_change_service,
)


@kopf.on.startup()
def startup_fn(**_: Any) -> None:
    # load the kubernetes client once on startup.
    load_kubernetes_config()


@kopf.on.create(GROUP, "v1", PLURAL)
@kopf.on.field(GROUP, "v1", PLURAL, field="spec")
def reconcile_provenance(spec: dict, name: str, namespace: str, body: dict, **_: Any) -> None:
    # keep the entrypoint thin and forward to the service layer.
    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    reconcile_application(custom, namespace, name, body)


@kopf.on.create(GROUP, "v1", SCA_PLURAL)
@kopf.on.field(GROUP, "v1", SCA_PLURAL, field="spec")
def reconcile_policy_change(body: dict, **_: Any) -> None:
    # reevaluate applications when the policy changes.
    api_client = client.ApiClient()
    custom = client.CustomObjectsApi(api_client)
    reconcile_policy_change_service(custom, body)