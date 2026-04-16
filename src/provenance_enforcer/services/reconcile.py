from __future__ import annotations

import logging
from typing import Any

import kopf
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from ..config import GROUP, PLURAL, SCA_PLURAL
from ..errors import ProvenanceVerificationError
from ..k8s.policies import policy_targets_zta
from ..k8s.status import set_failure_status
from .evaluation import evaluate_application, format_context, log_context


logger = logging.getLogger(__name__)


def load_kubernetes_config() -> None:
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")
    except Exception:
        config.load_kube_config()
        logger.info("Loaded local kubeconfig")


def reconcile_application(custom: client.CustomObjectsApi, namespace: str, name: str, body: dict[str, Any]) -> None:
    image = str(((body.get("spec", {}) or {}).get("image", "")) or "").strip()
    try:
        evaluate_application(custom, body)
    except ProvenanceVerificationError as exc:
        logger.warning(
            "Provenance verification failed %s",
            format_context(**log_context(namespace=namespace, name=name, image=image), error=str(exc)),
        )
        set_failure_status(custom, namespace, name, PLURAL, str(exc))
    except ApiException as exc:
        reason = f"Kubernetes API error while reconciling provenance: status={exc.status} reason={exc.reason}"
        logger.exception("%s %s", reason, format_context(**log_context(namespace=namespace, name=name, image=image)))
        set_failure_status(custom, namespace, name, PLURAL, reason)
        raise kopf.TemporaryError(reason, delay=30) from exc
    except Exception as exc:
        reason = f"Unexpected provenance verification error: {type(exc).__name__}: {exc}"
        logger.exception("%s %s", reason, format_context(**log_context(namespace=namespace, name=name, image=image)))
        set_failure_status(custom, namespace, name, PLURAL, reason)
        raise kopf.TemporaryError(reason, delay=30) from exc


def reconcile_policy_change(custom: client.CustomObjectsApi, body: dict[str, Any], version: str = "v1") -> None:
    policy_name = str(((body.get("metadata", {}) or {}).get("name", "")) or "")
    logger.info("Reconciling policy change %s", format_context(policy=policy_name))

    ztas = custom.list_cluster_custom_object(group=GROUP, version=version, plural=PLURAL).get("items", []) or []
    for item in ztas:
        metadata = item.get("metadata", {}) or {}
        namespace = str(metadata.get("namespace", ""))
        name = str(metadata.get("name", ""))
        labels = metadata.get("labels", {}) or {}
        image = str((((item.get("spec", {}) or {}).get("image", "")) or "")).strip()

        if not policy_targets_zta(body, namespace=namespace, app_name=name, labels=labels, app_spec=(item.get("spec", {}) or {})):
            continue

        try:
            evaluate_application(custom, item)
        except ProvenanceVerificationError as exc:
            logger.warning(
                "Provenance verification failed after policy change %s",
                format_context(
                    **log_context(namespace=namespace, name=name, image=image),
                    policy=policy_name,
                    error=str(exc),
                ),
            )
            set_failure_status(custom, namespace, name, PLURAL, str(exc))
        except ApiException as exc:
            reason = f"Kubernetes API error during policy-triggered reconcile: status={exc.status} reason={exc.reason}"
            logger.exception(
                "%s %s",
                reason,
                format_context(**log_context(namespace=namespace, name=name, image=image), policy=policy_name),
            )
            set_failure_status(custom, namespace, name, PLURAL, reason)
            raise kopf.TemporaryError(reason, delay=30) from exc
        except Exception as exc:
            reason = f"Unexpected error during policy-triggered reconcile: {type(exc).__name__}: {exc}"
            logger.exception(
                "%s %s",
                reason,
                format_context(**log_context(namespace=namespace, name=name, image=image), policy=policy_name),
            )
            set_failure_status(custom, namespace, name, PLURAL, reason)
            raise kopf.TemporaryError(reason, delay=30) from exc