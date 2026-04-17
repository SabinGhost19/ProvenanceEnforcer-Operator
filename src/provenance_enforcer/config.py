import os


def _csv_env(name: str, default: str) -> tuple[str, ...]:
	value = os.getenv(name, default)
	items = tuple(part.strip() for part in value.split(",") if part.strip())
	return items or tuple(part.strip() for part in default.split(",") if part.strip())

GROUP = "devsecops.licenta.ro"
VERSION = "v1"
PLURAL = "zerotrustapplications"
SCA_PLURAL = "supplychainattestations"

DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"
COSIGN_BIN = os.getenv("COSIGN_BIN", "cosign")
VERIFY_TIMEOUT_SECONDS = int(os.getenv("VERIFY_TIMEOUT_SECONDS", "120"))
VBBI_ATTESTATION_TYPE = os.getenv("VBBI_ATTESTATION_TYPE", "https://devsecops.licenta.ro/VBBI/v1")
VBBI_STATEMENT_TYPES = _csv_env(
	"VBBI_STATEMENT_TYPES",
	"https://in-toto.io/Statement/v1,https://in-toto.io/Statement/v0.1",
)
VBBI_STATEMENT_TYPE = VBBI_STATEMENT_TYPES[0]
VBBI_HMAC_MODE = os.getenv("VBBI_HMAC_MODE", "shared-secret")
VBBI_HMAC_KEY = os.getenv("VBBI_HMAC_KEY", "dev-only-vbbi-key")
VAULT_ADDR = os.getenv("VAULT_ADDR", "")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE", "")
VAULT_AUTH_METHOD = os.getenv("VAULT_AUTH_METHOD", "token")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "")
VAULT_TOKEN_FILE = os.getenv("VAULT_TOKEN_FILE", "")
VAULT_KUBERNETES_AUTH_MOUNT = os.getenv("VAULT_KUBERNETES_AUTH_MOUNT", "kubernetes")
VAULT_KUBERNETES_ROLE = os.getenv("VAULT_KUBERNETES_ROLE", "")
VAULT_KUBERNETES_JWT_FILE = os.getenv(
	"VAULT_KUBERNETES_JWT_FILE",
	"/var/run/secrets/kubernetes.io/serviceaccount/token",
)
VAULT_TRANSIT_MOUNT = os.getenv("VAULT_TRANSIT_MOUNT", "transit")
VAULT_TRANSIT_KEY = os.getenv("VAULT_TRANSIT_KEY", "")
VAULT_TRANSIT_ALGORITHM = os.getenv("VAULT_TRANSIT_ALGORITHM", "sha2-256")

TRUST_UNTRUSTED = "Untrusted"
TRUST_VERIFIED = "Verified"
TRUST_UNTRUSTED_PROVENANCE = "UntrustedProvenance"