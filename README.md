# Provenance Enforcer

Operator Kubernetes separat pentru Voucher-Based Build Integrity (VBBI).

Structura curenta a codului:

- `src/provenance_enforcer/operator.py` - entrypoint Kopf foarte subtire
- `src/provenance_enforcer/services/` - orchestration pentru reconcile si evaluarea completa a unui ZTA
- `src/provenance_enforcer/attestations/` - fetch, parse si policy validation pentru atestari
- `src/provenance_enforcer/security/` - HMAC, Merkle, hash helpers si integrarea Vault
- `src/provenance_enforcer/k8s/` - patch-uri de status si matching pentru politici Kubernetes
- `src/provenance_enforcer/errors.py` - erorile comune ale motorului de provenienta
- `src/provenance_enforcer/crypto.py` si `src/provenance_enforcer/voucher.py` - fatade compatibile pentru importurile existente

Responsabilitati curente:

- urmareste resursele `ZeroTrustApplication`
- gaseste politica `SupplyChainAttestation` aplicabila
- valideaza atestarea VBBI din OCI registry cu `cosign verify-attestation`
- valideaza structural voucherul VBBI si statement-ul in-toto
- verifica lantul HMAC pentru pasii din voucher, fie cu secret partajat, fie prin Vault Transit
- verifica radacina Merkle si corespondenta dintre frunze si pasii HMAC
- scrie verdictul in `status.trustLevel`

Variabile de mediu importante:

- `COSIGN_BIN` - calea catre binarul cosign
- `VERIFY_TIMEOUT_SECONDS` - timeout pentru verificarea atestarii
- `VBBI_ATTESTATION_TYPE` - tipul de atestare VBBI
- `VBBI_STATEMENT_TYPE` - tipul de statement in-toto acceptat
- `VBBI_HMAC_MODE` - `shared-secret` sau `vault-transit`
- `VBBI_HMAC_KEY` - cheia folosita in modul `shared-secret`
- `VAULT_ADDR`, `VAULT_TRANSIT_MOUNT`, `VAULT_TRANSIT_KEY`, `VAULT_TRANSIT_ALGORITHM` - configurare Vault Transit
- `VAULT_AUTH_METHOD` - `token` sau `kubernetes`
- `VAULT_TOKEN` sau `VAULT_TOKEN_FILE` - autentificare token catre Vault
- `VAULT_KUBERNETES_AUTH_MOUNT`, `VAULT_KUBERNETES_ROLE`, `VAULT_KUBERNETES_JWT_FILE` - autentificare Kubernetes catre Vault

Manifesturi incluse:

- `deploy/rbac/` pentru ServiceAccount, ClusterRole si ClusterRoleBinding
- `deploy/operator/deployment.yaml` pentru rulare directa
- `deploy/operator/hmac-secret.example.yaml` pentru modul `shared-secret`
- `deploy/operator/vault-token-secret.example.yaml` pentru modul `vault-transit` cu token static
- `helm/provenance-enforcer/` pentru instalare prin Helm

Configurare Helm pentru `shared-secret`:

- `hmac.mode: shared-secret` activeaza verificarea locala cu cheia partajata
- `hmacSecret.create: true` cere chartului sa creeze Secret-ul
- `hmacSecret.name` permite folosirea unui nume explicit pentru Secret
- `hmacSecret.keyField` permite schimbarea numelui campului din Secret
- `hmacSecret.value` seteaza valoarea efectiva a cheii daca Secret-ul este creat de chart
- `hmacSecret.annotations` si `hmacSecret.labels` permit metadata suplimentara pe Secret

Exemplu Helm pentru `shared-secret`:

```yaml
hmac:
	mode: shared-secret

hmacSecret:
	create: true
	name: provenance-enforcer-hmac
	keyField: key
	value: super-secret-shared-key
	annotations: {}
	labels: {}
```

Pentru un Secret deja existent in cluster:

```yaml
hmac:
	mode: shared-secret

hmacSecret:
	create: false
	name: existing-provenance-hmac
	keyField: key
```

Cum se citeste fluxul principal:

- `operator.py` primeste evenimentul Kopf si il deleaga catre `services/reconcile.py`
- `services/evaluation.py` identifica politica aplicabila, descarca atestarea si orchestreaza verificarea
- `attestations/` valideaza payload-ul in-toto si regulile de policy
- `security/` valideaza lantul HMAC si arborele Merkle
- `k8s/status.py` scrie verdictul final si motivele de eroare in `status`

Schema voucherului VBBI verificata:

- `statement._type` trebuie sa fie `https://in-toto.io/Statement/v1`
- `predicate.build_context` trebuie sa contina `repository`, `workflow`, `run_id`, `event`, `issuer_oidc`, `slsa_level`, `image` si `commit_sha`
- `predicate.hmac_chain` trebuie sa contina `provider`, `algorithm`, `h0_seed`, pasi ordonati, pozitii secventiale si `final_voucher`
- `predicate.merkle_tree` trebuie sa contina toate frunzele, in aceeasi ordine ca `hmac_chain.steps`, si `root_hash`

Exemplu Helm pentru Vault Transit:

```yaml
hmac:
	mode: vault-transit

vault:
	enabled: true
	addr: https://vault.devsecops.svc:8200
	authMethod: kubernetes
	kubernetesRole: provenance-enforcer
	transitMount: transit
	transitKey: vbbi-hmac
	transitAlgorithm: sha2-256
```

Rulare locala:

```bash
pip install -r requirements.txt
PYTHONPATH=src kopf run --all-namespaces -m provenance_enforcer.operator
```