# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **RFC 6962 Merkle verification cu negociere de versiune** (`security/merkle.py`):
  voucherele cu `merkle_tree.version >= 2` sau `algorithm == "rfc6962-sha256"`
  folosesc hashing domain-separated (`0x00` frunze / `0x01` noduri); voucherele
  legacy rămân pe SHA-256 plain. Statusul expune câmpurile noi
  `status.provenance.merkle.merkleVersion` și `merkleAlgorithm`.
- Izolare per-operator a stocării kopf progress/diffbase (evită coliziuni cu
  zta-operator care urmărește același CRD).

### Changed
- `VBBI_STATEMENT_TYPES` (CSV, plural) înlocuiește `VBBI_STATEMENT_TYPE`:
  se acceptă **atât** `https://in-toto.io/Statement/v1`, **cât și** `v0.1`.