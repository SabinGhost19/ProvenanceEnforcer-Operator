from __future__ import annotations

from .parser import validate_vbbi_structure
from ..errors import ProvenanceVerificationError


def extract_digest(image: str) -> str:
    if "@sha256:" not in image:
        return ""
    return image.split("@sha256:", 1)[1].strip().lower()


def validate_voucher_policy(
    voucher: dict,
    image: str,
    min_slsa_level: int,
    trusted_repositories: list[str],
) -> dict:
    predicate = voucher.get("predicate", {}) or {}
    subject = voucher.get("subject", []) or []
    structure_info = validate_vbbi_structure(voucher)
    build_context = predicate.get("build_context", {}) or {}
    repository = str(build_context.get("repository", "")).strip()

    if trusted_repositories and repository not in trusted_repositories:
        raise ProvenanceVerificationError(f"Voucher repository '{repository}' is not allowed by policy")

    build_context_image = str(build_context.get("image", "")).strip()
    if build_context_image and build_context_image != image:
        raise ProvenanceVerificationError("Voucher build_context.image does not match the ZeroTrustApplication image")

    expected_digest = extract_digest(image)
    subject_matches = False
    for item in subject:
        if not isinstance(item, dict):
            continue
        digest = ((item.get("digest", {}) or {}).get("sha256", "") or "").strip().lower()
        if expected_digest and digest == expected_digest:
            subject_matches = True
            break

    if expected_digest and subject and not subject_matches:
        raise ProvenanceVerificationError("Voucher subject digest does not match the ZeroTrustApplication image digest")

    slsa_level = int(build_context.get("slsa_level", predicate.get("slsa_level", 0)) or 0)
    if slsa_level < min_slsa_level:
        raise ProvenanceVerificationError(
            f"Voucher SLSA level {slsa_level} is below required minimum {min_slsa_level}"
        )

    return {
        "statementType": structure_info.get("statementType"),
        "stepCount": structure_info.get("stepCount"),
        "repository": repository,
        "slsaLevel": slsa_level,
        "subject": subject,
        "subjectVerified": subject_matches if expected_digest else False,
        "image": image,
    }
