"""Refresh persisted TLS findings to the current classification rules."""

from app.classification.migration import MigrationAdvisor
from app.classification.severity import SeverityEngine


def refresh_tls_findings(scan, findings):
    """Correct historical TLS finding fields when producing a current result."""
    context = dict((scan or {}).get("business_context") or {})
    if ((scan or {}).get("repository_source_type") == "https_endpoint"
            or (scan or {}).get("tls_target_url")):
        context["external_exposure"] = "Public"

    severity = SeverityEngine()
    advisor = MigrationAdvisor()
    refreshed = []
    for original in findings or []:
        finding = dict(original)
        if finding.get("evidence_type") == "tls_probe":
            full_evidence = finding.get("classification_reason")
            current_evidence = finding.get("evidence_snippet") or ""
            if isinstance(full_evidence, str) and len(full_evidence) > len(current_evidence):
                # Older records capped this field at 240 characters. The
                # classification reason retained the complete probe evidence.
                finding["evidence_snippet"] = full_evidence
            rule = finding.get("detection_rule_id")
            if rule == "TLS12-NO-PQC":
                finding.update({
                    "key_size": None,
                    "crypto_operation": "key_exchange",
                    "cryptographic_purpose": "key_establishment",
                    "quantum_classification": "Quantum Vulnerable",
                    "risk_horizon": "harvest_now_decrypt_later",
                })
            elif rule == "TLS-CERTIFICATE-ALGORITHM":
                finding.update({
                    "quantum_classification": "Quantum Vulnerable",
                    "risk_horizon": "future_live_authentication_forgery",
                })
            elif rule == "TLS-HYBRID-GROUP":
                finding.update({
                    "key_size": None,
                    "quantum_classification": "Quantum Resistant Under Current Knowledge",
                    "risk_horizon": "post_quantum_hybrid_key_establishment",
                })
            elif rule == "TLS13-GROUP-CAPABILITY":
                finding.update({
                    "key_size": None,
                    "quantum_classification": "Unknown / Needs Review",
                    "risk_horizon": "unconfirmed_key_establishment_capability",
                })
            finding.update(severity.score(finding, context))
            finding["migration_recommendation"] = advisor.recommend(finding)
        refreshed.append(finding)
    return refreshed
