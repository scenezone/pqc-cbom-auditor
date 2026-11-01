"""Standalone executive summary builder for the PQC audit report."""

from app.classification.migration import MigrationAdvisor


class ExecutiveSummaryBuilder:
    """Produces plain-language executive summary content from scan findings."""

    def __init__(self) -> None:
        self.advisor = MigrationAdvisor()

    def build(self, scan: dict, findings: list[dict]) -> dict:
        counts = self._counts(findings)
        return {
            "what_was_scanned": self._what_was_scanned(scan),
            "risk_overview": self._risk_overview(counts, len(findings), scan),
            "what_to_fix_first": self._what_to_fix_first(findings),
            "limitations": self._limitations(scan),
            "counts": counts,
        }

    def _counts(self, findings: list[dict]) -> dict:
        counts = {
            "Quantum Vulnerable": 0,
            "Quantum Resistant Under Current Knowledge": 0,
            "Unknown / Needs Review": 0,
        }
        for f in findings:
            qc = f.get("quantum_classification", "Unknown / Needs Review")
            counts[qc] = counts.get(qc, 0) + 1
        return counts

    def _what_was_scanned(self, scan: dict) -> str:
        if scan.get("repository_source_type") == "https_endpoint":
            tls = scan.get("tls_assessment") or {}
            return f"Live TLS assessment of {tls.get('target', scan.get('tls_target_url', 'the requested endpoint'))} (status: {tls.get('status', 'inconclusive')})."
        summary = (
            f"Static analysis of authorized source code from '{scan['repository_name']}' "
            f"({scan.get('scanned_files', 0)} files scanned, {scan.get('skipped_files', 0)} skipped)."
        )
        if scan.get("tls_target_url"):
            tls = scan.get("tls_assessment") or {}
            summary += f" TLS endpoint assessment requested for {tls.get('target', scan['tls_target_url'])} (status: {tls.get('status', 'inconclusive')})."
        return summary

    def _risk_overview(self, counts: dict, total: int, scan: dict) -> str:
        if total == 0:
            if scan.get("repository_source_type") == "https_endpoint":
                return "No TLS risk findings were produced for this endpoint assessment. Review the protocol and probe statuses for inconclusive or rejected checks."
            return "No supported cryptographic usage was identified within the scanned scope."
        return (
            f"{total} cryptographic and TLS assessment findings were identified: "
            f"{counts['Quantum Vulnerable']} quantum-vulnerable, "
            f"{counts['Quantum Resistant Under Current Knowledge']} quantum-resistant, "
            f"{counts['Unknown / Needs Review']} requiring manual review."
        )

    def _what_to_fix_first(self, findings: list[dict]) -> list[str]:
        top = sorted(findings, key=lambda f: f["severity_score"], reverse=True)[:5]
        return [
            f"{f['algorithm']} at {f['file_path']}:{f['start_line']} - {self.advisor.recommend(f)}"
            for f in top
        ]

    def _limitations(self, scan: dict) -> str:
        tls = scan.get("tls_assessment") or {}
        if scan.get("repository_source_type") == "https_endpoint":
            return "This assessment probes TLS handshakes and inspects the presented certificate. It does not scan source code or validate the certificate trust chain. Results reflect the scanner's OpenSSL client and the endpoint's response at assessment time."
        tls_note = " The requested TLS endpoint was actively probed, and the presented certificate was inspected without validating its trust chain." if tls.get("status") == "completed" else " It does not analyze runtime traffic or endpoint certificates unless an optional TLS target is supplied."
        return (
            "Static analysis identifies evidence only within the supported scan scope. "
            "It does not analyze compiled binaries, managed cloud cryptography, HSMs, or all third-party dependencies." + tls_note
        )
