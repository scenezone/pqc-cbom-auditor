import html
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.classification.tls_findings import refresh_tls_findings
from app.classification.migration import MigrationAdvisor
from app.reporting.executive_summary import ExecutiveSummaryBuilder


NAVY = colors.HexColor("#10243A")
BLUE = colors.HexColor("#2457A6")
TEAL = colors.HexColor("#0F766E")
INK = colors.HexColor("#1F2937")
MUTED = colors.HexColor("#64748B")
LINE = colors.HexColor("#D9E2EC")
PALE = colors.HexColor("#F3F6FA")
WHITE = colors.white


class ExecutivePDFGenerator:
    """Build a complete, reader-friendly PDF from scan and TLS evidence."""

    def __init__(self):
        self.summary_builder = ExecutiveSummaryBuilder()
        self.advisor = MigrationAdvisor()
        self.styles = self._styles()

    def generate(self, scan, findings):
        scan = scan or {}
        findings = refresh_tls_findings(scan, findings)
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            rightMargin=1.65 * cm,
            leftMargin=1.65 * cm,
            topMargin=2.15 * cm,
            bottomMargin=1.65 * cm,
            title="PQC Exposure & CBOM Audit Report",
            author="PQC CBOM Auditor",
            subject="Cryptographic inventory, post-quantum exposure, and migration guidance",
        )
        self.scan_id = self._value(scan.get("scan_id"), "Not available")
        summary = self.summary_builder.build(scan, findings)
        story = []
        story.extend(self._cover(scan, findings))
        story.append(PageBreak())
        story.extend(self._executive_overview(scan, findings, summary))

        tls = scan.get("tls_assessment") or {}
        if tls:
            story.append(PageBreak())
            story.extend(self._tls_section(tls, findings))

        story.append(PageBreak())
        story.extend(self._findings_section(findings))
        story.append(PageBreak())
        story.extend(self._roadmap(findings))
        story.extend(self._methodology(scan, summary))

        doc.build(story, onFirstPage=self._draw_page, onLaterPages=self._draw_page)
        return buf.getvalue()

    def _styles(self):
        base = getSampleStyleSheet()
        return {
            "cover_title": ParagraphStyle(
                "CoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
                fontSize=27, leading=32, alignment=TA_LEFT, textColor=NAVY,
                spaceAfter=12,
            ),
            "cover_subtitle": ParagraphStyle(
                "CoverSubtitle", parent=base["Normal"], fontSize=12, leading=17,
                textColor=MUTED, spaceAfter=8,
            ),
            "h1": ParagraphStyle(
                "SectionHeading", parent=base["Heading1"], fontName="Helvetica-Bold",
                fontSize=17, leading=21, textColor=NAVY, spaceBefore=2, spaceAfter=10,
                keepWithNext=True,
            ),
            "h2": ParagraphStyle(
                "Subheading", parent=base["Heading2"], fontName="Helvetica-Bold",
                fontSize=11.5, leading=15, textColor=BLUE, spaceBefore=10,
                spaceAfter=5, keepWithNext=True,
            ),
            "body": ParagraphStyle(
                "ReportBody", parent=base["BodyText"], fontName="Helvetica",
                fontSize=9, leading=13, textColor=INK, spaceAfter=5,
            ),
            "small": ParagraphStyle(
                "ReportSmall", parent=base["BodyText"], fontSize=7.5,
                leading=10, textColor=INK,
            ),
            "muted": ParagraphStyle(
                "ReportMuted", parent=base["BodyText"], fontSize=8,
                leading=11, textColor=MUTED,
            ),
            "table_head": ParagraphStyle(
                "TableHeader", parent=base["BodyText"], fontName="Helvetica-Bold",
                fontSize=7.3, leading=9, textColor=WHITE,
            ),
            "label": ParagraphStyle(
                "MetricLabel", parent=base["BodyText"], fontName="Helvetica-Bold",
                fontSize=7.2, leading=9, textColor=MUTED, alignment=TA_CENTER,
            ),
            "metric": ParagraphStyle(
                "MetricValue", parent=base["BodyText"], fontName="Helvetica-Bold",
                fontSize=17, leading=20, textColor=NAVY, alignment=TA_CENTER,
            ),
            "finding_title": ParagraphStyle(
                "FindingTitle", parent=base["Heading3"], fontName="Helvetica-Bold",
                fontSize=10.5, leading=14, textColor=NAVY, spaceAfter=5,
                keepWithNext=True,
            ),
            "code": ParagraphStyle(
                "Evidence", parent=base["Code"], fontName="Courier",
                fontSize=7.5, leading=10, textColor=INK, backColor=PALE,
                borderColor=LINE, borderWidth=0.4, borderPadding=6,
                wordWrap="CJK",
            ),
        }

    @staticmethod
    def _value(value, fallback="Not provided"):
        if value is None or value == "":
            return fallback
        return str(value)

    def _p(self, value, style="body"):
        return Paragraph(html.escape(self._value(value), quote=True).replace("\n", "<br/>"), self.styles[style])

    def _rich(self, text, style="body"):
        return Paragraph(text, self.styles[style])

    def _cover(self, scan, findings):
        source_type = scan.get("repository_source_type", "unknown")
        tls = scan.get("tls_assessment") or {}
        if source_type == "https_endpoint":
            subject = tls.get("target") or scan.get("tls_target_url") or scan.get("repository_name")
            assessment_type = "Live TLS endpoint assessment"
        elif tls:
            subject = scan.get("repository_name", "Repository assessment")
            assessment_type = "Source analysis and TLS endpoint assessment"
        else:
            subject = scan.get("repository_name", "Repository assessment")
            assessment_type = "Static cryptographic source analysis"

        now = datetime.now(timezone.utc).strftime("%d %B %Y")
        context = scan.get("business_context") or {}
        if scan.get("repository_source_type") == "https_endpoint" or scan.get("tls_target_url"):
            context = {**context, "external_exposure": "Public"}
        title = [Spacer(1, 2.1 * cm), self._rich("PQC Exposure &amp;<br/>Cryptographic Bill of Materials", "cover_title")]
        title.append(self._p("Post-quantum readiness assessment", "cover_subtitle"))
        title.append(Spacer(1, 0.9 * cm))
        title.append(self._rule())
        title.append(Spacer(1, 0.7 * cm))
        title.append(self._p("ASSESSMENT SUBJECT", "label"))
        title.append(self._p(subject, "h1"))
        title.append(self._p(assessment_type, "cover_subtitle"))
        title.extend([Spacer(1, 0.15 * cm), self._p("In plain language", "h2")])
        summary_box = Table([[self._p(self._plain_language_summary(scan, findings), "body")]],
                            colWidths=[17.4 * cm], hAlign="LEFT")
        summary_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PALE),
            ("BOX", (0, 0), (-1, -1), 0.6, LINE),
            ("LINEBEFORE", (0, 0), (0, -1), 2, TEAL),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        title.append(summary_box)
        title.append(Spacer(1, 0.7 * cm))
        details = [
            [self._p("REPORT DATE", "label"), self._p("SCAN STATUS", "label")],
            [self._p(now, "body"), self._p(scan.get("scan_status", "Report generated"), "body")],
            [self._p("FINDINGS INCLUDED", "label"), self._p("BUSINESS CRITICALITY", "label")],
            [self._p(str(len(findings)), "body"), self._p(context.get("business_criticality", "Not provided"), "body")],
            [self._p("DATA SENSITIVITY", "label"), self._p("SCAN REFERENCE", "label")],
            [self._p(context.get("data_sensitivity", "Not provided"), "body"), self._p(self.scan_id, "small")],
        ]
        table = Table(details, colWidths=[8.7 * cm, 8.7 * cm], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PALE),
            ("BOX", (0, 0), (-1, -1), 0.7, LINE),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        title.append(table)
        title.extend([Spacer(1, 1.1 * cm), self._p("CONFIDENTIAL • Prepared for authorized assessment recipients", "muted")])
        return title

    def _executive_overview(self, scan, findings, summary):
        out = [self._p("Executive overview", "h1"), self._p(summary["risk_overview"])]
        counts = self._classification_counts(findings)
        severities = self._severity_counts(findings)
        metrics = [
            ("TOTAL FINDINGS", len(findings)),
            ("QUANTUM VULNERABLE", counts["Quantum Vulnerable"]),
            ("NEEDS REVIEW", counts["Unknown / Needs Review"]),
            ("HIGH / CRITICAL", severities["High"] + severities["Critical"]),
        ]
        cards = [[self._p(label, "label") for label, _ in metrics],
                 [self._p(str(value), "metric") for _, value in metrics]]
        card_table = Table(cards, colWidths=[4.35 * cm] * 4, hAlign="LEFT")
        card_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PALE),
            ("BOX", (0, 0), (-1, -1), 0.6, LINE),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        out.extend([Spacer(1, 0.25 * cm), card_table, Spacer(1, 0.3 * cm)])
        out.extend([self._p("Assessment scope", "h2"), self._p(summary["what_was_scanned"]),
                    self._p(self._methodology_text(scan), "small")])

        context = scan.get("business_context") or {}
        if scan.get("repository_source_type") == "https_endpoint" or scan.get("tls_target_url"):
            context = {**context, "external_exposure": "Public"}
        scan_rows = [
            ("Assessment status", scan.get("scan_status", "Not provided")),
            ("Source type", scan.get("repository_source_type", "Not provided")),
            ("Files scanned / skipped", f"{scan.get('scanned_files', 0)} / {scan.get('skipped_files', 0)}"),
            ("Business criticality", context.get("business_criticality", "Not provided")),
            ("Data sensitivity", context.get("data_sensitivity", "Not provided")),
            ("Data retention horizon", context.get("data_retention_horizon", "Not provided")),
            ("External exposure", context.get("external_exposure", "Not provided")),
        ]
        out.extend([self._p("Assessment details", "h2"), self._key_value_table(scan_rows)])
        out.extend([Spacer(1, 0.25 * cm), self._p("Finding distribution", "h2"),
                    self._distribution_table(counts, severities)])

        positive = [f for f in findings if self._is_positive_finding(f)]
        if positive:
            out.append(self._p("Positive security results", "h2"))
            for finding in positive:
                algorithm = html.escape(self._value(finding.get("algorithm"), "Post-quantum hybrid key exchange"))
                evidence = html.escape(self._value(finding.get("evidence_snippet"), "A TLS 1.3 hybrid-group handshake was confirmed."))
                out.append(self._rich(f"<b>{algorithm}</b> — {evidence}", "body"))

        risk_findings = [f for f in findings if not self._is_positive_finding(f)]
        prioritized = sorted(risk_findings, key=self._finding_sort_key, reverse=True)[:5]
        out.append(self._p("Priority actions", "h2"))
        if prioritized:
            for idx, finding in enumerate(prioritized, 1):
                algorithm = self._value(finding.get("algorithm"), "Unknown algorithm")
                location = self._location(finding)
                rec = self.advisor.recommend(finding)
                out.append(self._rich(
                    f"<b>{idx}. {html.escape(algorithm)}</b> — {html.escape(location)}<br/>"
                    f"{html.escape(rec)}", "body"))
        else:
            out.append(self._p("No unresolved priority actions were identified in the supplied assessment data."))
        return out

    def _tls_section(self, tls, findings=None):
        out = [self._p("Live TLS endpoint assessment", "h1")]
        out.append(self._key_value_table([
            ("Target", tls.get("target", "Not provided")),
            ("Assessment status", tls.get("status", "Not provided")),
            ("Probe client", (tls.get("probe_client") or {}).get("name", "OpenSSL s_client")),
            ("Probe client version", (tls.get("probe_client") or {}).get("version", "Not recorded")),
            ("Hybrid groups standard", "RFC 10024 defines X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 for TLS 1.3."),
        ]))
        if tls.get("error"):
            out.extend([Spacer(1, 0.2 * cm), self._p(f"Assessment note: {tls['error']}")])

        protocols = tls.get("protocols") or []
        if protocols:
            out.append(self._p("Protocol and negotiated cipher results", "h2"))
            rows = [[self._p(v, "table_head") for v in ("Protocol", "Probe", "PQC status", "Cipher suite", "Cipher ID", "Negotiated group", "Attempts / note")]]
            for protocol in protocols:
                cipher = protocol.get("cipher_suite") or {}
                attempts_note = str(protocol.get("attempts", "—"))
                if protocol.get("reason"):
                    attempts_note += f" · {protocol['reason']}"
                rows.append([self._p(protocol.get("version"), "small"),
                             self._p(protocol.get("status"), "small"),
                             self._p(protocol.get("pqc_status"), "small"),
                             self._p(cipher.get("name", "Not observed"), "small"),
                             self._p(cipher.get("iana_id", "Unknown"), "small"),
                             self._p(protocol.get("negotiated_group", "Not reported"), "small"),
                             self._p(attempts_note, "small")])
            out.append(self._table(rows, [1.55*cm, 1.35*cm, 2.2*cm, 3.4*cm, 1.7*cm, 2.7*cm, 4.2*cm]))
            for protocol in protocols:
                cipher = protocol.get("cipher_suite") or {}
                algorithms = cipher.get("algorithms") or []
                if algorithms:
                    aes_levels = [f"{name}: NIST security level {level}" for name in algorithms
                                  if (level := self._aes_security_level(name)) is not None]
                    note = f"{protocol.get('version', 'TLS')} observed cipher components: {', '.join(algorithms)}."
                    if aes_levels:
                        note += " " + "; ".join(aes_levels) + "."
                    out.append(self._p(note, "small"))

        tls_findings = tls.get("findings") or []
        if tls_findings:
            out.append(self._p("TLS interpretation", "h2"))
            finding_by_rule = {f.get("detection_rule_id"): f for f in findings or [] if f.get("evidence_type") == "tls_probe"}
            for item in tls_findings:
                title = self._value(item.get("title"), "TLS finding")
                detail = self._value(item.get("detail"))
                severity = self._value(item.get("severity"), "Not rated")
                rule = self._tls_rule_for_title(title)
                scored_finding = finding_by_rule.get(rule)
                if scored_finding:
                    severity = (f"{scored_finding.get('severity_category', 'Not rated')} "
                                f"({scored_finding.get('severity_score', '—')}/100)")
                if "certificate" in title.lower():
                    title = "Endpoint certificate uses a quantum-vulnerable public key or signature"
                    if "future live-authentication" not in detail:
                        detail += " This is a future live-authentication forgery risk, not a harvest-now-decrypt-later decryption risk."
                elif "tls 1.2" in title.lower():
                    if "harvest-now-decrypt-later" not in detail:
                        detail += " Captured sessions using classical key exchange may face harvest-now-decrypt-later exposure."
                out.append(self._rich(f"<b>{html.escape(severity)} — {html.escape(title)}</b><br/>"
                                      f"{html.escape(detail)}", "body"))

        groups = tls.get("groups") or []
        if groups:
            out.append(self._p("Supported-group probes", "h2"))
            rows = [[self._p(v, "table_head") for v in ("Group", "Type", "Probe result", "Negotiated", "Classical", "PQC component", "Reason")]]
            for group in groups:
                rows.append([self._p(group.get("name"), "small"),
                             self._p(group.get("type"), "small"),
                             self._p(group.get("status"), "small"),
                             self._p(group.get("negotiated_group") or "No", "small"),
                             self._p(group.get("classical_algorithm") or "—", "small"),
                             self._p(self._group_component_label(group), "small"),
                             self._p(group.get("reason") or "—", "small")])
            out.append(self._table(rows, [3.2*cm, 1.5*cm, 2.1*cm, 2.4*cm, 2.3*cm, 2.5*cm, 3.6*cm]))
            out.append(self._p("A probe result of ‘inconclusive’ means endpoint support was not established by this run. It should not be interpreted as proof that the group is unsupported.", "muted"))

        certificates = tls.get("certificates") or ([tls["certificate"]] if tls.get("certificate") else [])
        certificates = [c for c in certificates if c and "parse_error" not in c]
        if certificates:
            out.append(self._p("Presented certificate details", "h2"))
            for cert in certificates:
                cert_rows = [
                    ("Protocol", cert.get("protocol", "Not provided")),
                    ("Subject", cert.get("subject", "Not provided")),
                    ("Issuer", cert.get("issuer", "Not provided")),
                    ("Serial number", cert.get("serial_number", "Not provided")),
                    ("Public key", f"{cert.get('public_key_algorithm', 'Unknown')} {cert.get('public_key_bits') or ''}".strip()),
                    ("Public-key quantum status", cert.get("public_key_quantum_status", "Not provided")),
                    ("Certificate signature", cert.get("signature_algorithm", "Not provided")),
                    ("Signature OID / hash", f"{cert.get('signature_oid', 'Unknown')} / {cert.get('signature_hash', 'Unknown')}"),
                    ("Signature quantum status", cert.get("signature_quantum_status", "Not provided")),
                    ("Validity", f"{cert.get('not_valid_before', 'Unknown')} to {cert.get('not_valid_after', 'Unknown')}"),
                    ("Trust validation", cert.get("validation_status", "Not performed")),
                    ("SHA-256 fingerprint", cert.get("fingerprint_sha256", "Not provided")),
                    ("Subject alternative names", ", ".join(cert.get("subject_alt_names") or []) or "Not provided"),
                ]
                out.append(self._key_value_table(cert_rows))
                out.append(Spacer(1, 0.15 * cm))
        return out

    def _findings_section(self, findings):
        out = [self._p("Complete findings register", "h1")]
        if not findings:
            out.append(self._p("No findings were supplied for this assessment."))
            return out
        out.append(self._p(f"This register contains all {len(findings)} finding(s) associated with the assessment. Findings are ordered by severity score, then classification.", "muted"))

        ordered = sorted(findings, key=self._finding_sort_key, reverse=True)
        rows = [[self._p(v, "table_head") for v in ("#", "Severity", "Algorithm / operation", "Location", "Quantum risk", "Confidence")]]
        for idx, finding in enumerate(ordered, 1):
            rows.append([self._p(str(idx), "small"),
                         self._p(f"{self._value(finding.get('severity_category'), 'Not rated')} ({finding.get('severity_score', '—')})", "small"),
                         self._rich(f"{html.escape(self._value(finding.get('algorithm'), 'Unknown'))}<br/>"
                                    f"{html.escape(self._value(finding.get('crypto_operation'), 'Not provided'))}", "small"),
                         self._p(self._location(finding), "small"),
                         self._p(self._classification_label(finding.get("quantum_classification")), "small"),
                         self._p(finding.get("detection_confidence", "Not provided"), "small")])
        out.append(self._table(rows, [0.7*cm, 2.4*cm, 3.5*cm, 4.4*cm, 4.1*cm, 2.0*cm]))
        out.append(Spacer(1, 0.35 * cm))
        out.append(self._p("Finding details and evidence", "h2"))

        for idx, finding in enumerate(ordered, 1):
            title = f"{idx}. {self._value(finding.get('algorithm'), 'Unknown algorithm')} — {self._value(finding.get('crypto_operation'), 'operation not provided')}"
            block = [self._p(title, "finding_title")]
            block.append(self._key_value_table([
                ("Finding ID", finding.get("finding_id", "Not provided")),
                ("Severity", f"{self._value(finding.get('severity_category'), 'Not rated')} ({finding.get('severity_score', '—')})"),
                ("Quantum classification", finding.get("quantum_classification", "Unknown / Needs Review")),
                ("Location", self._location(finding)),
                ("Algorithm variant / key size", f"{self._value(finding.get('algorithm_variant'), '—')} / {finding.get('key_size') or '—'}"),
                ("Risk timing", self._risk_timing_label(finding.get("risk_horizon") or (finding.get("score_explanation") or {}).get("risk_horizon"))),
                ("Purpose", finding.get("cryptographic_purpose", "Not provided")),
                ("Library / symbol", f"{finding.get('library_name', 'Not provided')} / {finding.get('symbol_name', finding.get('imported_symbol', 'Not provided'))}"),
                ("Language / evidence type", f"{finding.get('language', 'Not provided')} / {finding.get('evidence_type', 'Not provided')}"),
                ("Detection rule / confidence", f"{finding.get('detection_rule_id', 'Not provided')} / {finding.get('detection_confidence', 'Not provided')}"),
                ("Classification basis", finding.get("classification_reason", "Not provided")),
                ("Reference", finding.get("classification_reference", "Not provided")),
            ], compact=True))
            evidence = finding.get("evidence_snippet") or finding.get("detail")
            if evidence:
                block.extend([Spacer(1, 0.08 * cm), self._p("Evidence", "small"), self._p(evidence, "code")])
            recommendation = finding.get("migration_recommendation") or self.advisor.recommend(finding)
            block.extend([Spacer(1, 0.08 * cm), self._rich(f"<b>Recommended action:</b> {html.escape(str(recommendation))}", "body"), Spacer(1, 0.2 * cm)])
            out.extend(block)
        return out

    def _roadmap(self, findings):
        out = [self._p("Recommended migration roadmap", "h1")]
        vulnerable = [f for f in findings if f.get("quantum_classification") == "Quantum Vulnerable"]
        unknown = [f for f in findings if f.get("quantum_classification") == "Unknown / Needs Review"]
        resistant = [f for f in findings if f.get("quantum_classification") == "Quantum Resistant Under Current Knowledge"]
        actions = [
            ("1 · Establish ownership and exposure", "Assign owners to high-impact cryptographic systems. Inventory where vulnerable key establishment, signatures, and long-lived sensitive data are used."),
            ("2 · Prioritize migration design", "Prioritize quantum-vulnerable public-key operations and externally exposed services. Assess protocol, library, certificate, hardware, and interoperability dependencies before selecting a migration path."),
            ("3 · Validate post-quantum options", "Evaluate standardized ML-KEM for key establishment and ML-DSA or SLH-DSA for signatures where supported. For hybrid TLS, record confirmed endpoint capability separately from inconclusive probes."),
            ("4 · Track remediation and reassess", "Record owners, target dates, compatibility decisions, and residual risks. Repeat the source and endpoint assessment after material cryptographic or infrastructure changes."),
        ]
        for heading, description in actions:
            out.append(self._rich(f"<b>{html.escape(heading)}</b><br/>{html.escape(description)}", "body"))
        out.append(self._p("Assessment-specific priorities", "h2"))
        out.append(self._p(f"{len(vulnerable)} quantum-vulnerable finding(s), {len(unknown)} finding(s) requiring review, and {len(resistant)} finding(s) classified as quantum-resistant under current knowledge were recorded."))
        if unknown:
            out.append(self._p("Resolve inconclusive and unknown items by reviewing the underlying evidence, scanner capability, and endpoint behavior before concluding that an algorithm is present or absent."))
        return out

    def _methodology(self, scan, summary):
        out = [Spacer(1, 0.3 * cm), self._p("Methodology, interpretation, and limitations", "h1")]
        out.append(self._p(self._methodology_text(scan)))
        out.append(self._p(summary.get("limitations", "Assessment limitations were not provided.")))
        out.append(self._p("Quantum classification summarizes the expected impact of a sufficiently capable quantum computer on the identified primitive. It does not by itself establish exploitability, implementation correctness, or deployment-wide exposure. An inconclusive probe is not evidence of support or rejection.", "small"))
        out.append(self._p("NIST post-quantum standards referenced by this report include FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). Security levels shown for standardized algorithms describe the associated NIST parameter set; they are not a direct measure of endpoint risk.", "small"))
        return out

    def _methodology_text(self, scan):
        if scan.get("repository_source_type") == "https_endpoint":
            return ("The assessment performed live TLS 1.2 and TLS 1.3 handshakes, probed configured supported groups, recorded negotiated cipher suites, and inspected presented certificates. "
                    "It did not scan source code or validate the certificate trust chain. Results depend on scanner-side OpenSSL support and endpoint behavior at assessment time.")
        text = ("The assessment uses deterministic static analysis to identify supported cryptographic patterns in the selected source and configuration files. "
                "It does not execute repository code, inspect runtime traffic, analyze compiled binaries, or guarantee complete coverage.")
        if scan.get("tls_assessment") or scan.get("tls_target_url"):
            text += " The separately listed TLS endpoint assessment probes live protocol and group behavior and inspects the presented certificate without validating its trust chain."
        return text

    def _classification_counts(self, findings):
        result = {"Quantum Vulnerable": 0,
                  "Quantum Resistant Under Current Knowledge": 0,
                  "Unknown / Needs Review": 0}
        for finding in findings:
            name = finding.get("quantum_classification", "Unknown / Needs Review")
            result[name] = result.get(name, 0) + 1
        return result

    @staticmethod
    def _tls_rule_for_title(title):
        normalized = str(title).lower()
        if "certificate" in normalized:
            return "TLS-CERTIFICATE-ALGORITHM"
        if "tls 1.2" in normalized:
            return "TLS12-NO-PQC"
        if "hybrid" in normalized and "inconclusive" in normalized:
            return "TLS13-GROUP-CAPABILITY"
        if "hybrid" in normalized:
            return "TLS-HYBRID-GROUP"
        return None

    def _plain_language_summary(self, scan, findings):
        tls = scan.get("tls_assessment") or {}
        groups = tls.get("groups") or []
        confirmed = [g.get("name") for g in groups if g.get("type") == "hybrid" and g.get("status") == "confirmed"]
        protocols = {p.get("version"): p for p in tls.get("protocols") or []}
        tls12_supported = protocols.get("TLS 1.2", {}).get("status") == "confirmed"
        certificates = tls.get("certificates") or ([tls["certificate"]] if tls.get("certificate") else [])
        classical_certificate = any(
            cert and (cert.get("public_key_quantum_status") == "quantum_vulnerable"
                      or cert.get("signature_quantum_status") == "quantum_vulnerable")
            for cert in certificates
        )
        if confirmed:
            first = "The site can use post-quantum hybrid key exchange for TLS 1.3 sessions when clients negotiate those groups."
        elif tls.get("status") == "completed":
            first = "This scan did not confirm a post-quantum hybrid key exchange; an inconclusive probe does not prove the endpoint lacks support."
        else:
            counts = self._classification_counts(findings)
            first = (f"The assessment found {len(findings)} cryptographic item(s), including "
                     f"{counts.get('Quantum Vulnerable', 0)} quantum-vulnerable item(s).")
        if tls12_supported and classical_certificate:
            second = "Its TLS 1.2 fallback and current certificate still use classical cryptography; check whether older clients need TLS 1.2, and monitor CA and browser support for quantum-resistant website certificates."
        elif tls12_supported:
            second = "The endpoint also accepts TLS 1.2 without hybrid protection; check older-client needs before disabling it, or document the remaining traffic-confidentiality risk."
        elif classical_certificate:
            second = "The endpoint presents a classical certificate; monitor CA and browser roadmaps for a supported quantum-resistant website-authentication path."
        else:
            second = "Review the findings register for evidence, priorities, and the next migration actions."
        return f"{first} {second}"

    @staticmethod
    def _is_positive_finding(finding):
        return (finding.get("detection_rule_id") == "TLS-HYBRID-GROUP"
                and finding.get("quantum_classification") == "Quantum Resistant Under Current Knowledge")

    @staticmethod
    def _classification_label(value):
        return {
            "Quantum Vulnerable": "Vulnerable",
            "Quantum Resistant Under Current Knowledge": "Resistant",
            "Unknown / Needs Review": "Needs review",
        }.get(value, "Needs review")

    @staticmethod
    def _risk_timing_label(value):
        return {
            "harvest_now_decrypt_later": "Recorded traffic may face future decryption",
            "future_live_authentication_forgery": "Future live impersonation; not retroactive decryption",
            "post_quantum_hybrid_key_establishment": "Hybrid quantum-resistant key establishment",
            "unconfirmed_key_establishment_capability": "Endpoint capability not confirmed",
        }.get(value, "General quantum-exposure finding")

    def _severity_counts(self, findings):
        result = {name: 0 for name in ("Critical", "High", "Medium", "Low", "Informational")}
        for finding in findings:
            name = finding.get("severity_category", "Not rated")
            result[name] = result.get(name, 0) + 1
        return result

    def _distribution_table(self, classifications, severities):
        header = [self._p("CLASSIFICATION", "table_head"), self._p("COUNT", "table_head"),
                  self._p("SEVERITY", "table_head"), self._p("COUNT", "table_head")]
        rows = [header]
        classification_rows = list(classifications.items())
        severity_rows = [(k, v) for k, v in severities.items() if v]
        for index in range(max(len(classification_rows), len(severity_rows))):
            c = classification_rows[index] if index < len(classification_rows) else ("", "")
            s = severity_rows[index] if index < len(severity_rows) else ("", "")
            rows.append([self._p(c[0], "small"), self._p(str(c[1]), "small"), self._p(s[0], "small"), self._p(str(s[1]), "small")])
        return self._table(rows, [7.1*cm, 1.4*cm, 7.1*cm, 1.4*cm])

    def _key_value_table(self, pairs, compact=False):
        label_style = "small"
        value_style = "small" if compact else "body"
        rows = [[self._p(key, label_style), self._p(value, value_style)] for key, value in pairs]
        table = Table(rows, colWidths=[4.2 * cm, 13.0 * cm], hAlign="LEFT", splitByRow=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), PALE),
            ("BOX", (0, 0), (-1, -1), 0.45, LINE),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4 if compact else 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4 if compact else 6),
        ]))
        return table

    def _table(self, rows, widths):
        table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE]),
            ("GRID", (0, 0), (-1, -1), 0.35, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return table

    def _rule(self):
        table = Table([[""]], colWidths=[17.4 * cm], rowHeights=[0.08 * cm])
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), TEAL)]))
        return table

    def _location(self, finding):
        path = self._value(finding.get("file_path"), "Location not provided")
        line = finding.get("start_line")
        if line not in (None, "", 0, "0"):
            return f"{path}:{line}"
        return path

    @staticmethod
    def _aes_security_level(name):
        normalized = str(name).upper().replace("_", "-")
        if "AES-128" in normalized:
            return 1
        if "AES-192" in normalized:
            return 3
        if "AES-256" in normalized:
            return 5
        return None

    @staticmethod
    def _group_component_label(group):
        pqc = group.get("pqc_algorithm")
        if not pqc:
            return "—"
        level = 5 if "1024" in str(pqc) else 3
        return f"{pqc} (level {level})"

    @staticmethod
    def _finding_sort_key(finding):
        severity_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
        return (severity_rank.get(finding.get("severity_category"), 0), finding.get("severity_score", 0))

    def _draw_page(self, canvas, doc):
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.55)
        canvas.line(doc.leftMargin, height - 1.35 * cm, width - doc.rightMargin, height - 1.35 * cm)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(NAVY)
        canvas.drawString(doc.leftMargin, height - 1.05 * cm, "PQC CBOM AUDITOR")
        canvas.setFont("Helvetica", 7.3)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(width - doc.rightMargin, height - 1.05 * cm, "CONFIDENTIAL ASSESSMENT REPORT")
        canvas.line(doc.leftMargin, 1.2 * cm, width - doc.rightMargin, 1.2 * cm)
        canvas.setFont("Helvetica", 7.2)
        canvas.drawString(doc.leftMargin, 0.85 * cm, f"Scan reference: {self.scan_id}")
        canvas.drawRightString(width - doc.rightMargin, 0.85 * cm, f"Page {doc.page}")
        canvas.restoreState()
