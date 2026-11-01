import csv, json, logging, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from app.cbom.generator import CBOMGenerator
from app.cbom.validator import CBOMValidator
from app.classification.classifier import QuantumClassifier
from app.classification.migration import MigrationAdvisor
from app.classification.severity import SeverityEngine
from app.config import get_settings
from app.database.mongodb import database
from app.reporting.pdf_generator import ExecutivePDFGenerator
from app.scanner.engine import ScanEngine
from app.scanner.repository_loader import cleanup_workspace
from app.tls.probe import probe_tls_endpoint

logger = logging.getLogger(__name__)

class ScanService:
    def __init__(self):
        self.engine = ScanEngine()
        self.classifier = QuantumClassifier()
        self.severity = SeverityEngine()
        self.advisor = MigrationAdvisor()
        self.cbom_gen = CBOMGenerator()
        self.cbom_val = CBOMValidator()
        self.pdf_gen = ExecutivePDFGenerator()

    def execute_scan(self, scan_id, workspace):
        scan = database.get_scan(scan_id)
        if not scan:
            return
        database.update_scan(scan_id, {"scan_status": "running"})

        def progress(s, k, n):
            database.update_scan(scan_id, {"scanned_files": s, "skipped_files": k, "total_findings": n})

        try:
            endpoint_only = scan.get("repository_source_type") == "https_endpoint"
            if endpoint_only:
                raw = []
                stats = {"incomplete": False, "total_files": 0, "scanned_files": 0, "skipped_files": 0}
            else:
                raw, stats = self.engine.scan_workspace(workspace, scan_id,
                                                        scan["scan_configuration"]["languages"],
                                                        progress_callback=progress)
                intake_skipped = scan.get("intake_skipped_files", 0)
                stats["total_files"] += intake_skipped
                stats["skipped_files"] += intake_skipped
            enriched = []
            for f in raw:
                f.update(self.classifier.classify(f))
                f.update(self.severity.score(f, scan["business_context"]))
                f["migration_recommendation"] = self.advisor.recommend(f)
                enriched.append(f)
            tls_assessment = None
            if scan.get("tls_target_url"):
                try:
                    tls_assessment = probe_tls_endpoint(scan["tls_target_url"])
                    for tls_finding in tls_assessment.get("findings", []):
                        normalized = self._normalize_tls_finding(scan_id, tls_assessment, tls_finding)
                        tls_finding["finding_id"] = normalized["finding_id"]
                        enriched.append(normalized)
                except Exception as tls_exc:
                    logger.exception("TLS assessment failed for scan %s: %s", scan_id, tls_exc)
                    tls_assessment = {"target": scan["tls_target_url"], "status": "inconclusive",
                                      "error": "TLS assessment could not be completed.",
                                      "protocols": [], "groups": [], "findings": []}
            database.findings.delete_many({"scan_id": scan_id})
            database.insert_findings(enriched)
            status = "incomplete" if stats["incomplete"] else "completed"
            scan_update = {"scan_status": status,
                "completed_at": datetime.now(timezone.utc),
                "total_files": stats["total_files"], "scanned_files": stats["scanned_files"],
                "skipped_files": stats["skipped_files"], "total_findings": len(enriched)}
            if tls_assessment is not None:
                scan_update["tls_assessment"] = tls_assessment
            database.update_scan(scan_id, scan_update)
            try:
                self._write_exports(scan_id, enriched)
            except Exception as exp_err:
                logger.error("Failed to write scan exports for %s: %s", scan_id, exp_err)
        except Exception as exc:
            logger.exception("Scan execution failed for %s: %s", scan_id, exc)
            database.update_scan(scan_id, {
                "scan_status": "failed",
                "error_summary": str(exc),
                "completed_at": datetime.now(timezone.utc),
            })
        finally:
            if workspace is not None:
                cleanup_workspace(workspace)

    def _normalize_tls_finding(self, scan_id, assessment, item):
        title = item["title"]
        cert = item.get("certificate") or assessment.get("certificate") or {}
        if "certificate" in title.lower():
            algorithm = cert.get("public_key_algorithm", "Unknown")
            if cert.get("public_key_bits"):
                algorithm = f"{algorithm}-{cert['public_key_bits']}"
            operation, purpose = "digital_signature", "authenticity"
            rule = "TLS-CERTIFICATE-ALGORITHM"
            variant = cert.get("signature_algorithm", algorithm)
        elif "hybrid" in title.lower() and item.get("quantum_status") == "hybrid_or_pqc_confirmed":
            algorithm = next((g.get("pqc_algorithm") for g in assessment.get("groups", [])
                              if g.get("status") == "confirmed" and g.get("pqc_algorithm")), "ML-KEM")
            operation, purpose = "key_exchange", "key_establishment"
            rule, variant = "TLS-HYBRID-GROUP", algorithm
        elif "hybrid" in title.lower():
            algorithm = "TLS 1.3 hybrid group capability"
            operation, purpose = "key_exchange", "key_establishment"
            rule, variant = "TLS13-GROUP-CAPABILITY", "TLS 1.3"
        elif "TLS 1.2" in title:
            algorithm = "TLS 1.2"
            operation, purpose = "protocol", "transport_security"
            rule, variant = "TLS12-NO-PQC", "TLS 1.2"
        else:
            algorithm = "TLS 1.3"
            operation, purpose = "key_exchange", "key_establishment"
            rule, variant = "TLS13-GROUP-CAPABILITY", "TLS 1.3"
        finding = {
            "finding_id": str(uuid.uuid4()), "scan_id": scan_id, "language": "tls",
            "file_path": assessment.get("target", "TLS endpoint"), "start_line": 0, "end_line": 0,
            "symbol_name": title, "library_name": "TLS endpoint probe", "imported_symbol": rule,
            "crypto_operation": operation, "algorithm": algorithm, "algorithm_variant": variant,
            "key_size": cert.get("public_key_bits"), "cryptographic_purpose": purpose,
            "evidence_type": "tls_probe", "evidence_snippet": item["detail"][:240],
            "detection_rule_id": rule,
            "detection_confidence": "Medium" if item["quantum_status"] == "inconclusive" else "High",
            "tls_quantum_status": item["quantum_status"],
        }
        finding.update(self.classifier.classify(finding))
        quantum_status = item.get("quantum_status")
        if quantum_status in {"not_pqc", "quantum_vulnerable"}:
            finding["quantum_classification"] = "Quantum Vulnerable"
            finding["classification_reason"] = item["detail"]
        elif quantum_status == "hybrid_or_pqc_confirmed":
            finding["quantum_classification"] = "Quantum Resistant Under Current Knowledge"
            finding["classification_reason"] = item["detail"]
        elif quantum_status == "inconclusive":
            finding["quantum_classification"] = "Unknown / Needs Review"
            finding["classification_reason"] = item["detail"]
        severity = item.get("severity", "Medium")
        finding.update({"severity_category": severity,
                        "severity_score": {"Critical": 90, "High": 75, "Medium": 50, "Low": 20}.get(severity, 50)})
        finding["migration_recommendation"] = self.advisor.recommend(finding)
        return finding

    def _write_exports(self, scan_id, findings):
        d = get_settings().scan_temp_directory / scan_id / "exports"
        d.mkdir(parents=True, exist_ok=True)
        clean = [{k: v for k, v in f.items() if k != "_id"} for f in findings]
        (d / "findings.json").write_text(json.dumps(clean, indent=2, default=str), encoding="utf-8")
        with (d / "findings.csv").open("w", newline="", encoding="utf-8") as h:
            w = csv.DictWriter(h, fieldnames=["finding_id","scan_id","language","file_path","start_line",
                "algorithm","crypto_operation","library_name","quantum_classification",
                "severity_score","severity_category","detection_confidence","migration_recommendation"],
                extrasaction="ignore")
            w.writeheader()
            w.writerows(clean)

    def generate_cbom(self, scan_id):
        scan = database.get_scan(scan_id)
        findings = database.get_findings(scan_id)
        cbom = self.cbom_gen.generate(scan, findings)
        d = get_settings().scan_temp_directory / scan_id / "exports"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "cbom.json"
        p.write_text(json.dumps(cbom, indent=2), encoding="utf-8")
        return {"cbom": cbom, "validation": self.cbom_val.validate(cbom), "path": p}

    def generate_pdf(self, scan_id):
        scan = database.get_scan(scan_id)
        findings = database.get_findings(scan_id)
        pdf = self.pdf_gen.generate(scan, findings)
        d = get_settings().report_storage_directory
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{scan_id}-executive-report.pdf"
        p.write_bytes(pdf)
        database.create_report_record({"report_id": str(uuid.uuid4()), "scan_id": scan_id,
            "report_type": "executive_pdf", "generation_status": "complete",
            "generated_at": datetime.now(timezone.utc), "storage_reference": str(p),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=get_settings().report_retention_hours)})
        return p

    def export_findings_csv(self, scan_id):
        p = get_settings().scan_temp_directory / scan_id / "exports" / "findings.csv"
        return p.read_bytes() if p.exists() else b""

    def export_findings_json(self, scan_id):
        p = get_settings().scan_temp_directory / scan_id / "exports" / "findings.json"
        return p.read_bytes() if p.exists() else b"{}"

scan_service = ScanService()
