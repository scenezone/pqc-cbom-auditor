from app.database.mongodb import database
from app.classification.severity import SeverityEngine
from app.scanner.normalizer import algorithm_family, normalize_algorithm
from app.classification.classifier import QuantumClassifier

def test_algorithm_family_and_classifier():
    norm = normalize_algorithm("aes-128-gcm")
    assert norm == "AES-128-GCM"
    fam = algorithm_family("AES-128-GCM")
    assert fam == "Symmetric"
    c = QuantumClassifier().classify({"algorithm": "AES-128-GCM"})
    assert c["quantum_classification"] == "Quantum Resistant Under Current Knowledge"

    fam_rsa = algorithm_family("RSA-4096")
    assert fam_rsa == "RSA"
    c_rsa = QuantumClassifier().classify({"algorithm": "RSA-4096"})
    assert c_rsa["quantum_classification"] == "Quantum Vulnerable"

def test_severity_resilience_to_case_and_unknowns():
    finding = {"algorithm": "RSA-2048", "quantum_classification": "Quantum Vulnerable",
               "crypto_operation": "key_exchange", "cryptographic_purpose": "key_establishment"}
    # Context with lowercase and unlisted values
    ctx = {"business_criticality": "high", "data_sensitivity": "confidential",
           "data_retention_horizon": "1-3 years", "external_exposure": "internal"}
    res = SeverityEngine().score(finding, ctx)
    assert res["severity_score"] > 0
    assert res["severity_category"] in ("Critical", "High", "Medium", "Low")

def test_database_list_and_delete(monkeypatch):
    test_id = "test-scan-uuid-1234"
    database.scans.insert_one({"scan_id": test_id, "repository_name": "Test Repo", "started_at": 100})
    scans = database.list_scans()
    assert any(s["scan_id"] == test_id for s in scans)
    database.delete_scan(test_id)
    scans_after = database.list_scans()
    assert not any(s["scan_id"] == test_id for s in scans_after)
