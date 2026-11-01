from app.classification.classifier import QuantumClassifier

def test_rsa_vulnerable():
    assert QuantumClassifier().classify({"algorithm":"RSA-2048"})["quantum_classification"] == "Quantum Vulnerable"

def test_ecdh_vulnerable():
    assert QuantumClassifier().classify({"algorithm":"ECDH"})["quantum_classification"] == "Quantum Vulnerable"

def test_aes_resistant():
    assert QuantumClassifier().classify({"algorithm":"AES-256-GCM"})["quantum_classification"] == "Quantum Resistant Under Current Knowledge"

def test_mlkem_pqc():
    r = QuantumClassifier().classify({"algorithm":"ML-KEM"})
    assert r["is_standardized_pqc"] is True
    assert "FIPS 203" in r["classification_reference"]

def test_unknown_review():
    assert QuantumClassifier().classify({"algorithm":"CustomQuantumWrapper"})["quantum_classification"] == "Unknown / Needs Review"
