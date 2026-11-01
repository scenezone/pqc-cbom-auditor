from app.classification.severity import SeverityEngine

def base():
    return {"algorithm":"RSA-2048","crypto_operation":"key_exchange",
            "cryptographic_purpose":"key_establishment",
            "quantum_classification":"Quantum Vulnerable","detection_confidence":"High"}

CTX = {"business_criticality":"Critical","data_sensitivity":"Restricted",
       "data_retention_horizon":"More than 15 years","external_exposure":"Public"}

def test_deterministic():
    a = SeverityEngine().score(base(), CTX)
    b = SeverityEngine().score(base(), CTX)
    assert a["severity_score"] == b["severity_score"]
    assert a["severity_category"] == "Critical"

def test_key_establishment_higher_than_signature():
    ke = SeverityEngine().score(base(), CTX)
    sig = SeverityEngine().score({**base(),"crypto_operation":"digital_signature",
                                  "cryptographic_purpose":"authenticity"}, CTX)
    assert ke["severity_score"] > sig["severity_score"]
