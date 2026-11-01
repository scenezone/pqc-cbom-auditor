import json
from app.cbom.generator import CBOMGenerator
from app.cbom.validator import CBOMValidator

def test_cbom_structure():
    scan = {"scan_id":"t","repository_name":"s","repository_source_type":"zip_upload",
            "business_context":{"business_criticality":"High","data_sensitivity":"Confidential"}}
    f = {"finding_id":"f1","algorithm":"RSA-2048","algorithm_variant":"RSA-2048",
         "crypto_operation":"key_generation","quantum_classification":"Quantum Vulnerable",
         "classification_reference":"NIST IR 8547","file_path":"src/crypto.py","start_line":3,
         "evidence_snippet":"rsa.generate_private_key(...)"}
    cbom = CBOMGenerator().generate(scan, [f])
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.7"
    assert cbom["components"][0]["type"] == "cryptographic-asset"

def test_validator_rejects_invalid(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"bomFormat":"CycloneDX"}))
    r = CBOMValidator().validate(p.read_text())
    assert r["valid"] is False and r["errors"]
