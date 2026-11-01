from app.reporting.pdf_generator import ExecutivePDFGenerator

def test_pdf_generation():
    scan = {"scan_id":"t","repository_name":"sample","repository_source_type":"zip_upload",
            "scanned_files":1,"skipped_files":0,
            "business_context":{"business_criticality":"High","data_sensitivity":"Confidential"}}
    f = [{"finding_id":"f1","algorithm":"RSA-2048","crypto_operation":"key_generation",
          "quantum_classification":"Quantum Vulnerable","classification_reference":"NIST IR 8547",
          "file_path":"src/crypto.py","start_line":3,"severity_score":85,
          "severity_category":"High","evidence_snippet":"rsa.generate_private_key(...)"}]
    pdf = ExecutivePDFGenerator().generate(scan, f)
    assert pdf.startswith(b"%PDF")
