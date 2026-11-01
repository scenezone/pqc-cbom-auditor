from pathlib import Path
from app.scanner.python_scanner import PythonCryptoScanner
from app.scanner.generic_scanner import GenericRegexScanner

def test_python_rsa_detection(tmp_path):
    source = "from cryptography.hazmat.primitives.asymmetric import rsa\nprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    p = tmp_path / "rsa.py"; p.write_text(source)
    f = PythonCryptoScanner().scan_file(p, source)
    assert any(x["algorithm"].startswith("RSA") for x in f)
    assert f[0]["start_line"] == 2

def test_python_unused_import(tmp_path):
    source = "import hashlib\n"
    p = tmp_path / "u.py"; p.write_text(source)
    assert PythonCryptoScanner().scan_file(p, source) == []

def test_js_web_crypto(tmp_path):
    source = "const key = await crypto.subtle.generateKey({name: 'RSA-OAEP'}, true, ['encrypt','decrypt']);\n"
    p = tmp_path / "c.js"; p.write_text(source)
    f = GenericRegexScanner("javascript").scan_file(p, source)
    assert any(x["algorithm"] in ("RSA", "RSA-OAEP") for x in f)

def test_go_rsa(tmp_path):
    source = "key, err := rsa.GenerateKey(rand.Reader, 2048)\n"
    p = tmp_path / "m.go"; p.write_text(source)
    f = GenericRegexScanner("go").scan_file(p, source)
    assert any(x["algorithm"].startswith("RSA") for x in f)

def test_java_ecdsa(tmp_path):
    source = 'Signature signature = Signature.getInstance("SHA256withECDSA");\n'
    p = tmp_path / "M.java"; p.write_text(source)
    f = GenericRegexScanner("java").scan_file(p, source)
    assert any(x["algorithm"] == "ECDSA" for x in f)

def test_ts_web_crypto(tmp_path):
    source = "const key: CryptoKey = await crypto.subtle.generateKey({name: 'RSA-OAEP'}, true, ['encrypt','decrypt']);\n"
    p = tmp_path / "c.ts"; p.write_text(source)
    f = GenericRegexScanner("typescript").scan_file(p, source)
    assert any(x["algorithm"] in ("RSA", "RSA-OAEP") for x in f)
    assert f[0]["language"] == "typescript"

def test_scan_engine_typescript(tmp_path):
    from app.scanner.engine import ScanEngine
    p = tmp_path / "crypto.ts"
    p.write_text("const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n")
    findings, stats = ScanEngine().scan_workspace(tmp_path, "test-scan", ["typescript"])
    assert stats["scanned_files"] == 1
    assert len(findings) == 1
    assert findings[0]["language"] == "typescript"

def test_python_sample_repo_both_findings(tmp_path):
    source = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "digest = hashes.Hash(hashes.SHA256())\n"
    )
    p = tmp_path / "sample.py"
    p.write_text(source)
    findings = PythonCryptoScanner().scan_file(p, source)
    algos = {f["algorithm"] for f in findings}
    assert "RSA-2048" in algos
    assert "SHA-256" in algos

def test_python_hashlib_direct_import(tmp_path):
    source = "from hashlib import sha256\nh = sha256(b'test')\n"
    p = tmp_path / "h.py"
    p.write_text(source)
    findings = PythonCryptoScanner().scan_file(p, source)
    assert any(f["algorithm"] == "SHA-256" for f in findings)

def test_js_node_crypto_async_and_hmac(tmp_path):
    source = (
        "const crypto = require('crypto');\n"
        "crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, pub, priv) => {});\n"
        "const hmac = crypto.createHmac('sha256', secret);\n"
    )
    p = tmp_path / "node_crypto.js"
    p.write_text(source)
    findings = GenericRegexScanner("javascript").scan_file(p, source)
    algos = {f["algorithm"] for f in findings}
    assert "RSA-2048" in algos
    assert any("HMAC" in a or "SHA" in a for a in algos)

def test_js_cryptojs_and_jwt(tmp_path):
    source = (
        "const ciphertext = CryptoJS.AES.encrypt('my message', 'secret key 123');\n"
        "const token = jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256' });\n"
    )
    p = tmp_path / "libs.js"
    p.write_text(source)
    findings = GenericRegexScanner("javascript").scan_file(p, source)
    algos = {f["algorithm"] for f in findings}
    assert "AES" in algos
    assert any("RSA" in a for a in algos)

def test_zip_extraction_resilience_to_oversized_file(tmp_path):
    import zipfile
    from app.scanner.repository_loader import extract_zip
    zip_path = tmp_path / "repo.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("huge_asset.bin", b"0" * (15 * 1024 * 1024))
        zf.writestr("src/main.py", "import hashlib\nh = hashlib.sha256(b'ok')\n")

    dest = tmp_path / "extracted"
    dest.mkdir()
    count = extract_zip(zip_path, dest)
    assert count == 1
    assert (dest / "src/main.py").exists()
    assert not (dest / "huge_asset.bin").exists()


