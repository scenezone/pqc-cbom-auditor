import ipaddress
import logging
import re
import subprocess
import time
from datetime import timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

from app.config import get_settings
from app.utils.security import resolve_public_addresses

logger = logging.getLogger(__name__)

HYBRID_GROUPS = [
    {"name": "X25519MLKEM768", "id": "0x11EC", "classical": "X25519", "pqc": "ML-KEM-768"},
    {"name": "SecP256r1MLKEM768", "id": "0x11EB", "classical": "secp256r1", "pqc": "ML-KEM-768"},
    {"name": "SecP384r1MLKEM1024", "id": "0x11ED", "classical": "secp384r1", "pqc": "ML-KEM-1024"},
]
CLASSICAL_GROUPS = [
    {"name": "X25519", "id": "0x001D", "quantum_status": "quantum_vulnerable"},
    {"name": "prime256v1", "id": "0x0017", "quantum_status": "quantum_vulnerable"},
    {"name": "secp384r1", "id": "0x0018", "quantum_status": "quantum_vulnerable"},
]
CIPHER_SUITE_IDS = {
    "TLS_AES_128_GCM_SHA256": "0x1301", "TLS_AES_256_GCM_SHA384": "0x1302",
    "TLS_CHACHA20_POLY1305_SHA256": "0x1303", "TLS_AES_128_CCM_SHA256": "0x1304",
    "TLS_AES_128_CCM_8_SHA256": "0x1305",
    "ECDHE-RSA-AES128-GCM-SHA256": "0xC02F", "ECDHE-RSA-AES256-GCM-SHA384": "0xC030",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "0xC02B", "ECDHE-ECDSA-AES256-GCM-SHA384": "0xC02C",
    "ECDHE-RSA-CHACHA20-POLY1305": "0xCCA8", "ECDHE-ECDSA-CHACHA20-POLY1305": "0xCCA9",
    "ECDHE-RSA-AES128-SHA256": "0xC027", "ECDHE-RSA-AES256-SHA384": "0xC028",
    "ECDHE-ECDSA-AES128-SHA256": "0xC023", "ECDHE-ECDSA-AES256-SHA384": "0xC024",
    "ECDHE-RSA-AES128-SHA": "0xC013", "ECDHE-RSA-AES256-SHA": "0xC014",
    "ECDHE-ECDSA-AES128-SHA": "0xC009", "ECDHE-ECDSA-AES256-SHA": "0xC00A",
    "DHE-RSA-AES128-GCM-SHA256": "0x009E", "DHE-RSA-AES256-GCM-SHA384": "0x009F",
    "AES128-GCM-SHA256": "0x009C", "AES256-GCM-SHA384": "0x009D",
    "AES128-SHA": "0x002F", "AES256-SHA": "0x0035",
}

def _safe_target(target_url):
    parsed = urlparse(str(target_url))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("TLS target must be a public HTTPS URL without embedded credentials")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port or 443
    addresses = resolve_public_addresses(host, port)
    return host, port, addresses[0]

def normalize_tls_target_url(target_url):
    parsed = urlparse(str(target_url))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("TLS target must be an HTTPS URL without embedded credentials")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parsed.port or 443
    return f"https://{host}" + (f":{port}" if port != 443 else "")

def _connection_address(address, port):
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    return f"[{address}]:{port}" if ip.version == 6 else f"{address}:{port}"

def _command(target, protocol, group=None, trace=False):
    settings = get_settings()
    host, port, address = target
    args = [settings.tls_openssl_binary, "s_client", "-connect", _connection_address(address, port),
            "-servername", host, "-verify_hostname", host, "-showcerts"]
    args.append("-tls1_2" if protocol == "TLS 1.2" else "-tls1_3")
    if group:
        args.extend(["-groups", group])
    if trace:
        args.append("-trace")
    return args

def _run_handshake(target, protocol, group=None, trace=False):
    settings = get_settings()
    attempts = 0
    last_output = ""
    last_diagnostics = {"exit_code": None, "stderr": "", "timed_out": False}
    while attempts < 2:
        if settings.tls_probe_inter_probe_delay_seconds > 0:
            time.sleep(settings.tls_probe_inter_probe_delay_seconds)
        if attempts and settings.tls_probe_retry_backoff_seconds > 0:
            time.sleep(settings.tls_probe_retry_backoff_seconds)
        attempts += 1
        command = _command(target, protocol, group, trace)
        host = target[0]
        try:
            proc = subprocess.run(command, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True,
                                  timeout=settings.tls_probe_timeout_seconds, check=False)
            stdout = _text(proc.stdout)
            stderr = _text(proc.stderr)
            last_output = stdout + "\n" + stderr
            last_diagnostics = {"exit_code": proc.returncode, "stderr": stderr, "timed_out": False}
            _log_attempt(host, protocol, group, attempts, proc.returncode, stderr, False, command)
            success = bool(re.search(r"(?:Protocol version|Protocol)\s*:\s*TLSv1\.[23]|New,\s*TLSv1\.[23]", last_output) or
                           "CONNECTION ESTABLISHED" in last_output)
            if success:
                return {"status": "confirmed", "attempts": attempts, "output": last_output, **last_diagnostics}
            if re.search(r"SSL_CONF_cmd|unknown group|no such group|invalid group|group.*not found", last_output, re.I):
                return {"status": "inconclusive", "attempts": attempts,
                        "reason": "The local OpenSSL client does not support this group.", "output": last_output, **last_diagnostics}
            if re.search(r"alert protocol version|unsupported protocol|no protocols available|handshake failure|no suitable key share|no shared cipher", last_output, re.I):
                return {"status": "not_supported", "attempts": attempts,
                        "reason": "The endpoint rejected this protocol or group.", "output": last_output, **last_diagnostics}
            return {"status": "inconclusive", "attempts": attempts,
                    "reason": _failure_reason(stderr, proc.returncode), "output": last_output, **last_diagnostics}
        except subprocess.TimeoutExpired as exc:
            stdout = _text(exc.stdout)
            stderr = _text(exc.stderr)
            last_output = stdout + "\n" + stderr
            last_diagnostics = {"exit_code": None, "stderr": stderr, "timed_out": True}
            _log_attempt(host, protocol, group, attempts, None, stderr, True, command)
            if attempts == 2:
                return {"status": "inconclusive", "attempts": attempts,
                        "reason": f"Handshake timed out twice after {settings.tls_probe_timeout_seconds}s per attempt; server support is inconclusive.",
                        "output": last_output, **last_diagnostics}
        except FileNotFoundError:
            return {"status": "inconclusive", "attempts": attempts,
                    "reason": "OpenSSL CLI is unavailable on the scanner host.", **last_diagnostics}
        except OSError as exc:
            _log_attempt(host, protocol, group, attempts, None, str(exc), False, command)
            return {"status": "inconclusive", "attempts": attempts,
                    "reason": f"TLS probe could not run: {type(exc).__name__}: {exc}", **last_diagnostics}
    return {"status": "inconclusive", "attempts": attempts, "reason": "TLS probe did not complete.", **last_diagnostics}


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _log_attempt(host, protocol, group, attempt, exit_code, stderr, timed_out, command):
    logger.info(
        "TLS probe host=%s protocol=%s group=%s attempt=%d command=%r exit_code=%s timed_out=%s stderr=%s",
        host, protocol, group or "default", attempt, command, exit_code, timed_out, stderr,
    )


def _failure_reason(stderr, exit_code):
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    detail = lines[-1] if lines else "OpenSSL returned no diagnostic text."
    if len(detail) > 500:
        detail = detail[-500:]
    return f"OpenSSL exited with code {exit_code}: {detail}"


def _openssl_version():
    settings = get_settings()
    try:
        proc = subprocess.run([settings.tls_openssl_binary, "version", "-a"],
                              capture_output=True, text=True, timeout=5, check=False)
        output = (proc.stdout or proc.stderr or "").strip()
        return output.splitlines()[0] if output else f"version command exited with code {proc.returncode}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable ({type(exc).__name__})"

def _parse_cipher(output):
    match = re.search(r"Ciphersuite:\s*([^\s]+)|Cipher is\s+([^\s]+)", output)
    name = (match.group(1) or match.group(2)) if match else None
    if not name:
        return None
    upper = name.upper()
    algorithms = []
    if "AES" in upper:
        mode = next((value for value in ("GCM", "CBC", "CCM", "XTS", "CTR") if value in upper), None)
        # Cipher-suite names also contain the hash size (for example SHA256).
        # Extract the AES key size specifically, rather than searching digits
        # anywhere in the suite name.
        aes_key_size = re.search(r"AES(?:[-_])?(128|192|256)", upper)
        bits = aes_key_size.group(1) if aes_key_size else None
        algorithms.append(f"AES-{bits}-{mode}" if bits and mode else "AES")
    if "CHACHA20" in upper:
        algorithms.append("ChaCha20-Poly1305")
    if "ECDHE" in upper:
        algorithms.append("ECDHE")
    if "RSA" in upper:
        algorithms.append("RSA")
    elif "ECDSA" in upper:
        algorithms.append("ECDSA")
    for digest in ("SHA384", "SHA256", "SHA1"):
        if digest in upper:
            algorithms.append(digest.replace("SHA", "SHA-"))
            break
    iana_id = CIPHER_SUITE_IDS.get(name)
    if not iana_id:
        for line in output.splitlines():
            if name in line:
                identifier = re.search(r"\b0x([0-9a-f]{4})\b", line, re.I)
                if identifier:
                    iana_id = f"0x{identifier.group(1).upper()}"
                    break
    return {"name": name, "iana_id": iana_id, "algorithms": algorithms}

def _parse_negotiated_group(output):
    # OpenSSL has used several labels across releases. Accept only negotiated
    # peer/server output; ClientHello key_share traces can list offers that the
    # server did not select.
    patterns = (
        r"(?:Server|Peer) Temp Key:\s*(?:ECDH|ECDSA)\s*,\s*([A-Za-z0-9_-]+)",
        r"(?:Server|Peer) Temp Key:\s*([A-Za-z0-9_-]+)",
        r"Negotiated\s+(?:TLS\s*v?\s*1\.[23]\s+)?group:\s*([A-Za-z0-9_-]+)",
        r"Negotiated group:\s*([A-Za-z0-9_-]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, output, re.I)
        if match:
            return match.group(1)
    return None


def _canonical_group(name):
    normalized = re.sub(r"[^A-Z0-9]", "", name.upper())
    aliases = {
        "PRIME256V1": "SECP256R1", "P256": "SECP256R1",
        "X25519MLKEM768": "X25519MLKEM768",
        "SECP256R1MLKEM768": "SECP256R1MLKEM768",
        "SECP384R1MLKEM1024": "SECP384R1MLKEM1024",
    }
    return aliases.get(normalized, normalized)

def _group_was_negotiated(expected, output):
    actual = _parse_negotiated_group(output)
    if not actual:
        return None
    return actual if _canonical_group(actual) == _canonical_group(expected) else None

def _checked_group_result(expected, result):
    if result["status"] != "confirmed":
        return result, None
    negotiated = _group_was_negotiated(expected, result.get("output", ""))
    if negotiated is None:
        return {**result, "status": "inconclusive",
                "reason": "Handshake completed, but the negotiated group could not be confirmed from client output."}, None
    return result, negotiated

def _utc_date(value):
    try:
        date_value = getattr(value, "not_valid_before_utc", None) or value.not_valid_before
        return date_value.replace(tzinfo=timezone.utc).isoformat()
    except (AttributeError, ValueError):
        return None

def _utc_expiry(cert):
    try:
        value = getattr(cert, "not_valid_after_utc", None)
        if value is None:
            value = cert.not_valid_after
        return value.replace(tzinfo=timezone.utc).isoformat()
    except (AttributeError, ValueError):
        return None

def _certificate_details(output):
    cert_match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.S)
    if not cert_match:
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_match.group(0).encode("ascii"))
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            public_key_algorithm, key_bits = "RSA", key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey):
            public_key_algorithm, key_bits = "ECDSA", key.key_size
        elif isinstance(key, ed25519.Ed25519PublicKey):
            public_key_algorithm, key_bits = "Ed25519", 256
        elif isinstance(key, ed448.Ed448PublicKey):
            public_key_algorithm, key_bits = "Ed448", 448
        else:
            public_key_algorithm, key_bits = type(key).__name__, None
        signature_oid = cert.signature_algorithm_oid
        signature_name = getattr(signature_oid, "_name", None) or signature_oid.dotted_string
        signature_hash = None
        try:
            signature_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        except Exception:
            pass
        normalized_signature = signature_name.upper().replace("-", "").replace("_", "")
        normalized_key = public_key_algorithm.upper().replace("-", "").replace("_", "")
        pqc_signature = "MLDSA" in normalized_signature or "SLHDSA" in normalized_signature
        pqc_public_key = "MLDSA" in normalized_key or "SLHDSA" in normalized_key
        san = []
        try:
            extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        return {
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "serial_number": format(cert.serial_number, "x"), "subject_alt_names": san,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "not_valid_before": _utc_date(cert), "not_valid_after": _utc_expiry(cert),
            "public_key_algorithm": public_key_algorithm, "public_key_bits": key_bits,
            "public_key_quantum_status": "quantum_resistant" if pqc_public_key else "quantum_vulnerable",
            "signature_algorithm": signature_name, "signature_oid": signature_oid.dotted_string,
            "signature_hash": signature_hash,
            "signature_quantum_status": "quantum_resistant" if pqc_signature else "quantum_vulnerable",
            "validation_status": "not_validated_by_probe",
        }
    except Exception:
        return {"parse_error": "The peer certificate was received but could not be parsed."}

def _probe_result(protocol, result, output=None):
    version = protocol
    return {"version": version, "status": result["status"],
            "pqc_status": "not_pqc" if protocol == "TLS 1.2" and result["status"] == "confirmed" else "not_applicable",
            "negotiated_group": _parse_negotiated_group(output or ""), "cipher_suite": _parse_cipher(output or ""),
            "attempts": result.get("attempts", 0), "reason": result.get("reason"),
            "exit_code": result.get("exit_code"), "timed_out": result.get("timed_out", False),
            "stderr_excerpt": result.get("stderr", "")[-2000:]}

def _build_findings(protocols, groups, certificates):
    findings = []
    tls12 = next(item for item in protocols if item["version"] == "TLS 1.2")
    tls13 = next(item for item in protocols if item["version"] == "TLS 1.3")
    if tls12["status"] == "confirmed":
        findings.append({"title": "TLS 1.2 provides no PQC key exchange", "severity": "High",
                         "quantum_status": "not_pqc",
                         "detail": "TLS 1.2 was negotiated successfully. The standardized ML-KEM hybrid groups tested here are TLS 1.3 groups and cannot protect TLS 1.2 sessions."})
    hybrid = [group for group in groups if group["pqc_algorithm"]]
    confirmed_hybrid = [group for group in hybrid if group["status"] == "confirmed"]
    uncertain_hybrid = [group for group in hybrid if group["status"] == "inconclusive"]
    if tls13["status"] == "confirmed" and confirmed_hybrid:
        names = ", ".join(group["name"] for group in confirmed_hybrid)
        findings.append({"title": "TLS 1.3 PQC hybrid key exchange confirmed", "severity": "Low",
                         "quantum_status": "hybrid_or_pqc_confirmed",
                         "detail": f"Forced TLS 1.3 handshakes successfully negotiated the hybrid group(s): {names}. This confirms capability for those groups, not that every client session selects them."})
    elif tls13["status"] == "confirmed" and uncertain_hybrid:
        reasons = sorted({group.get("reason") for group in uncertain_hybrid if group.get("reason")})
        reason = " ".join(reasons) or "The probe could not confirm whether the endpoint accepts the tested hybrid groups."
        findings.append({"title": "TLS 1.3 hybrid key exchange is inconclusive", "severity": "Medium",
                         "quantum_status": "inconclusive",
                         "detail": f"One or more hybrid-group probes could not establish support. {reason}"})
    elif tls13["status"] == "confirmed":
        findings.append({"title": "No tested TLS 1.3 PQC hybrid group was accepted", "severity": "High",
                         "quantum_status": "not_pqc",
                         "detail": "TLS 1.3 was confirmed, but each tested standardized ML-KEM hybrid group was rejected by the endpoint."})
    reported_certificates = set()
    for certificate in certificates:
        if not certificate or "parse_error" in certificate:
            continue
        fingerprint = certificate.get("fingerprint_sha256") or certificate.get("serial_number")
        if fingerprint and fingerprint in reported_certificates:
            continue
        if fingerprint:
            reported_certificates.add(fingerprint)
        key_status = certificate["public_key_quantum_status"]
        sig_status = certificate["signature_quantum_status"]
        if key_status == "quantum_vulnerable" or sig_status == "quantum_vulnerable":
            key_name = certificate["public_key_algorithm"]
            if certificate.get("public_key_bits"):
                key_name += f"-{certificate['public_key_bits']}"
            findings.append({"title": f"{certificate.get('protocol', 'TLS')} certificate has a quantum-vulnerable public key or signature",
                             "severity": "High", "quantum_status": "quantum_vulnerable",
                             "protocol": certificate.get("protocol"), "certificate": certificate,
                             "detail": f"Certificate public key: {key_name} ({key_status}); certificate signature: {certificate['signature_algorithm']} ({sig_status}). The endpoint presented this classical certificate; no PQ certificate was observed for this protocol."})
    return findings

def probe_tls_endpoint(target_url):
    try:
        target = _safe_target(target_url)
    except (ValueError, UnicodeError) as exc:
        return {"target": str(target_url), "status": "rejected", "error": str(exc), "protocols": [], "groups": [], "findings": []}
    host, port, _ = target
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    safe_target = f"https://{display_host}" + (f":{port}" if port != 443 else "")
    protocol_results, outputs = [], {}
    for version in ("TLS 1.2", "TLS 1.3"):
        result = _run_handshake(target, version, trace=True)
        outputs[version] = result.get("output", "")
        protocol_results.append(_probe_result(version, result, outputs[version]))
    certificates, certificates_by_protocol = [], {}
    for protocol in protocol_results:
        if protocol["status"] != "confirmed":
            continue
        cert = _certificate_details(outputs[protocol["version"]])
        if cert:
            cert["protocol"] = protocol["version"]
            certificates_by_protocol[protocol["version"]] = cert
            certificates.append(cert)
            protocol["certificate_fingerprint"] = cert.get("fingerprint_sha256")
    certificate = certificates_by_protocol.get("TLS 1.3") or certificates_by_protocol.get("TLS 1.2")

    groups = []
    for group in CLASSICAL_GROUPS:
        result = _run_handshake(target, "TLS 1.3", group["name"])
        result, negotiated_group = _checked_group_result(group["name"], result)
        groups.append({"name": group["name"], "iana_id": group["id"], "protocol": "TLS 1.3",
                       "type": "classical", "pqc_algorithm": None, "status": result["status"],
                       "negotiated_group": negotiated_group,
                       "attempts": result.get("attempts", 0), "reason": result.get("reason"),
                       "exit_code": result.get("exit_code"), "timed_out": result.get("timed_out", False),
                       "stderr_excerpt": result.get("stderr", "")[-2000:],
                       "quantum_status": group["quantum_status"]})
    for group in HYBRID_GROUPS:
        result = _run_handshake(target, "TLS 1.3", group["name"])
        result, negotiated_group = _checked_group_result(group["name"], result)
        groups.append({"name": group["name"], "iana_id": group["id"], "protocol": "TLS 1.3",
                       "type": "hybrid", "classical_algorithm": group["classical"],
                       "pqc_algorithm": group["pqc"], "status": result["status"],
                       "negotiated_group": negotiated_group,
                       "attempts": result.get("attempts", 0), "reason": result.get("reason"),
                       "exit_code": result.get("exit_code"), "timed_out": result.get("timed_out", False),
                       "stderr_excerpt": result.get("stderr", "")[-2000:],
                       "quantum_status": "hybrid_or_pqc_confirmed" if result["status"] == "confirmed" else result["status"]})

    confirmed_hybrid = [g for g in groups if g["type"] == "hybrid" and g["status"] == "confirmed"]
    for protocol in protocol_results:
        if protocol["version"] == "TLS 1.3" and protocol["status"] == "confirmed":
            if confirmed_hybrid:
                protocol["pqc_status"] = "hybrid_or_pqc_confirmed"
            elif any(g["type"] == "hybrid" and g["status"] == "inconclusive" for g in groups):
                protocol["pqc_status"] = "inconclusive"
            else:
                protocol["pqc_status"] = "not_pqc"

    findings = _build_findings(protocol_results, groups, certificates)
    return {"target": safe_target, "status": "completed", "protocols": protocol_results,
            "groups": groups, "certificate": certificate, "certificates": certificates, "findings": findings,
            "probe_client": {"name": "OpenSSL s_client", "version": _openssl_version(),
                             "timeout_seconds": get_settings().tls_probe_timeout_seconds,
                             "inter_probe_delay_seconds": get_settings().tls_probe_inter_probe_delay_seconds,
                             "hybrid_groups": "requires a build with RFC 10024 groups"}}
