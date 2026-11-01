import uuid
from datetime import datetime, timezone
from app.scanner.normalizer import algorithm_family

def _ref(prefix):
    return f"{prefix}:{uuid.uuid4()}"

def _property(name, value):
    return {"name": f"pqc-auditor:{name}", "value": str(value)}

class CBOMGenerator:
    def generate(self, scan, findings):
        assets, dependencies = {}, {}
        for finding in findings:
            key = f"{finding.get('algorithm', 'Unknown')}:{finding.get('crypto_operation', 'unknown')}"
            if key not in assets:
                bom_ref = _ref("crypto-asset")
                assets[key] = {
                    "type": "cryptographic-asset", "bom-ref": bom_ref,
                    "name": finding.get("algorithm", "Unknown"),
                    "version": finding.get("algorithm_variant") or "unknown",
                    "description": f"Cryptographic algorithm observed by {finding.get('evidence_type', 'static source analysis')}. Quantum classification: {finding.get('quantum_classification', 'Unknown / Needs Review')}.",
                    "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
                        "primitive": self._primitive(finding),
                        "parameterSetIdentifier": finding.get("algorithm_variant") or "unknown",
                        "executionEnvironment": "unknown", "implementationPlatform": "unknown",
                        "certificationLevel": [], "mode": "unknown", "padding": "unknown",
                        "cryptoFunctions": [self._fn(finding)],
                        "nistQuantumSecurityLevel": self._level(finding)}},
                    "properties": [_property("quantumClassification", finding.get("quantum_classification", "Unknown / Needs Review")),
                                   _property("algorithmFamily", algorithm_family(finding.get("algorithm", "Unknown")))],
                    "evidence": {"occurrences": []},
                }
                dependencies[bom_ref] = set()
            assets[key]["evidence"]["occurrences"].append({
                "location": finding.get("file_path", ""), "line": finding.get("start_line", 0),
                "additionalContext": finding.get("evidence_snippet", "")})

        tls_components, tls_dependencies = self._tls_components(scan.get("tls_assessment"))
        components = list(assets.values()) + tls_components
        dependencies.update(tls_dependencies)
        return {"bomFormat": "CycloneDX", "specVersion": "1.7",
                "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
                "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                    "component": {"type": "application", "name": scan.get("repository_name", "Unknown"), "version": "1.0.0"},
                    "properties": [_property("scanId", scan.get("scan_id", "")),
                                   _property("repositorySourceType", scan.get("repository_source_type", "unknown")),
                                   _property("businessCriticality", scan.get("business_context", {}).get("business_criticality", "unknown")),
                                   _property("dataSensitivity", scan.get("business_context", {}).get("data_sensitivity", "unknown"))]},
                "components": components,
                "dependencies": [{"ref": ref, "dependsOn": sorted(items)} for ref, items in dependencies.items() if items]}

    def _tls_components(self, assessment):
        components, dependencies = [], {}
        if not assessment or assessment.get("status") != "completed":
            return components, dependencies

        protocol_refs = {}
        for protocol in assessment.get("protocols", []):
            ref = _ref("tls-protocol")
            protocol_refs[protocol["version"]] = ref
            cipher = protocol.get("cipher_suite") or {}
            components.append({"type": "cryptographic-asset", "bom-ref": ref,
                "name": protocol["version"], "version": protocol["version"],
                "description": f"Live TLS protocol probe status: {protocol.get('status')}; PQC status: {protocol.get('pqc_status')}.",
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                    "type": "TLS", "version": protocol["version"]}},
                "properties": [_property("probeStatus", protocol.get("status")),
                               _property("pqcStatus", protocol.get("pqc_status"))]})
            dependencies[ref] = set()
            if protocol.get("status") == "confirmed" and cipher.get("name"):
                cipher_ref = _ref("tls-cipher-suite")
                cipher_id = cipher.get("iana_id") or "unknown"
                components.append({"type": "cryptographic-asset", "bom-ref": cipher_ref,
                    "name": cipher["name"], "version": cipher_id,
                    "description": f"Cipher suite negotiated by the TLS {protocol['version']} probe.",
                    "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
                        "primitive": "symmetric", "parameterSetIdentifier": cipher_id,
                        "executionEnvironment": "remote_endpoint", "implementationPlatform": "TLS",
                        "certificationLevel": [], "mode": "negotiated_cipher_suite",
                        "padding": "unknown", "cryptoFunctions": ["encrypt"],
                        "nistQuantumSecurityLevel": 0}},
                    "properties": [_property("ianaCipherSuiteId", cipher_id),
                                   _property("cipherSuiteName", cipher["name"]),
                                   _property("algorithms", ",".join(cipher.get("algorithms", [])))]})
                dependencies[ref].add(cipher_ref)
                dependencies[cipher_ref] = set()
                for algorithm in cipher.get("algorithms", []):
                    classification, security_level = self._algorithm_quantum_level(algorithm)
                    algorithm_ref = self._algorithm_component(components, dependencies, algorithm,
                        "symmetric" if algorithm.startswith(("AES", "ChaCha20")) else
                        "signature" if algorithm in ("RSA", "ECDSA") else "pke" if algorithm == "ECDHE" else "hash",
                        classification, "TLS cipher-suite primitive", security_level)
                    dependencies[cipher_ref].add(algorithm_ref)

        for group in assessment.get("groups", []):
            ref = _ref("tls-group")
            group_name = group["name"]
            is_hybrid = group.get("type") == "hybrid"
            # Classification describes the algorithm; probeStatus describes
            # whether this endpoint accepted it. Keep these separate so an
            # incomplete probe does not make a known ML-KEM primitive unknown.
            classification = ("Quantum Resistant Under Current Knowledge" if is_hybrid
                              else "Quantum Vulnerable")
            primitive = "kem" if is_hybrid else "pke"
            components.append({"type": "cryptographic-asset", "bom-ref": ref, "name": group_name,
                "version": group.get("iana_id", "unknown"),
                "description": f"TLS supported-group probe: {group.get('status')}; protocol: {group.get('protocol')}.",
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
                    "primitive": primitive, "parameterSetIdentifier": group.get("iana_id", "unknown"),
                    "executionEnvironment": "remote_endpoint", "implementationPlatform": "TLS",
                    "certificationLevel": [], "mode": "key_exchange", "padding": "unknown",
                    "cryptoFunctions": ["key_exchange"],
                    "nistQuantumSecurityLevel": self._group_security_level(group) if is_hybrid else 0}},
                "properties": [_property("ianaSupportedGroupId", group.get("iana_id", "unknown")),
                               _property("protocol", group.get("protocol", "TLS 1.3")),
                               _property("probeStatus", group.get("status")),
                               _property("negotiatedGroup", group.get("negotiated_group") or "none"),
                               _property("quantumClassification", classification),
                               _property("classicalComponent", group.get("classical_algorithm") or "none"),
                               _property("pqcComponent", group.get("pqc_algorithm") or "none")]})
            dependencies.setdefault(protocol_refs.get(group.get("protocol"), ""), set()).add(ref)
            dependencies[ref] = set()
            if is_hybrid and group.get("pqc_algorithm"):
                pqc_ref = self._algorithm_component(components, dependencies, group["pqc_algorithm"], "kem",
                    "Quantum Resistant Under Current Knowledge",
                    "PQC component of TLS hybrid key exchange", self._group_security_level(group))
                dependencies[ref].add(pqc_ref)
                classical_ref = self._algorithm_component(components, dependencies,
                    group.get("classical_algorithm", "classical ECDHE"), "pke", "Quantum Vulnerable",
                    "Classical component of TLS hybrid key exchange")
                dependencies[ref].add(classical_ref)

        certificates = assessment.get("certificates") or ([assessment.get("certificate")] if assessment.get("certificate") else [])
        certificate_refs = {}
        for certificate in certificates:
            if not certificate or "parse_error" in certificate:
                continue
            fingerprint = certificate.get("fingerprint_sha256") or certificate.get("serial_number") or certificate.get("protocol", "unknown")
            cert_ref = certificate_refs.get(fingerprint)
            if not cert_ref:
                cert_ref = _ref("tls-certificate")
                certificate_refs[fingerprint] = cert_ref
                key_name = certificate.get("public_key_algorithm", "Unknown")
                if certificate.get("public_key_bits"):
                    key_name = f"{key_name}-{certificate['public_key_bits']}"
                key_ref = self._algorithm_component(components, dependencies, key_name, "signature",
                    "Quantum Resistant Under Current Knowledge" if certificate.get("public_key_quantum_status") == "quantum_resistant" else "Quantum Vulnerable",
                    "TLS endpoint certificate public-key algorithm")
                sig_name = certificate.get("signature_algorithm", "Unknown")
                sig_ref = self._algorithm_component(components, dependencies, sig_name, "signature",
                    "Quantum Resistant Under Current Knowledge" if certificate.get("signature_quantum_status") == "quantum_resistant" else "Quantum Vulnerable",
                    "TLS endpoint certificate signature algorithm")
                certificate_properties = {"subject": certificate.get("subject"), "issuer": certificate.get("issuer"),
                    "serialNumber": certificate.get("serial_number"),
                    "notBefore": certificate.get("not_valid_before"), "notAfter": certificate.get("not_valid_after"),
                    "subjectAltNames": certificate.get("subject_alt_names", []),
                    "publicKeyAlgorithm": key_name, "publicKeyBits": certificate.get("public_key_bits"),
                    "signatureAlgorithm": sig_name, "signatureOID": certificate.get("signature_oid"),
                    "signatureHash": certificate.get("signature_hash")}
                components.append({"type": "cryptographic-asset", "bom-ref": cert_ref,
                    "name": f"TLS certificate for {assessment.get('target', 'endpoint')}",
                    "version": certificate.get("serial_number", "unknown"),
                    "description": "Peer certificate presented during TLS probing. Certificate trust-chain validation was not performed by this probe.",
                    "cryptoProperties": {"assetType": "certificate", "certificateProperties": certificate_properties},
                    "properties": [_property("certificateValidation", certificate.get("validation_status", "not_validated")),
                                   _property("publicKeyAlgorithmRef", key_ref), _property("signatureAlgorithmRef", sig_ref)]})
                dependencies[cert_ref] = {key_ref, sig_ref}
            protocol_ref = protocol_refs.get(certificate.get("protocol"))
            if protocol_ref:
                dependencies[protocol_ref].add(cert_ref)

        return components, dependencies

    def _algorithm_component(self, components, dependencies, name, primitive, classification, description, security_level=None):
        existing = next((component for component in components
                         if component.get("name") == name and component.get("cryptoProperties", {}).get("assetType") == "algorithm"), None)
        if existing:
            return existing["bom-ref"]
        ref = _ref("crypto-algorithm")
        components.append({"type": "cryptographic-asset", "bom-ref": ref, "name": name,
            "version": "unknown", "description": description,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
                "primitive": primitive, "parameterSetIdentifier": name,
                "executionEnvironment": "remote_endpoint", "implementationPlatform": "TLS",
                "certificationLevel": [], "mode": "unknown", "padding": "unknown",
                "cryptoFunctions": ["key_exchange" if primitive in ("kem", "pke") else "unknown"],
                "nistQuantumSecurityLevel": security_level if security_level is not None else
                    (self._algorithm_quantum_level(name)[1] if classification == "Quantum Resistant Under Current Knowledge" else 0)}},
            "properties": [_property("quantumClassification", classification)]})
        dependencies[ref] = set()
        return ref

    def _group_security_level(self, group):
        return 5 if "1024" in str(group.get("pqc_algorithm")) else 3

    def _algorithm_quantum_level(self, name):
        normalized = name.upper().replace("-", "").replace("_", "")
        if normalized in ("AES128GCM", "AES128CBC", "AES128CCM", "AES128"):
            return "Quantum Resistant Under Current Knowledge", 1
        if normalized in ("AES256GCM", "AES256CBC", "AES256CCM", "AES256"):
            return "Quantum Resistant Under Current Knowledge", 5
        if normalized in ("AES192GCM", "AES192CBC", "AES192CCM", "AES192"):
            return "Quantum Resistant Under Current Knowledge", 3
        if normalized in ("CHACHA20POLY1305", "SHA256", "SHA384"):
            return "Quantum Resistant Under Current Knowledge", 0
        if normalized in ("ECDHE", "RSA", "ECDSA"):
            return "Quantum Vulnerable", 0
        return "Unknown / Needs Review", 0

    def _primitive(self, finding):
        op, family = finding.get("crypto_operation"), algorithm_family(finding.get("algorithm", "Unknown"))
        if op in {"key_exchange", "key_encapsulation"}: return "kem"
        if op == "digital_signature": return "signature"
        if op == "hashing": return "hash"
        if family == "Symmetric": return "symmetric"
        return "pke"

    def _fn(self, finding):
        return {"key_generation":"keygen", "key_exchange":"key_exchange", "key_encapsulation":"encapsulate",
                "encryption":"encrypt", "decryption":"decrypt", "digital_signature":"sign",
                "hashing":"digest", "mac":"mac"}.get(finding.get("crypto_operation"), "unknown")

    def _level(self, finding):
        return 0 if finding.get("quantum_classification") != "Quantum Resistant Under Current Knowledge" else 3
