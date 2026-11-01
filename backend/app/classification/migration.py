MIGRATIONS = {
    "RSA": {"key_establishment":"Assess migration to standards-based PQC key establishment such as ML-KEM (FIPS 203), considering hybrid deployment during transition.",
            "digital_signature":"Assess migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), considering certificate, protocol, and HSM compatibility.",
            "default":"Assess RSA usage and plan migration to appropriate NIST-standardized PQC alternatives."},
    "ECC": {"key_exchange":"Assess ML-KEM-capable protocols and compatible hybrid migration approaches for ECDH/X25519 key establishment.",
            "digital_signature":"Assess migration from ECDSA/Ed25519 to ML-DSA or SLH-DSA where protocol and ecosystem support exists.",
            "default":"Assess elliptic-curve cryptography usage and plan a PQC migration path."},
    "Finite-field DH": {"default":"Assess migration from classical DH/DSA to ML-KEM for key establishment or ML-DSA/SLH-DSA for signatures."},
    "Symmetric": {"default":"AES-256 can normally be retained when correctly implemented; review key management, modes, IV/nonce handling, and operational configuration."},
    "Hash": {"default":"Modern SHA-2/SHA-3 usage is generally retained; review collision-sensitive designs and protocol usage."},
    "PQC KEM": {"default":"ML-KEM is a standardized PQC key-encapsulation mechanism; verify implementation maturity, parameter sets, and integration correctness."},
    "PQC Signature": {"default":"ML-DSA or SLH-DSA is a standardized PQC signature algorithm; verify implementation maturity and integration correctness."},
    "Other": {"default":"Manual investigation is required to identify the algorithm and determine an appropriate migration path."},
}

class MigrationAdvisor:
    def recommend(self, finding):
        family = finding.get("algorithm_family","Other")
        operation = finding.get("crypto_operation","default")
        rules = MIGRATIONS.get(family, MIGRATIONS["Other"])
        return rules.get(operation, rules["default"])
