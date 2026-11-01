import re

ALGORITHM_ALIASES = {
    "RSA2048":"RSA-2048","RSA-2048":"RSA-2048","RSA3072":"RSA-3072","RSA-3072":"RSA-3072",
    "RSA4096":"RSA-4096","RSA-4096":"RSA-4096",
    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding":"RSA-OAEP","RSA-OAEP":"RSA-OAEP",
    "secp256r1":"P-256","prime256v1":"P-256","P-256":"P-256","X25519":"X25519","Ed25519":"Ed25519",
    "aes-256-gcm":"AES-256-GCM","AES-256-GCM":"AES-256-GCM","aes-128-gcm":"AES-128-GCM","AES-128-GCM":"AES-128-GCM",
    "aes-256-cbc":"AES-256-CBC","AES-256-CBC":"AES-256-CBC","AES":"AES",
    "SHA256":"SHA-256","SHA-256":"SHA-256","SHA384":"SHA-384","SHA-384":"SHA-384",
    "SHA512":"SHA-512","SHA-512":"SHA-512","SHA3-256":"SHA3-256","SHA3-512":"SHA3-512",
    "sha1":"SHA-1","SHA1":"SHA-1","SHA-1":"SHA-1","md5":"MD5","MD5":"MD5",
    "des":"DES","DES":"DES","3des":"3DES","3DES":"3DES","TripleDES":"3DES",
    "blowfish":"Blowfish","Blowfish":"Blowfish","chacha20":"ChaCha20","ChaCha20":"ChaCha20",
    "HMAC":"HMAC","hmac":"HMAC","bcrypt":"bcrypt","argon2":"Argon2","Argon2":"Argon2",
    "MLKEM":"ML-KEM","ML-KEM":"ML-KEM","MLDSA":"ML-DSA","ML-DSA":"ML-DSA",
    "SLHDSA":"SLH-DSA","SLH-DSA":"SLH-DSA","kyber":"ML-KEM","dilithium":"ML-DSA","sphincs":"SLH-DSA",
}

FAMILY_MAP = {
    "RSA":"RSA","RSA-OAEP":"RSA","RSA-2048":"RSA","RSA-3072":"RSA","RSA-4096":"RSA",
    "ECDSA":"ECC","ECDH":"ECC","X25519":"ECC","Ed25519":"ECC","P-256":"ECC","P-384":"ECC","P-521":"ECC",
    "AES":"Symmetric","AES-128":"Symmetric","AES-192":"Symmetric","AES-256":"Symmetric",
    "AES-256-GCM":"Symmetric","AES-128-GCM":"Symmetric","AES-256-CBC":"Symmetric","AES-128-CBC":"Symmetric",
    "DES":"Symmetric","3DES":"Symmetric","TripleDES":"Symmetric","Blowfish":"Symmetric","ChaCha20":"Symmetric",
    "SHA":"Hash","SHA-256":"Hash","SHA-384":"Hash","SHA-512":"Hash","SHA-224":"Hash","SHA-1":"Hash","MD5":"Hash",
    "SHA3-256":"Hash","SHA3-512":"Hash",
    "HMAC":"MAC","HMAC-SHA256":"MAC","HMAC-SHA512":"MAC","HMAC-SHA1":"MAC",
    "bcrypt":"KDF","Argon2":"KDF","PBKDF2":"KDF","Scrypt":"KDF",
    "DH":"Finite-field DH","Diffie-Hellman":"Finite-field DH","DSA":"Finite-field DH",
    "ML-KEM":"PQC KEM","ML-DSA":"PQC Signature","SLH-DSA":"PQC Signature","TLS":"Protocol",
}

def normalize_algorithm(raw):
    if not raw:
        return "Unknown"
    candidate = raw.strip()
    if candidate in ALGORITHM_ALIASES:
        return ALGORITHM_ALIASES[candidate]
    upper = candidate.upper()
    if "RSA" in upper or upper.startswith("RS"):
        m = re.search(r"(\d{4})", candidate)
        return f"RSA-{m.group(1)}" if m else "RSA"
    if "AES" in upper:
        bits = re.search(r"(128|192|256)", candidate)
        mode = "GCM" if "GCM" in upper else ("CBC" if "CBC" in upper else "")
        base = f"AES-{bits.group(1)}" if bits else "AES"
        return f"{base}-{mode}" if mode else base
    if "ECDSA" in upper or upper.startswith("ES"): return "ECDSA"
    if "ECDH" in upper: return "ECDH"
    if "X25519" in upper: return "X25519"
    if "ED25519" in upper: return "Ed25519"
    if "SHA3" in upper or "SHA-3" in upper:
        return "SHA3-256" if "256" in candidate else "SHA3-512"
    if "SHA" in upper or upper.startswith("HS"):
        bits = re.search(r"(224|256|384|512|1)", candidate)
        return f"SHA-{bits.group(1)}" if bits else "SHA-256"
    if "MD5" in upper: return "MD5"
    if "DES" in upper: return "3DES" if ("3DES" in upper or "TRIPLE" in upper) else "DES"
    if "BLOWFISH" in upper: return "Blowfish"
    if "CHACHA" in upper: return "ChaCha20"
    if "HMAC" in upper: return "HMAC"
    if "BCRYPT" in upper: return "bcrypt"
    if "ARGON2" in upper: return "Argon2"
    if "ML" in upper and "KEM" in upper or "KYBER" in upper: return "ML-KEM"
    if "ML" in upper and "DSA" in upper or "DILITHIUM" in upper: return "ML-DSA"
    if "SLH" in upper or "SPHINCS" in upper: return "SLH-DSA"
    return candidate

def algorithm_family(algorithm):
    if not algorithm:
        return "Other"
    if algorithm in FAMILY_MAP:
        return FAMILY_MAP[algorithm]
    upper = algorithm.upper()
    if upper.startswith("AES") or "AES" in upper:
        return "Symmetric"
    if upper.startswith("RSA") or "RSA" in upper or upper.startswith("RS"):
        return "RSA"
    if any(k in upper for k in ["ECDSA", "ECDH", "X25519", "ED25519", "SECP256", "PRIME256", "P-256", "P-384", "P-521"]):
        return "ECC"
    if upper.startswith("SHA") or "SHA" in upper or "MD5" in upper:
        return "Hash"
    if any(k in upper for k in ["DES", "TRIPLEDES", "3DES", "BLOWFISH", "CHACHA"]):
        return "Symmetric"
    if any(k in upper for k in ["BCRYPT", "ARGON2", "PBKDF2", "SCRYPT"]):
        return "KDF"
    if "HMAC" in upper or upper.startswith("HS"):
        return "MAC"
    if "ML-KEM" in upper or "KYBER" in upper:
        return "PQC KEM"
    if "ML-DSA" in upper or "SLH-DSA" in upper or "DILITHIUM" in upper or "SPHINCS" in upper:
        return "PQC Signature"
    if "DH" in upper:
        return "Finite-field DH"
    if "TLS" in upper or "SSL" in upper:
        return "Protocol"
    return "Other"
