import re
from pathlib import Path
from app.scanner.normalizer import normalize_algorithm
from app.scanner.signature_registry import RULES_BY_LANGUAGE
from app.utils.security import redact_secrets

class GenericRegexScanner:
    def __init__(self, language):
        self.language = language
        fallback_language = {"typescript": "javascript", "html": "javascript", "kotlin": "java", "scala": "java"}.get(language)
        fallback_rules = RULES_BY_LANGUAGE.get(fallback_language, [])
        self.rules = RULES_BY_LANGUAGE.get(language, fallback_rules)

    def scan_file(self, path, source):
        findings = []
        lines = source.splitlines()
        dependency_manifest = self._is_dependency_manifest(path)
        for rule in self.rules:
            if rule.rule_id == "CFG-CRYPTO-DEPENDENCY" and not dependency_manifest:
                continue
            compiled = re.compile(rule.pattern, re.IGNORECASE)
            seen = set()
            for lineno, line in enumerate(lines, start=1):
                if lineno in seen:
                    continue
                match = compiled.search(line)
                if not match:
                    continue
                seen.add(lineno)
                algorithm = self._resolve(line, rule.algorithm)
                key_size = self._key_size(line)
                if key_size and algorithm.upper() == "RSA":
                    algorithm = f"RSA-{key_size}"
                normalized = normalize_algorithm(algorithm)
                findings.append({
                    "language": self.language, "file_path": str(path),
                    "start_line": lineno, "end_line": lineno,
                    "symbol_name": match.group(0), "library_name": rule.library_name,
                    "imported_symbol": rule.imported_symbol,
                    "crypto_operation": rule.crypto_operation,
                    "algorithm": normalized,
                    "algorithm_variant": algorithm,
                    "key_size": key_size,
                    "cryptographic_purpose": rule.cryptographic_purpose,
                    "evidence_type": rule.evidence_type,
                    "evidence_snippet": redact_secrets(line),
                    "detection_rule_id": rule.rule_id,
                    "detection_confidence": rule.detection_confidence,
                })
        return self._dedupe(findings)

    def _is_dependency_manifest(self, path):
        name = Path(path).name.lower()
        return (
            name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                     "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock",
                     "cargo.toml", "cargo.lock", "go.mod", "go.sum", "gemfile",
                     "gemfile.lock", "composer.json", "composer.lock", "pom.xml",
                     "build.gradle", "build.gradle.kts", "packages.config"}
            or name.endswith(".lock")
            or (name.startswith("requirements") and name.endswith(".txt"))
            or name.endswith(".csproj")
        )

    def _resolve(self, line, default):
        matches = re.findall(r"[\x27\x22]([^\x27\x22]+)[\x27\x22]", line)
        matches.extend(re.findall(
            r"\b(?:ML[-_]?KEM(?:[-_]\d+)?|ML[-_]?DSA(?:[-_]\d+)?|SLH[-_]?DSA(?:[-_][A-Z0-9_-]+)?|"
            r"RSA[-_]?\d{3,4}|AES[-_]?(?:128|192|256)?(?:[-_](?:GCM|CBC|CTR|CCM|XTS))?|"
            r"SHA[-_]?(?:1|224|256|384|512|3(?:[-_]?(?:224|256|384|512))?)|"
            r"ECDSA|ECDH|X25519|X448|Ed25519|Ed448|ChaCha20(?:[-_]Poly1305)?|"
            r"TripleDES|3DES|DES|Blowfish|MD5|MD4|BLAKE2[bs])\b", line, re.IGNORECASE))
        for c in matches:
            upper = c.upper()
            if any(t in upper for t in ["ML-KEM","ML-DSA","SLH-DSA","KYBER","DILITHIUM","SPHINCS",
                                        "ECDSA","ECDH","X25519","ED25519","RSA","AES","SHA",
                                        "MD5","DES","BLOWFISH","CHACHA","HMAC","BCRYPT","ARGON2"]):
                return c
        return default

    def _key_size(self, line):
        m = re.search(r"\b(2048|3072|4096|128|192|256|384|521)\b", line)
        return int(m.group(1)) if m else None

    def _dedupe(self, findings):
        seen, unique = set(), []
        for f in findings:
            key = (f["file_path"], f["start_line"], f["algorithm"], f["crypto_operation"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
