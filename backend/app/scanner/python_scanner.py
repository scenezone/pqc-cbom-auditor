import ast, re
from pathlib import Path
from app.scanner.normalizer import normalize_algorithm
from app.scanner.signature_registry import RULES_BY_LANGUAGE
from app.utils.security import redact_secrets

class PythonCryptoScanner:
    language = "python"

    def scan_file(self, path, source):
        findings = []
        try:
            tree = ast.parse(source)
            findings = self._scan_ast(tree, path, source)
        except SyntaxError:
            pass

        # Regex fallback / supplement for dynamic patterns or files with syntax issues
        regex_findings = self._scan_regex(path, source)
        findings.extend(regex_findings)

        return self._dedupe(findings)

    def _scan_ast(self, tree, path, source):
        findings = []
        imported = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imported[a.asname or a.name] = a.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for a in node.names:
                    imported[a.asname or a.name] = f"{module}.{a.name}"

        rules = RULES_BY_LANGUAGE[self.language]
        lines = source.splitlines()

        for node in ast.walk(tree):
            call_node = None
            if isinstance(node, ast.Call):
                call_node = node
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                call_node = node.value

            if call_node is None:
                continue

            func_text = self._expr(call_node.func)
            if not func_text:
                continue

            full_call_text = self._expr(call_node)
            lineno = getattr(node, "lineno", getattr(call_node, "lineno", 1))
            line_snippet = lines[lineno - 1] if 1 <= lineno <= len(lines) else ""

            resolved_func = self._resolve_import(func_text, imported)
            key_size = self._key_size(full_call_text) or self._key_size(line_snippet)

            for rule in rules:
                if rule.language != self.language:
                    continue

                matched = (
                    re.search(rule.pattern, func_text, re.IGNORECASE) or
                    re.search(rule.pattern, resolved_func, re.IGNORECASE) or
                    re.search(rule.pattern, full_call_text, re.IGNORECASE)
                )
                if not matched:
                    continue

                raw_algo = rule.algorithm
                if key_size and raw_algo == "RSA":
                    raw_algo = f"RSA-{key_size}"
                elif raw_algo in ("Hash", "SHA", "Unknown"):
                    raw_algo = self._resolve_algo(full_call_text, line_snippet, rule.algorithm)

                algo = normalize_algorithm(raw_algo)

                findings.append({
                    "language": self.language,
                    "file_path": str(path),
                    "start_line": lineno,
                    "end_line": getattr(node, "end_lineno", lineno),
                    "symbol_name": func_text or rule.imported_symbol,
                    "library_name": rule.library_name,
                    "imported_symbol": resolved_func or rule.imported_symbol,
                    "crypto_operation": rule.crypto_operation,
                    "algorithm": algo,
                    "algorithm_variant": raw_algo,
                    "key_size": key_size,
                    "cryptographic_purpose": rule.cryptographic_purpose,
                    "evidence_type": rule.evidence_type,
                    "evidence_snippet": redact_secrets(line_snippet),
                    "detection_rule_id": rule.rule_id,
                    "detection_confidence": rule.detection_confidence,
                })

        return findings

    def _scan_regex(self, path, source):
        findings = []
        rules = RULES_BY_LANGUAGE.get(self.language, [])
        lines = source.splitlines()
        for rule in rules:
            compiled = re.compile(rule.pattern, re.IGNORECASE)
            seen = set()
            for lineno, line in enumerate(lines, start=1):
                if lineno in seen:
                    continue
                match = compiled.search(line)
                if not match:
                    continue
                seen.add(lineno)
                key_size = self._key_size(line)
                raw_algo = rule.algorithm
                if key_size and raw_algo == "RSA":
                    raw_algo = f"RSA-{key_size}"
                elif raw_algo in ("Hash", "SHA", "Unknown"):
                    raw_algo = self._resolve_algo(line, line, rule.algorithm)

                algo = normalize_algorithm(raw_algo)
                findings.append({
                    "language": self.language,
                    "file_path": str(path),
                    "start_line": lineno,
                    "end_line": lineno,
                    "symbol_name": match.group(0),
                    "library_name": rule.library_name,
                    "imported_symbol": rule.imported_symbol,
                    "crypto_operation": rule.crypto_operation,
                    "algorithm": algo,
                    "algorithm_variant": raw_algo,
                    "key_size": key_size,
                    "cryptographic_purpose": rule.cryptographic_purpose,
                    "evidence_type": rule.evidence_type,
                    "evidence_snippet": redact_secrets(line),
                    "detection_rule_id": rule.rule_id,
                    "detection_confidence": rule.detection_confidence,
                })
        return findings

    def _resolve_import(self, func_text, imported):
        if func_text in imported:
            return imported[func_text]
        parts = func_text.split(".", 1)
        if len(parts) == 2 and parts[0] in imported:
            return f"{imported[parts[0]]}.{parts[1]}"
        return func_text

    def _resolve_algo(self, text, line, default):
        matches = re.findall(r"[\x27\x22]([^\x27\x22]+)[\x27\x22]", text + " " + line)
        for c in matches:
            upper = c.upper()
            if any(t in upper for t in ["ML-KEM","ML-DSA","SLH-DSA","KYBER","DILITHIUM","SPHINCS",
                                        "ECDSA","ECDH","X25519","ED25519","RSA","AES","SHA",
                                        "MD5","DES","BLOWFISH","CHACHA","HMAC","BCRYPT","ARGON2"]):
                return c
        m = re.search(r"\b(sha256|sha384|sha512|sha224|sha1|md5|aes|des)\b", (text + " " + line).lower())
        if m:
            return m.group(1).upper()
        return default

    def _expr(self, node):
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    def _snippet(self, source, line):
        lines = source.splitlines()
        return lines[line-1] if 1 <= line <= len(lines) else ""

    def _key_size(self, text):
        m = re.search(r"\b(2048|3072|4096|128|192|256|384|521)\b", text)
        return int(m.group(1)) if m else None

    def _dedupe(self, findings):
        seen, unique = set(), []
        for f in findings:
            key = (f["file_path"], f["start_line"], f["algorithm"], f["crypto_operation"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
