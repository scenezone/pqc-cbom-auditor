import time, uuid
from app.config import get_settings
from app.scanner.generic_scanner import GenericRegexScanner
from app.scanner.python_scanner import PythonCryptoScanner
from app.scanner.repository_loader import detect_language, discover_source_files

SCANNERS = {
    "python": PythonCryptoScanner(),
    "javascript": GenericRegexScanner("javascript"),
    "typescript": GenericRegexScanner("typescript"),
    "java": GenericRegexScanner("java"),
    "kotlin": GenericRegexScanner("kotlin"),
    "scala": GenericRegexScanner("scala"),
    "go": GenericRegexScanner("go"),
    "html": GenericRegexScanner("html"),
    "cpp": GenericRegexScanner("cpp"),
    "rust": GenericRegexScanner("rust"),
    "csharp": GenericRegexScanner("csharp"),
    "php": GenericRegexScanner("php"),
    "ruby": GenericRegexScanner("ruby"),
    "swift": GenericRegexScanner("swift"),
    "shell": GenericRegexScanner("shell"),
    "sql": GenericRegexScanner("sql"),
    "config": GenericRegexScanner("config"),
}

class ScanEngine:
    def scan_workspace(self, workspace, scan_id, languages, progress_callback=None):
        settings = get_settings()
        started = time.monotonic()
        files, skipped, total_files = discover_source_files(workspace, languages)
        findings, scanned = [], 0

        def process(path):
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return path, [], True
            lang = self._detect(path)
            if lang not in languages or lang not in SCANNERS:
                return path, [], True
            return path, SCANNERS[lang].scan_file(path, source), False

        timed_out = False
        for index, path in enumerate(files):
            if time.monotonic() - started >= settings.max_scan_duration_seconds:
                skipped += len(files) - index
                timed_out = True
                break
            try:
                _, file_findings, was_skipped = process(path)
            except Exception:
                skipped += 1
                continue
            if was_skipped:
                skipped += 1
            else:
                scanned += 1
            for f in file_findings:
                f.update({"finding_id": str(uuid.uuid4()), "scan_id": scan_id})
                findings.append(f)
            if progress_callback:
                progress_callback(scanned, skipped, len(findings))

        stats = {"total_files": total_files, "scanned_files": scanned,
                 "skipped_files": skipped,
                 "incomplete": timed_out or time.monotonic() - started > settings.max_scan_duration_seconds}
        return findings, stats

    def _detect(self, path):
        return detect_language(path) or "unknown"
