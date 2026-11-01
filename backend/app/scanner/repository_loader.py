import os, shutil, subprocess, zipfile
from pathlib import Path
from app.config import get_settings
from app.utils.security import is_safe_public_url

EXCLUDED_DIRS = {".git",".hg",".svn","node_modules","venv",".venv","__pycache__",
                 "dist","build","target",".next",".cache","vendor","coverage","__MACOSX",".idea",".vscode"}
BINARY_EXT = {".png",".jpg",".jpeg",".gif",".ico",".pdf",".zip",".gz",".tar",".jar",
              ".class",".exe",".dll",".so",".dylib",".woff",".woff2",".ttf",".mp4",
              ".mp3",".sqlite",".db"}

SUPPORTED_LANGUAGES = ["python", "javascript", "typescript", "java", "kotlin", "scala", "go", "html",
                       "cpp", "rust", "csharp", "php", "ruby", "swift", "shell", "sql", "config"]
EXTENSION_LANGUAGE = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    ".go": "go",
    ".html": "html", ".htm": "html", ".vue": "html", ".svelte": "html",
    ".c": "cpp", ".h": "cpp", ".cc": "cpp", ".hh": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".rs": "rust",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".swift": "swift", ".m": "cpp",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".sql": "sql",
    ".json": "config", ".yaml": "config", ".yml": "config", ".toml": "config",
    ".ini": "config", ".cfg": "config", ".conf": "config", ".properties": "config",
    ".xml": "config", ".cnf": "config", ".tf": "config", ".hcl": "config", ".gradle": "config",
    ".csproj": "config", ".props": "config", ".targets": "config",
}
SPECIAL_FILE_LANGUAGES = {
    "dockerfile": "config", "makefile": "shell", ".env": "config",
    "requirements.txt": "config", "pipfile": "config", "pipfile.lock": "config",
    "cargo.lock": "config", "go.mod": "config", "go.sum": "config", "yarn.lock": "config",
    "gemfile": "config", "gemfile.lock": "config", "composer.lock": "config",
    "poetry.lock": "config", "build.gradle.kts": "config",
}

def detect_language(path):
    name = Path(path).name.lower()
    if name in SPECIAL_FILE_LANGUAGES or name.startswith(".env.") or name.endswith(".lock") or (name.startswith("requirements") and name.endswith(".txt")):
        return SPECIAL_FILE_LANGUAGES.get(name, "config")
    return EXTENSION_LANGUAGE.get(Path(path).suffix.lower())

class RepositoryValidationError(Exception):
    pass

def _safe_member_path(workspace, member_name):
    clean = member_name.replace("\\", "/").lstrip("/")
    target = (workspace / clean).resolve()
    ws_resolved = str(workspace.resolve())
    if not (str(target).startswith(ws_resolved + os.sep) or str(target) == ws_resolved):
        raise RepositoryValidationError(f"Unsafe archive path: {member_name}")
    return target

def extract_zip(archive_path, workspace, return_stats=False):
    settings = get_settings()
    max_extracted = settings.max_extracted_size_mb * 1024 * 1024
    max_files = settings.max_repository_files
    max_file = settings.max_file_size_mb * 1024 * 1024
    total, actual_total, count, skipped_large = 0, 0, 0, 0
    try:
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename.replace("\\", "/").lstrip("/")
                parts = Path(name).parts
                if not parts or ".." in parts or any(p.startswith("/") for p in parts):
                    raise RepositoryValidationError("Path traversal detected in archive")
                if any(p in EXCLUDED_DIRS for p in parts):
                    continue
                if info.file_size > max_file:
                    skipped_large += 1
                    continue
                total += info.file_size
                if total > max_extracted:
                    raise RepositoryValidationError("Decompressed repository exceeds size limit")
                count += 1
                if count > max_files:
                    raise RepositoryValidationError("Repository exceeds file-count limit")
                target = _safe_member_path(workspace, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("wb") as dst:
                    actual_file = 0
                    while chunk := src.read(1024 * 1024):
                        actual_file += len(chunk)
                        actual_total += len(chunk)
                        if actual_file > max_file:
                            raise RepositoryValidationError("Archive entry exceeds file size limit")
                        if actual_total > max_extracted:
                            raise RepositoryValidationError("Decompressed repository exceeds size limit")
                        dst.write(chunk)
        if return_stats:
            return {"extracted_files": count, "skipped_large_files": skipped_large}
        return count
    except zipfile.BadZipFile as exc:
        raise RepositoryValidationError("Invalid ZIP archive") from exc

def clone_public_repository(url, workspace):
    settings = get_settings()
    if not is_safe_public_url(url, settings.allowed_git_host_list):
        raise RepositoryValidationError("Repository URL is not allowed or resolves to a blocked network")
    if any(t in url for t in ["@", "//user:", "//user@"]):
        raise RepositoryValidationError("Embedded credentials are not permitted")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}
    try:
        subprocess.run(["git","clone","--depth=1","--single-branch","--no-recurse-submodules",
                        "--quiet",url,str(workspace)], check=True,
                       timeout=settings.clone_timeout_seconds, env=env, capture_output=True)
    except subprocess.TimeoutExpired as exc:
        raise RepositoryValidationError("Repository clone timed out") from exc
    except subprocess.CalledProcessError as exc:
        raise RepositoryValidationError("Repository clone failed") from exc

    # Apply the same repository-wide resource limits to Git checkouts as ZIP uploads.
    # The clone is removed by the caller if a limit is exceeded.
    max_files = settings.max_repository_files
    max_bytes = settings.max_clone_size_mb * 1024 * 1024
    total_files = total_bytes = 0
    for root, dirs, names in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS or d == ".git"]
        for name in names:
            path = Path(root) / name
            try:
                if path.is_symlink():
                    continue
                is_git_metadata = ".git" in path.relative_to(workspace).parts
                if not is_git_metadata:
                    total_files += 1
                total_bytes += path.stat().st_size
            except OSError:
                continue
            if total_files > max_files:
                raise RepositoryValidationError("Repository exceeds file-count limit")
            if total_bytes > max_bytes:
                raise RepositoryValidationError("Cloned repository exceeds size limit")

def discover_source_files(workspace, languages):
    selected = set(languages)
    files, skipped, total = [], 0, 0
    max_file = get_settings().max_file_size_mb * 1024 * 1024
    max_files = get_settings().max_repository_files
    for root, dirs, names in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for name in names:
            total += 1
            path = Path(root) / name
            language = detect_language(path)
            if path.suffix.lower() in BINARY_EXT:
                skipped += 1
                continue
            if language not in selected:
                skipped += 1
                continue
            try:
                if path.is_symlink():
                    skipped += 1
                    continue
                if path.stat().st_size > max_file:
                    skipped += 1
                    continue
                files.append(path)
            except OSError:
                skipped += 1
                continue
    files = sorted(files)
    if len(files) > max_files:
        skipped += len(files) - max_files
        files = files[:max_files]
    return files, skipped, total

def iter_source_files(workspace, languages):
    return discover_source_files(workspace, languages)[0]

def cleanup_workspace(workspace):
    shutil.rmtree(workspace, ignore_errors=True)
