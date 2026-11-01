# PQC Exposure & CBOM Audit Platform

Production-oriented Post-Quantum Cryptography (PQC) exposure assessment and Cryptography Bill of Materials (CBOM) audit platform.

## Quick start

### Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

### Full stack with Docker
```bash
docker compose up --build
```

### Tests
```bash
cd backend
pytest -q
```

## CBOM schema
Download the official CycloneDX 1.7 JSON schema and place it at:
`backend/schemas/cyclonedx-1.7.schema.json`
from https://github.com/CycloneDX/specification/releases (v1.7 JSON schema).

## Security
This application intentionally has no login system. Deploy behind a private network, VPN, or access-controlled reverse proxy. Do not expose repository-upload endpoints publicly.

## Repository scan coverage
Scans inspect Python, JavaScript/TypeScript, Java/Kotlin/Scala, Go, HTML and embedded web code, C/C++, Rust, C#, PHP, Ruby, Swift, shell scripts, SQL, common configuration formats, and dependency manifests. Detection uses curated static signatures, so files are read without executing repository code. Common generated, dependency, and tool directories such as `node_modules`, `vendor`, `dist`, `build`, and `.git` are excluded. Binary assets and files beyond configured size or scan limits are not analyzed.

ZIP uploads are limited by `MAX_UPLOAD_SIZE_MB`, `MAX_EXTRACTED_SIZE_MB`, `MAX_REPOSITORY_FILES`, and `MAX_FILE_SIZE_MB`. Public Git scans use a depth-one checkout of one branch, do not fetch submodules, and enforce `MAX_CLONE_SIZE_MB`, `MAX_REPOSITORY_FILES`, and `MAX_FILE_SIZE_MB`. Private GitHub repositories are not supported.

## Live TLS endpoint assessment
HTTPS endpoint assessment is available as a standalone scan source, so no repository or ZIP archive is required. Repository audits can also include an optional HTTPS endpoint assessment. The probe checks TLS 1.2 and TLS 1.3 independently, tests classic groups and the standardized TLS 1.3 hybrid groups from [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html), inspects the presented leaf certificate, and records cipher-suite IANA identifiers. TLS 1.2 is reported as `not_pqc`; hybrid group support is reported only when a forced-group handshake succeeds. Timeouts are retried once and then marked inconclusive. Findings are available in the audit dashboard, CBOM, PDF report, and findings exports. The probe does not validate the certificate trust chain, and it only inspects the certificate presented during the handshake.

Hybrid-group checks require an OpenSSL build that implements RFC 10024 groups. The backend Docker image installs the system OpenSSL client; deployments using a different image should use OpenSSL 3.5 or later. The TLS target must resolve exclusively to public IP addresses.
