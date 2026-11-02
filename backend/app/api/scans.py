import uuid
from pathlib import Path
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from app.config import get_settings
from app.database.mongodb import database
from app.schemas import RepositoryURLScanRequest, TLSEndpointScanRequest
from app.scanner.repository_loader import (SUPPORTED_LANGUAGES, RepositoryValidationError, cleanup_workspace,
                                           clone_public_repository, extract_zip)
from app.services.job_manager import job_manager
from app.services.scan_service import scan_service
from app.tls.probe import normalize_tls_target_url

router = APIRouter(prefix="/api/scans", tags=["Scanning"])

def _public_endpoint_context(scan):
    result = dict(scan)
    if result.get("repository_source_type") == "https_endpoint" or result.get("tls_target_url"):
        context = dict(result.get("business_context") or {})
        context["external_exposure"] = "Public"
        result["business_context"] = context
    return result

async def _create_repository_scan(
    source_type,
    scan_name,
    business_context,
    tls_target_url,
    file=None,
    repository_url=None,
    scan_configuration=None,
):
    settings = get_settings()
    try:
        tls_target = normalize_tls_target_url(tls_target_url) if tls_target_url.strip() else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if source_type not in {"zip", "github"}:
        raise HTTPException(status_code=400, detail="Source type must be 'zip' or 'github'")
    if source_type == "zip" and file is None:
        raise HTTPException(status_code=400, detail="Select a ZIP archive")
    if source_type == "github" and not (repository_url or "").strip():
        if file is not None:
            await file.close()
        raise HTTPException(status_code=400, detail="Enter a public Git repository URL")
    if source_type == "github" and file is not None:
        await file.close()
        raise HTTPException(status_code=400, detail="Provide either a repository URL or a ZIP archive, not both")
    if source_type == "zip" and (repository_url or "").strip():
        await file.close()
        raise HTTPException(status_code=400, detail="Provide either a repository URL or a ZIP archive, not both")

    scan_id = str(uuid.uuid4())
    workspace = settings.scan_temp_directory / scan_id / "source"
    workspace.mkdir(parents=True, exist_ok=True)
    try:
        intake = {"skipped_large_files": 0}
        if source_type == "zip":
            archive = workspace.parent / "repository.zip"
            upload_limit = settings.max_upload_size_mb * 1024 * 1024
            uploaded = 0
            oversized_upload = False
            try:
                with archive.open("wb") as destination:
                    while chunk := await file.read(1024 * 1024):
                        uploaded += len(chunk)
                        if uploaded > upload_limit:
                            oversized_upload = True
                            break
                        destination.write(chunk)
            finally:
                await file.close()
            if oversized_upload:
                raise HTTPException(status_code=413, detail="Upload exceeds maximum allowed size")
            intake = extract_zip(archive, workspace, return_stats=True)
            repository_source_type = "zip_upload"
        else:
            clone_public_repository(str(repository_url), workspace)
            repository_source_type = "public_git"
    except RepositoryValidationError as exc:
        cleanup_workspace(workspace.parent)
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        cleanup_workspace(workspace.parent)
        raise
    except Exception:
        cleanup_workspace(workspace.parent)
        raise

    configuration = scan_configuration or {
        "languages": SUPPORTED_LANGUAGES,
        "scan_depth": 10,
        "include_tests": False,
    }
    effective_business_context = dict(business_context or {})
    if tls_target:
        # The endpoint probe rejects non-public IPs, so its assessed exposure
        # must not inherit the repository form's default of Internal.
        effective_business_context["external_exposure"] = "Public"
    scan = database.create_scan({
        "scan_id": scan_id, "repository_name": scan_name,
        "repository_source_type": repository_source_type,
        "tls_target_url": tls_target,
        "intake_skipped_files": intake["skipped_large_files"],
        "languages": configuration.get("languages", SUPPORTED_LANGUAGES),
        "scan_configuration": configuration,
        "business_context": effective_business_context})
    job_manager.enqueue(scan_id, lambda: scan_service.execute_scan(scan_id, workspace))
    return {"scan_id": scan_id, "status": scan["scan_status"]}


@router.post("/source")
async def scan_repository_source(
    source_type: str = Form(...),
    scan_name: str = Form("Untitled scan"),
    repository_url: str = Form(""),
    file: UploadFile | None = File(None),
    business_criticality: str = Form("Moderate"),
    data_sensitivity: str = Form("Internal"),
    data_retention_horizon: str = Form("1-3 years"),
    external_exposure: str = Form("Internal"),
    tls_target_url: str = Form(""),
):
    return await _create_repository_scan(
        source_type=source_type,
        scan_name=scan_name,
        business_context={"business_criticality": business_criticality,
                          "data_sensitivity": data_sensitivity,
                          "data_retention_horizon": data_retention_horizon,
                          "external_exposure": external_exposure},
        tls_target_url=tls_target_url,
        file=file,
        repository_url=repository_url,
    )


@router.post("/upload")
async def upload_repository(
    file: UploadFile = File(...),
    scan_name: str = Form("Untitled scan"),
    business_criticality: str = Form("Moderate"),
    data_sensitivity: str = Form("Internal"),
    data_retention_horizon: str = Form("1-3 years"),
    external_exposure: str = Form("Internal"),
    tls_target_url: str = Form(""),
):
    return await _create_repository_scan(
        "zip", scan_name,
        {"business_criticality": business_criticality,
         "data_sensitivity": data_sensitivity,
         "data_retention_horizon": data_retention_horizon,
         "external_exposure": external_exposure},
        tls_target_url, file=file,
    )


@router.post("/repository")
async def scan_repository(request: RepositoryURLScanRequest):
    return await _create_repository_scan(
        "github", request.scan_name, request.business_context.model_dump(),
        str(request.tls_target_url) if request.tls_target_url else "",
        repository_url=str(request.repository_url),
        scan_configuration=request.scan_configuration.model_dump(),
    )

@router.post("/https")
async def scan_https_endpoint(request: TLSEndpointScanRequest):
    try:
        tls_target = normalize_tls_target_url(request.target_url)
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    scan_id = str(uuid.uuid4())
    scan = database.create_scan({
        "scan_id": scan_id,
        "repository_name": request.scan_name,
        "repository_source_type": "https_endpoint",
        "tls_target_url": tls_target,
        "languages": [],
        "scan_configuration": {"languages": [], "scan_depth": 0, "include_tests": False},
        "business_context": {**request.business_context.model_dump(), "external_exposure": "Public"},
    })
    job_manager.enqueue(scan_id, lambda: scan_service.execute_scan(scan_id, None))
    return {"scan_id": scan_id, "status": scan["scan_status"]}

@router.get("/{scan_id}/status")
async def scan_status(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _public_endpoint_context(scan)

@router.get("")
@router.get("/")
async def list_scans(limit: int = 100, skip: int = 0):
    return [_public_endpoint_context(scan) for scan in database.list_scans(limit=limit, skip=skip)]

@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    database.delete_scan(scan_id)
    return {"status": "deleted", "scan_id": scan_id}

@router.get("/{scan_id}/summary")
async def scan_summary(scan_id: str):
    scan = database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = scan_service.current_findings(scan_id, scan=scan)
    scan = _public_endpoint_context(scan)
    classifications = {"Quantum Vulnerable":0,"Quantum Resistant Under Current Knowledge":0,"Unknown / Needs Review":0}
    severity = {"Critical":0,"High":0,"Medium":0,"Low":0}
    algorithms, languages = {}, {}
    for f in findings:
        qc = f.get("quantum_classification", "Unknown / Needs Review")
        classifications[qc] = classifications.get(qc, 0) + 1
        sc = f.get("severity_category", "Low")
        severity[sc] = severity.get(sc, 0) + 1
        algorithms[f.get("algorithm", "Unknown")] = algorithms.get(f.get("algorithm", "Unknown"), 0) + 1
        languages[f.get("language", "unknown")] = languages.get(f.get("language", "unknown"), 0) + 1
    priority_findings = [f for f in findings if not (
        f.get("detection_rule_id") == "TLS-HYBRID-GROUP"
        and f.get("quantum_classification") == "Quantum Resistant Under Current Knowledge")]
    return {"scan": scan,
        "counts": {"files_scanned": scan.get("scanned_files",0), "files_skipped": scan.get("skipped_files",0),
                   "findings": len(findings), "unique_assets": len({f["algorithm"] for f in findings if "algorithm" in f}),
                   "quantum_vulnerable": classifications.get("Quantum Vulnerable", 0),
                   "quantum_resistant": classifications.get("Quantum Resistant Under Current Knowledge", 0),
                   "needs_review": classifications.get("Unknown / Needs Review", 0),
                   "high_priority": severity.get("Critical", 0) + severity.get("High", 0)},
        "classification_distribution": classifications, "severity_distribution": severity,
        "algorithm_distribution": algorithms, "language_distribution": languages,
        "top_findings": sorted(priority_findings, key=lambda f: f.get("severity_score", 0), reverse=True)[:10]}
