import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import cbom, classification, feedback, findings, reports, scans
from app.config import get_settings
from app.database.mongodb import database
from app.scanner.repository_loader import SUPPORTED_LANGUAGES

logging.basicConfig(level=get_settings().log_level)
app = FastAPI(title="PQC Exposure & CBOM Audit Platform", version="1.0.0",
              description="Static cryptographic discovery, quantum-risk classification, CBOM generation, and executive reporting.")
app.add_middleware(CORSMiddleware, allow_origins=get_settings().allowed_origins,
                   allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(classification.router)
app.include_router(cbom.router)
app.include_router(reports.router)
app.include_router(feedback.router)

@app.exception_handler(Exception)
async def unhandled(request, exc):
    logging.exception("Unhandled server error")
    return JSONResponse(status_code=500, content={"detail": "An internal server error occurred."})

@app.get("/api/health")
async def health():
    ok = database.ping()
    return {"status": "healthy" if ok else "degraded", "database": ok}

@app.get("/api/config/public")
async def public_config():
    s = get_settings()
    return {"max_upload_size_mb": s.max_upload_size_mb, "max_repository_files": s.max_repository_files,
            "max_file_size_mb": s.max_file_size_mb,
            "supported_languages": SUPPORTED_LANGUAGES,
            "allowed_git_hosts": s.allowed_git_host_list,
            "scan_retention_hours": s.scan_retention_hours,
            "report_retention_hours": s.report_retention_hours}
