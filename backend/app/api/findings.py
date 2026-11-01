from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from app.database.mongodb import database
from app.services.scan_service import scan_service

router = APIRouter(prefix="/api/scans", tags=["Findings"])

@router.get("/{scan_id}/findings")
async def get_findings(scan_id: str, classification: str = None, language: str = None,
                       algorithm: str = None, severity: str = None, confidence: str = None):
    if not database.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return database.get_findings(scan_id, classification, language, algorithm, severity, confidence)

@router.get("/{scan_id}/findings/{finding_id}")
async def get_finding(scan_id: str, finding_id: str):
    f = database.get_finding(scan_id, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f

@router.get("/{scan_id}/findings/export")
async def export_findings(scan_id: str, format: str = "csv"):
    if format not in {"csv","json"}:
        raise HTTPException(status_code=400, detail="Unsupported export format")
    if format == "csv":
        content, mt, fn = scan_service.export_findings_csv(scan_id), "text/csv", f"{scan_id}-findings.csv"
    else:
        content, mt, fn = scan_service.export_findings_json(scan_id), "application/json", f"{scan_id}-findings.json"
    return Response(content=content, media_type=mt,
                    headers={"Content-Disposition": f'attachment; filename="{fn}"'})
