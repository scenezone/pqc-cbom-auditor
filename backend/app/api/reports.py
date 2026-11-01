from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from app.services.scan_service import scan_service

router = APIRouter(prefix="/api/scans", tags=["Reports"])

@router.post("/{scan_id}/reports/generate")
async def generate_report(scan_id: str):
    if not scan_service.export_findings_json(scan_id):
        raise HTTPException(status_code=404, detail="Scan findings not available")
    p = scan_service.generate_pdf(scan_id)
    return {"scan_id": scan_id, "report_path": p.name, "status": "complete"}

@router.get("/{scan_id}/reports/download")
async def download_report(scan_id: str):
    p = scan_service.generate_pdf(scan_id)
    return FileResponse(p, media_type="application/pdf", filename=f"{scan_id}-executive-report.pdf")
