from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from app.services.scan_service import scan_service

router = APIRouter(prefix="/api/scans", tags=["CBOM"])

@router.post("/{scan_id}/cbom/generate")
async def generate_cbom(scan_id: str):
    try:
        result = scan_service.generate_cbom(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Scan or findings not found")
    return {"scan_id": scan_id, "validation": result["validation"],
            "component_count": len(result["cbom"]["components"]),
            "cbom": result["cbom"]}

@router.get("/{scan_id}/cbom/download")
async def download_cbom(scan_id: str):
    p = scan_service.generate_cbom(scan_id)["path"]
    return FileResponse(p, media_type="application/json", filename=f"{scan_id}-cbom.json")

@router.get("/{scan_id}/cbom/validate")
async def validate_cbom(scan_id: str):
    return scan_service.generate_cbom(scan_id)["validation"]
