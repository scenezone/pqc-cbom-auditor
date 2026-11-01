from datetime import datetime, timezone
from fastapi import APIRouter
from app.database.mongodb import database
from app.schemas import FeedbackRequest

router = APIRouter(prefix="/api/feedback", tags=["Feedback"])

@router.post("")
async def submit_feedback(request: FeedbackRequest):
    database.db.feedback.insert_one({**request.model_dump(),
                                     "created_at": datetime.now(timezone.utc)})
    return {"status": "received"}
