"""Router for health checks and system status."""

from pathlib import Path
from fastapi import APIRouter, status
from ..schemas import HealthResponse
from ..config import MODEL_DIR, DATABASE_PATH
from ..db.database import get_db_connection

router = APIRouter(prefix="/api", tags=["System"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Check system and component health",
)
async def check_health():
    """Returns the operational status of all backend subsystems."""
    # Check ML model files
    text_model_file = MODEL_DIR / "saved_model" / "text_scam_pipeline.joblib"
    url_model_file = MODEL_DIR / "saved_model" / "url_phishing_pipeline.joblib"

    text_status = "loaded" if text_model_file.exists() else "missing_model_file"
    url_status = "loaded" if url_model_file.exists() else "missing_model_file"

    # Check database connectivity
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "healthy",
        "components": {
            "rule_engine": "online",
            "text_model": text_status,
            "url_model": url_status,
            "database": db_status,
            "llm_service": "fallback_ready",
        },
        "version": "1.0.0",
    }
