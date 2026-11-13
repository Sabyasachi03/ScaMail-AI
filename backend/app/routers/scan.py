"""Router for scam and phishing analysis endpoint."""

from fastapi import APIRouter, HTTPException, status
from ..schemas import ScanRequest, ScanResponse
from ..services.pipeline import DetectionPipeline

router = APIRouter(prefix="/api", tags=["Detection"])

# Singleton pipeline instance
_pipeline = DetectionPipeline()


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan text and/or URL for scam and phishing threats",
)
async def scan_content(payload: ScanRequest):
    """Primary endpoint for checking suspicious SMS/text messages or URLs.

    Combines:
    1. PII Redaction
    2. Heuristic Rule Checks
    3. Classical Machine Learning Inference
    4. Fusion Scoring Formula
    5. Bilingual Explanations (English & Hindi)
    6. SQLite History Storage
    """
    has_text = bool(payload.text and payload.text.strip())
    has_url = bool(payload.url and payload.url.strip())

    if not has_text and not has_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one of 'text' or 'url' must be provided and non-empty.",
        )

    try:
        result = _pipeline.process(
            text=payload.text,
            url=payload.url,
            language_preference=payload.language_preference or "both",
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing scan pipeline: {str(e)}",
        )
