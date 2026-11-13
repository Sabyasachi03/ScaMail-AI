"""Router for scan history and analytics endpoints."""

from typing import Optional
from fastapi import APIRouter, Query, status
from ..schemas import HistoryResponse, StatsResponse
from ..db.crud import get_scan_history, get_scan_statistics

router = APIRouter(prefix="/api", tags=["History & Analytics"])


@router.get(
    "/history",
    response_model=HistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve paginated scan history",
)
async def fetch_history(
    limit: int = Query(default=20, ge=1, le=100, description="Items per page"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    verdict: Optional[str] = Query(default=None, description="Filter by verdict"),
):
    """Returns past scans with sensitive details redacted."""
    return get_scan_history(limit=limit, offset=offset, verdict=verdict)


@router.get(
    "/stats",
    response_model=StatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve dashboard summary statistics",
)
async def fetch_stats():
    """Returns aggregated metrics for frontend charts and counters."""
    return get_scan_statistics()
