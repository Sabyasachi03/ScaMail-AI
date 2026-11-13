"""API routers package."""

from .scan import router as scan_router
from .history import router as history_router
from .health import router as health_router

__all__ = ["scan_router", "history_router", "health_router"]
