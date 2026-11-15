"""FastAPI Main Application for ScaMail AI Backend.

Developed by Aayush (Backend & Integration Engineer).
"""

from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import HOST, PORT, DEBUG
from .db.database import init_db
from .routers import scan_router, history_router, health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events: initialize SQLite database on startup."""
    init_db()
    yield


app = FastAPI(
    title="ScaMail AI — Detection & Decision Support API",
    description=(
        "Hybrid multi-layer scam and phishing detection backend combining "
        "heuristic rules, classical ML classifiers, and bilingual AI explanations."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for React frontend (Vite port 5173, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers first so /api takes priority
app.include_router(scan_router)
app.include_router(history_router)
app.include_router(health_router)

# Mount frontend production build if available, otherwise return welcome JSON
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")
else:
    @app.get("/", tags=["System"])
    async def root():
        """Welcome endpoint pointing to documentation."""
        return {
            "project": "ScaMail AI",
            "version": "1.0.0",
            "documentation": "/docs",
            "endpoints": {
                "scan": "POST /api/scan",
                "history": "GET /api/history",
                "stats": "GET /api/stats",
                "health": "GET /api/health",
            },
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=HOST, port=PORT, reload=DEBUG)
