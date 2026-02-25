from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers.health import router as health_router
from app.routers.lookup import router as lookup_router
from app.routers.ui import router as ui_router

app = FastAPI(title="Live Threat Dashboard API", version="0.1.0")

ui_dir = Path(__file__).resolve().parent / "ui"
app.mount("/ui", StaticFiles(directory=ui_dir), name="ui")

app.include_router(ui_router)
app.include_router(health_router)
app.include_router(lookup_router)
