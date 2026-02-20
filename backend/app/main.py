from fastapi import FastAPI

from app.routers.health import router as health_router
from app.routers.lookup import router as lookup_router

app = FastAPI(title="Live Threat Dashboard API", version="0.1.0")

app.include_router(health_router)
app.include_router(lookup_router)