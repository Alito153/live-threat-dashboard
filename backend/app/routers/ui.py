from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse


router = APIRouter(include_in_schema=False)
ui_dir = Path(__file__).resolve().parent.parent / "ui"


@router.get("/")
async def ui_home() -> FileResponse:
    return FileResponse(ui_dir / "index.html")
