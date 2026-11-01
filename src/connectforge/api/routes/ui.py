"""The web page and its static files."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from connectforge.settings import STATIC

router = APIRouter()


# Browsers must re-check the page files on every load (a cheap 304 when unchanged), so an update to the
# UI is never hidden behind an old cached copy.
NO_CACHE = {"Cache-Control": "no-cache"}


@router.get("/")
def index():
    return FileResponse(STATIC / "index.html", headers=NO_CACHE)


@router.get("/static/{name}")
def static(name: str):
    path = (STATIC / name).resolve()
    if path.parent != STATIC.resolve() or not path.exists():
        raise HTTPException(404)
    return FileResponse(path, headers=NO_CACHE)
