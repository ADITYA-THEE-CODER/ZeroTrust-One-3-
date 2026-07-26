from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os
from app.core.ai_engine import run_unified_scanner

app = FastAPI(
    title="ZeroTrust One Platform",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

class ScanRequest(BaseModel):
    scan_type: str
    content: str

@app.get("/", response_class=FileResponse)
async def serve_homepage():
    if os.path.exists("static/index.html"):
        return FileResponse("static/index.html")
    return {"status": "online", "message": "Website HTML file missing in static/ folder"}

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content=b"", media_type="image/x-icon")

@app.post("/api/v1/scan")
async def scan_payload(payload: ScanRequest):
    if not payload.content.strip():
        raise HTTPException(status_code=400, detail="Scan content cannot be empty.")
    
    result = await run_unified_scanner(payload.content, payload.scan_type)
    return {
        "status": "success",
        "input_type": payload.scan_type,
        "analysis": result
    }
