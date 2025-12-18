import hashlib
import os
import re
import time
from pathlib import Path
from typing import List, Literal, Optional, TypedDict

import aiohttp
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

# Load environment variables from .env file
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL")
VT_API_BASE = "https://www.virustotal.com/api/v3"

app = FastAPI(title="PDF Threat Checker", version="2.0.0")

# Allow same-origin and local dev; adjust origins if hosting elsewhere.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class Finding(TypedDict):
    message: str
    severity: Literal["high", "medium", "info"]


class ScanResponse(TypedDict):
    name: str
    size_bytes: int
    size_human: str
    checks: int
    findings: List[Finding]
    status: Literal["clean", "caution", "warning"]
    status_label: str
    time_ms: int
    pdf_header_valid: bool


class VTStats(TypedDict):
    malicious: int
    suspicious: int
    harmless: int
    undetected: int


class VTScanResponse(TypedDict):
    name: str
    size_bytes: int
    size_human: str
    sha256: str
    heuristic_findings: List[Finding]
    heuristic_status: Literal["clean", "caution", "warning"]
    vt_stats: Optional[VTStats]
    vt_status: Optional[Literal["clean", "caution", "warning"]]
    vt_permalink: Optional[str]
    time_ms: int
    pdf_header_valid: bool


class URLScanResponse(TypedDict):
    url: str
    vt_stats: Optional[VTStats]
    vt_status: Optional[Literal["clean", "caution", "warning"]]
    vt_permalink: Optional[str]
    categories: Optional[dict]
    time_ms: int


heuristics = [
    {
        "key": "javascript",
        "pattern": re.compile(r"/JavaScript|/JS", re.IGNORECASE),
        "message": "Embedded JavaScript found",
        "severity": "high",
    },
    {
        "key": "launch",
        "pattern": re.compile(r"/Launch", re.IGNORECASE),
        "message": "Launch action detected",
        "severity": "high",
    },
    {
        "key": "openAction",
        "pattern": re.compile(r"/OpenAction|/AA\b", re.IGNORECASE),
        "message": "Auto-run action on open",
        "severity": "medium",
    },
    {
        "key": "embeddedFile",
        "pattern": re.compile(r"/EmbeddedFile|/Filespec", re.IGNORECASE),
        "message": "Embedded file present",
        "severity": "medium",
    },
    {
        "key": "richMedia",
        "pattern": re.compile(r"/RichMedia|/MediaClip", re.IGNORECASE),
        "message": "Rich media stream detected",
        "severity": "medium",
    },
    {
        "key": "uri",
        "pattern": re.compile(r"/URI|http://|https://", re.IGNORECASE),
        "message": "External links present",
        "severity": "info",
    },
]


def human_size(bytes_len: int) -> str:
    if bytes_len == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    idx = min(int((bytes_len).bit_length() / 10), len(units) - 1)
    return f"{bytes_len / (1024 ** idx):.1f} {units[idx]}"


def evaluate_status(findings: List[Finding]) -> str:
    if any(f["severity"] == "high" for f in findings):
        return "warning"
    if any(f["severity"] == "medium" for f in findings):
        return "caution"
    return "clean"


def evaluate_vt_status(stats: VTStats) -> str:
    """Evaluate status based on VirusTotal detection stats."""
    if stats["malicious"] > 0:
        return "warning"
    if stats["suspicious"] > 0:
        return "caution"
    return "clean"


async def vt_get_file_report(sha256: str) -> Optional[dict]:
    """Get file report from VirusTotal by SHA256 hash."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{VT_API_BASE}/files/{sha256}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            if resp.status == 200:
                return await resp.json()
            elif resp.status == 404:
                return None  # File not found in VT database
            else:
                return None


async def vt_upload_file(file_bytes: bytes, filename: str) -> Optional[str]:
    """Upload file to VirusTotal and return analysis ID."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = aiohttp.FormData()
    data.add_field("file", file_bytes, filename=filename, content_type="application/octet-stream")
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{VT_API_BASE}/files",
            headers=headers,
            data=data,
            timeout=aiohttp.ClientTimeout(total=60)
        ) as resp:
            if resp.status == 200:
                result = await resp.json()
                return result.get("data", {}).get("id")
            return None


async def vt_get_analysis(analysis_id: str) -> Optional[dict]:
    """Get analysis status/result from VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{VT_API_BASE}/analyses/{analysis_id}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            if resp.status == 200:
                return await resp.json()
            return None


async def vt_scan_url(url: str) -> Optional[str]:
    """Submit URL to VirusTotal for scanning, return analysis ID."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{VT_API_BASE}/urls",
            headers=headers,
            data={"url": url},
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            if resp.status == 200:
                result = await resp.json()
                return result.get("data", {}).get("id")
            return None


async def vt_get_url_report(url_id: str) -> Optional[dict]:
    """Get URL report from VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{VT_API_BASE}/urls/{url_id}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            if resp.status == 200:
                return await resp.json()
            return None


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve the single-page frontend when running locally via uvicorn."""
    index_path = Path(__file__).resolve().parent.parent / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return HTMLResponse(index_path.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "vt_configured": bool(VIRUSTOTAL_API_KEY)
    }


@app.post("/api/scan", response_model=ScanResponse)
async def scan_pdf(file: UploadFile = File(...)):
    """Original heuristic-only scan endpoint."""
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed.")

    start = time.perf_counter()
    raw_bytes = await file.read()

    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file.")

    pdf_header_valid = raw_bytes.startswith(b"%PDF")
    text = raw_bytes.decode("latin1", errors="ignore")

    findings: List[Finding] = [
        {"message": rule["message"], "severity": rule["severity"]}  # type: ignore
        for rule in heuristics
        if rule["pattern"].search(text)
    ]

    status = evaluate_status(findings)
    status_label = "Clean" if status == "clean" else "Caution" if status == "caution" else "Warning"

    response: ScanResponse = {
        "name": file.filename or "upload.pdf",
        "size_bytes": len(raw_bytes),
        "size_human": human_size(len(raw_bytes)),
        "checks": len(heuristics),
        "findings": findings,
        "status": status,  # type: ignore
        "status_label": status_label,
        "time_ms": max(1, int((time.perf_counter() - start) * 1000)),
        "pdf_header_valid": pdf_header_valid,
    }

    return JSONResponse(response)


@app.post("/api/scan-vt")
async def scan_pdf_virustotal(file: UploadFile = File(...)):
    """Enhanced scan using both heuristics and VirusTotal API."""
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed.")

    start = time.perf_counter()
    raw_bytes = await file.read()

    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file.")

    # Calculate SHA256
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    
    pdf_header_valid = raw_bytes.startswith(b"%PDF")
    text = raw_bytes.decode("latin1", errors="ignore")

    # Heuristic scan
    findings: List[Finding] = [
        {"message": rule["message"], "severity": rule["severity"]}  # type: ignore
        for rule in heuristics
        if rule["pattern"].search(text)
    ]
    heuristic_status = evaluate_status(findings)

    # VirusTotal scan
    vt_stats: Optional[VTStats] = None
    vt_status: Optional[str] = None
    vt_permalink: Optional[str] = None

    if VIRUSTOTAL_API_KEY:
        # First, try to get existing report
        vt_report = await vt_get_file_report(sha256)
        
        if vt_report:
            attrs = vt_report.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            vt_stats = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
            vt_status = evaluate_vt_status(vt_stats)
            vt_permalink = f"https://www.virustotal.com/gui/file/{sha256}"
        else:
            # File not in VT database, upload it
            analysis_id = await vt_upload_file(raw_bytes, file.filename or "upload.pdf")
            if analysis_id:
                # Poll for results (max 30 seconds)
                for _ in range(6):
                    await asyncio.sleep(5)
                    analysis = await vt_get_analysis(analysis_id)
                    if analysis:
                        status_attr = analysis.get("data", {}).get("attributes", {}).get("status")
                        if status_attr == "completed":
                            stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
                            vt_stats = {
                                "malicious": stats.get("malicious", 0),
                                "suspicious": stats.get("suspicious", 0),
                                "harmless": stats.get("harmless", 0),
                                "undetected": stats.get("undetected", 0),
                            }
                            vt_status = evaluate_vt_status(vt_stats)
                            vt_permalink = f"https://www.virustotal.com/gui/file/{sha256}"
                            break

    response: VTScanResponse = {
        "name": file.filename or "upload.pdf",
        "size_bytes": len(raw_bytes),
        "size_human": human_size(len(raw_bytes)),
        "sha256": sha256,
        "heuristic_findings": findings,
        "heuristic_status": heuristic_status,  # type: ignore
        "vt_stats": vt_stats,
        "vt_status": vt_status,  # type: ignore
        "vt_permalink": vt_permalink,
        "time_ms": max(1, int((time.perf_counter() - start) * 1000)),
        "pdf_header_valid": pdf_header_valid,
    }

    return JSONResponse(response)


@app.post("/api/url-scan")
async def scan_url(url: str = Form(...)):
    """Scan a URL using VirusTotal API."""
    import base64
    
    start = time.perf_counter()
    
    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="VirusTotal API key not configured. Add VIRUSTOTAL to .env file."
        )
    
    # Validate URL format
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL format. Must start with http:// or https://")

    vt_stats: Optional[VTStats] = None
    vt_status: Optional[str] = None
    vt_permalink: Optional[str] = None
    categories: Optional[dict] = None
    
    # Generate URL ID (base64 of URL without padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    
    # First try to get existing report
    vt_report = await vt_get_url_report(url_id)
    
    if vt_report and vt_report.get("data"):
        attrs = vt_report.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        vt_stats = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
        vt_status = evaluate_vt_status(vt_stats)
        vt_permalink = attrs.get("url") and f"https://www.virustotal.com/gui/url/{url_id}"
        categories = attrs.get("categories")
    else:
        # Submit URL for scanning
        analysis_id = await vt_scan_url(url)
        if analysis_id:
            # Poll for results (max 30 seconds)
            import asyncio
            for _ in range(6):
                await asyncio.sleep(5)
                analysis = await vt_get_analysis(analysis_id)
                if analysis:
                    status_attr = analysis.get("data", {}).get("attributes", {}).get("status")
                    if status_attr == "completed":
                        stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
                        vt_stats = {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0),
                        }
                        vt_status = evaluate_vt_status(vt_stats)
                        vt_permalink = f"https://www.virustotal.com/gui/url/{url_id}"
                        break

    response: URLScanResponse = {
        "url": url,
        "vt_stats": vt_stats,
        "vt_status": vt_status,  # type: ignore
        "vt_permalink": vt_permalink,
        "categories": categories,
        "time_ms": max(1, int((time.perf_counter() - start) * 1000)),
    }

    return JSONResponse(response)


if __name__ == "__main__":
    import asyncio
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8081, reload=True)
