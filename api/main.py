import re
import time
from typing import List, Literal, TypedDict

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="PDF Threat Checker", version="1.0.0")

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
        "pattern": re.compile(r"/OpenAction|/AA\\b", re.IGNORECASE),
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


@app.get("/api/health")
async def health():
    return {"ok": True}


@app.post("/api/scan", response_model=ScanResponse)
async def scan_pdf(file: UploadFile = File(...)):
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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=7800, reload=True)
