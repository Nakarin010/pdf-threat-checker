import sys
from pathlib import Path

# Add the project root to the python path so we can import api.main
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

def test_health_check():
    """Verify the health endpoint returns OK."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert "vt_configured" in data
    assert isinstance(data["vt_configured"], bool)

def test_upload_clean_pdf():
    """Verify that a simple clean PDF is detected as clean."""
    # Create a minimal valid PDF header
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF"
    files = {"file": ("clean.pdf", pdf_content, "application/pdf")}
    
    response = client.post("/api/scan", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "clean"
    assert data["checks"] > 0
    assert data["findings"] == []
    assert data["pdf_header_valid"] is True

def test_upload_suspicious_pdf():
    """Verify that a PDF with JavaScript keywords is flagged."""
    # Create a PDF content with "JavaScript" trigger
    pdf_content = b"%PDF-1.4\n/Type /Catalog /JavaScript (alert('hacked'))"
    files = {"file": ("suspicious.pdf", pdf_content, "application/pdf")}
    
    response = client.post("/api/scan", files=files)
    assert response.status_code == 200
    data = response.json()
    
    # Expect at least a warning or high severity finding
    assert data["status"] in ["warning", "caution"]
    findings = data["findings"]
    assert any(f["message"] == "Embedded JavaScript found" for f in findings)

def test_upload_invalid_file_type():
    """Verify that non-PDF files are rejected."""
    files = {"file": ("image.png", b"fake png content", "image/png")}
    response = client.post("/api/scan", files=files)
    assert response.status_code == 400
    assert "Only PDF files are allowed" in response.json()["detail"]

def test_upload_empty_file():
    """Verify handling of empty files."""
    files = {"file": ("empty.pdf", b"", "application/pdf")}
    response = client.post("/api/scan", files=files)
    assert response.status_code == 400
    assert "Empty file" in response.json()["detail"]
