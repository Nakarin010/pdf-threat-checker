# PDF Threat Checker

A lightweight web application for scanning PDFs and URLs for potential security threats using heuristic analysis and VirusTotal integration.

## Main Functions

- **PDF Heuristic Scanning** - Detects embedded JavaScript, launch actions, auto-run triggers, embedded files, rich media, and external URIs
- **VirusTotal Integration** - Scans PDFs and URLs against 70+ security vendors
- **Dual Scan Modes** - Quick (heuristics only) or Full (heuristics + VirusTotal)
- **URL Reputation Check** - Detects phishing, malware distribution, C&C servers, and malicious scripts

## Architecture

```
├── api/
│   └── main.py          # FastAPI backend with scan endpoints
├── index.html           # Single-page frontend application
├── tests/               # API tests
└── requirements.txt     # Python dependencies
```

**Stack:**
- Backend: FastAPI (Python)
- Frontend: Vanilla HTML/CSS/JavaScript
- API: VirusTotal API v3
- Server: Uvicorn ASGI server

## How to Use

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

### Configuration (Optional)

Create a `.env` file in the root directory for VirusTotal integration:

```bash
VIRUSTOTAL=your_api_key_here
```

> Without a VirusTotal API key, only heuristic scanning will be available.

### Run the Server

```bash
# Option 1: Using the main script
python api/main.py

# Option 2: Using uvicorn directly
uvicorn api.main:app --host 0.0.0.0 --port 8081 --reload
```

### Access the Application

Open your browser and navigate to:
```
http://localhost:8081
```

## API Endpoints

- `GET /` - Serve frontend
- `GET /api/health` - Health check
- `POST /api/scan` - Heuristic PDF scan
- `POST /api/scan-vt` - Full PDF scan with VirusTotal
- `POST /api/url-scan` - URL scan with VirusTotal

## Testing

```bash
pytest tests/
```
