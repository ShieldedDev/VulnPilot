# Usage Guide

## Local Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Then open:

```text
http://localhost:5000
```

## Login

The default admin account is configurable through environment variables. If you do not customize `.env`, the app uses a local development default.

## Launching a scan

1. Log in.
2. Open the scan page.
3. Enter a target URL or IP.
4. Choose a scan type.
5. Start the scan.

## Result review

The app exposes:
- live progress polling
- results page
- report download endpoints
- scan history

## Safety reminder

Only test systems that are explicitly authorized for assessment.
