# VulnPilot

A Flask-based application for evidence-focused reconnaissance, vulnerability candidate discovery, and reporting in authorized security assessments.

## Overview

The project has been improved from a demo-style scanner into a more maintainable and safer foundation for a VAPT tool. The main changes include:

- centralized configuration model
- normalized finding schema
- safer default scanner settings
- evidence-based vulnerability reporting
- documentation for setup, usage, architecture, and security boundaries

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Open the app at:

```text
http://localhost:5000
```

## Security and Operational Defaults

The scanner now uses safer defaults for:

- timeouts
- retries
- concurrency
- layered scope controls
- consistent user-agent settings
- TLS verification enabled by default

## Important Notice

This tool is intended for authorized security testing only. Do not use it on targets without explicit permission.

## Project Structure

```text
VulnPilot/
├── app.py
├── README.md
├── ARCHITECTURE.md
├── CONFIGURATION.md
├── USAGE.md
├── MODULES.md
├── SECURITY.md
├── .env.example
├── requirements.txt
├── modules/
│   ├── __init__.py
│   ├── config.py
│   ├── database.py
│   ├── finding.py
│   ├── report_generator.py
│   └── scanner.py
├── static/
│   ├── css/
│   ├── js/
│   └── reports/
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── forgot_password.html
│   ├── help.html
│   ├── history.html
│   ├── login.html
│   ├── register.html
│   ├── results.html
│   └── scan.html
├── tests/
│   └── test_scan_models.py
└── vapt.db
```

## Scan Workflow

1. user authenticates
2. target and scan type are submitted
3. scanner phases run in sequence
4. results are normalized into evidence-based findings
5. reports are exported to JSON and PDF-style output

## Key Improvements Already Included

- safer configuration model in [modules/config.py](modules/config.py)
- normalized vulnerability schema in [modules/finding.py](modules/finding.py)
- lower-risk default scan settings in [modules/scanner.py](modules/scanner.py)
- environment-based admin setup in [modules/database.py](modules/database.py)
- regression tests in [tests/test_scan_models.py](tests/test_scan_models.py)

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CONFIGURATION.md](CONFIGURATION.md)
- [USAGE.md](USAGE.md)
- [MODULES.md](MODULES.md)
- [SECURITY.md](SECURITY.md)

## License and Use

This project is intended for ethical security testing and vulnerability discovery in environments where you are authorized to test.
