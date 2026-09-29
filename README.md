# Advanced VAPT Scanner

A professional Vulnerability Assessment and Penetration Testing (VAPT) web application
built with Python Flask and Vanilla JavaScript.

---

## ⚡ Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation

```bash
# 1. Clone or extract the project
cd vapt_scanner

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

### Access the App
Open your browser: `http://localhost:5000`

### Default Admin Credentials
```
Username: admin
Password: Admin@1234
```

---

## 📁 Project Structure

```
vapt_scanner/
├── app.py                      # Main Flask application
├── requirements.txt
├── vapt.db                     # SQLite database (auto-created)
├── modules/
│   ├── __init__.py
│   ├── scanner.py              # Core VAPT scanning engine
│   ├── report_generator.py     # PDF & JSON report generator
│   └── database.py             # SQLite database handler
├── templates/
│   ├── base.html               # Base layout with navbar
│   ├── login.html
│   ├── register.html
│   ├── forgot_password.html
│   ├── dashboard.html
│   ├── scan.html               # Live scan interface
│   ├── results.html            # Tabbed results display
│   ├── history.html
│   └── help.html               # OWASP Top 10 guide
└── static/
    ├── css/
    │   ├── main.css            # Global styles & dark theme
    │   ├── dashboard.css
    │   ├── scan.css
    │   ├── results.css
    │   └── help.css
    ├── js/
    │   ├── auth.js             # Auth form interactions
    │   ├── scan.js             # Live scan polling & progress
    │   ├── results.js          # Tab switching
    │   ├── history.js          # Delete scan records
    │   └── help.js             # Scroll highlighting
    └── reports/                # Generated PDF & JSON reports
```

---

## 🎯 Safe Demo Targets

Use only targets you own or have explicit authorization for:

| Target | Description |
|--------|-------------|
| `http://testphp.vulnweb.com` | Deliberately vulnerable PHP app by Acunetix |
| `http://localhost` | Your local development server |
| `http://dvwa.local` | DVWA — Damn Vulnerable Web App |
| `http://192.168.56.101` | Metasploitable2 on local network |

---

## 🔍 Scanning Phases

### Phase 1 — Reconnaissance
- Web technology detection (server, CMS, frameworks)
- Web spider/crawler (links, forms)
- Subdomain discovery
- Directory fuzzing (built-in + custom wordlist)

### Phase 2 — Enumeration
- Port scanning (24 common ports)
- Service enumeration & banner grabbing
- OS detection

### Phase 3 — Vulnerability Scanning
- XSS (Reflected + Stored indicators)
- SQL Injection (error-based + blind simulation)
- IDOR pattern testing
- Security header analysis
- SSL/TLS configuration check
- API endpoint discovery
- OWASP Top 10 checks

### Phase 4 — Analysis & Reporting
- CVSS v3.1 severity scoring
- Risk classification (Critical/High/Medium/Low)
- PoC exploitation simulation
- PDF report generation (with reportlab)
- JSON report generation

---

## ⚠️ Legal Disclaimer

This tool is intended **exclusively for authorized security testing** in academic,
lab, and controlled environments. Only test systems you own or have written
permission to test. Unauthorized scanning is illegal.

---

## 📦 Tech Stack

- **Backend:** Python 3, Flask, SQLite
- **Frontend:** Vanilla HTML5, CSS3, JavaScript (ES6)
- **PDF Generation:** ReportLab
- **Scanning:** Python stdlib (socket, ssl, urllib)
