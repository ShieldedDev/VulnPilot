import os
import json
import uuid
import threading
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, flash
from werkzeug.security import generate_password_hash, check_password_hash
from modules.scanner import VAPTScanner
from modules.report_generator import ReportGenerator
from modules.database import Database

app = Flask(__name__)
app.secret_key = os.urandom(24)

db = Database()
scan_sessions = {}

# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = db.get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Please try again.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not username or not email or not password:
            flash('All fields are required.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
        elif db.get_user_by_username(username):
            flash('Username already exists.', 'error')
        else:
            hashed = generate_password_hash(password)
            db.create_user(username, email, hashed)
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = db.get_user_by_email(email)
        if user:
            flash('If that email is registered, a reset link would be sent. (Demo: check console)', 'info')
        else:
            flash('If that email is registered, a reset link would be sent.', 'info')
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    scans = db.get_scans_by_user(session['user_id'])
    stats = {
        'total': len(scans),
        'completed': sum(1 for s in scans if s['status'] == 'completed'),
        'running': sum(1 for s in scans if s['status'] == 'running'),
        'critical': sum(1 for s in scans if s.get('critical_count', 0) > 0)
    }
    return render_template('dashboard.html', scans=scans[:5], stats=stats)

# ─── Scanner ──────────────────────────────────────────────────────────────────

@app.route('/scan')
def scan():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('scan.html')

@app.route('/scan/start', methods=['POST'])
def start_scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'full')
    wordlist = data.get('wordlist', '')
    if not target:
        return jsonify({'error': 'Target is required'}), 400

    scan_id = str(uuid.uuid4())
    db.create_scan(scan_id, session['user_id'], target, scan_type)
    scan_sessions[scan_id] = {
        'status': 'running',
        'progress': [],
        'results': {},
        'target': target
    }

    def run_scan():
        scanner = VAPTScanner(target, scan_type, wordlist)
        session_data = scan_sessions[scan_id]

        def log(msg, phase=None):
            session_data['progress'].append({'message': msg, 'phase': phase, 'time': datetime.now().strftime('%H:%M:%S')})

        log('Initializing VAPT Scanner...', 'init')
        log(f'Target: {target}', 'init')

        results = {}

        # Phase 1: Recon
        log('PHASE 1: Reconnaissance Started', 'recon')
        log('Running web technology detection...', 'recon')
        results['tech'] = scanner.detect_technologies()
        log('Technology detection complete.', 'recon')

        log('Running web crawler/spider...', 'recon')
        results['crawl'] = scanner.crawl()
        log(f'Crawler found {len(results["crawl"].get("links", []))} links.', 'recon')

        log('Running subdomain discovery...', 'recon')
        results['subdomains'] = scanner.discover_subdomains()
        log(f'Found {len(results["subdomains"].get("found", []))} subdomains.', 'recon')

        log('Running directory fuzzing...', 'recon')
        results['dirs'] = scanner.fuzz_directories(wordlist)
        log(f'Directory fuzzing complete. {len(results["dirs"].get("found", []))} paths found.', 'recon')

        # Phase 2: Enumeration
        log('PHASE 2: Enumeration Started', 'enum')
        log('Running port scan...', 'enum')
        results['ports'] = scanner.scan_ports()
        log(f'Port scan complete. {len(results["ports"].get("open", []))} open ports found.', 'enum')

        log('Running service enumeration & banner grabbing...', 'enum')
        results['services'] = scanner.enumerate_services(results['ports'].get('open', []))
        log('Service enumeration complete.', 'enum')

        log('Running OS detection...', 'enum')
        results['os'] = scanner.detect_os()
        log('OS detection complete.', 'enum')

        # Phase 3: Vulnerability Scanning
        log('PHASE 3: Vulnerability Scanning Started', 'vuln')
        log('Testing for XSS vulnerabilities...', 'vuln')
        results['xss'] = scanner.test_xss()
        log(f'XSS scan complete. {len(results["xss"].get("findings", []))} findings.', 'vuln')

        log('Testing for SQL Injection...', 'vuln')
        results['sqli'] = scanner.test_sqli()
        log(f'SQLi scan complete. {len(results["sqli"].get("findings", []))} findings.', 'vuln')

        log('Testing for IDOR vulnerabilities...', 'vuln')
        results['idor'] = scanner.test_idor()
        log('IDOR testing complete.', 'vuln')

        log('Checking security headers & misconfigurations...', 'vuln')
        results['headers'] = scanner.check_headers()
        log('Header analysis complete.', 'vuln')

        log('Testing SSL/TLS configuration...', 'vuln')
        results['ssl'] = scanner.check_ssl()
        log('SSL/TLS check complete.', 'vuln')

        log('Discovering API endpoints...', 'vuln')
        results['api'] = scanner.discover_api_endpoints()
        log('API discovery complete.', 'vuln')

        log('Running OWASP Top 10 checks...', 'vuln')
        results['owasp'] = scanner.check_owasp()
        log('OWASP Top 10 checks complete.', 'vuln')

        # Phase 4: Analysis
        log('PHASE 4: Vulnerability Analysis Started', 'analysis')
        results['analysis'] = scanner.analyze_vulnerabilities(results)
        log('Severity classification complete.', 'analysis')
        log('CVSS score calculation complete.', 'analysis')
        log('Remediation recommendations generated.', 'analysis')

        # Generate Reports
        log('Generating VAPT Reports...', 'report')
        report_gen = ReportGenerator(target, results, scan_id)
        pdf_path = report_gen.generate_pdf()
        json_path = report_gen.generate_json()
        results['reports'] = {'pdf': pdf_path, 'json': json_path}
        log('Reports generated successfully.', 'report')

        log('Scan Completed Successfully!', 'complete')
        session_data['status'] = 'completed'
        session_data['results'] = results

        # Count severities
        vuln_counts = results['analysis'].get('severity_counts', {})
        db.update_scan(scan_id, 'completed', json.dumps(results),
                       vuln_counts.get('Critical', 0),
                       vuln_counts.get('High', 0),
                       vuln_counts.get('Medium', 0),
                       vuln_counts.get('Low', 0))

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

    return jsonify({'scan_id': scan_id})

@app.route('/scan/<scan_id>/status')
def scan_status(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if scan_id not in scan_sessions:
        scan = db.get_scan(scan_id)
        if scan and scan['results']:
            return jsonify({'status': 'completed', 'progress': [], 'results': json.loads(scan['results'])})
        return jsonify({'error': 'Scan not found'}), 404
    data = scan_sessions[scan_id]
    return jsonify({'status': data['status'], 'progress': data['progress'], 'results': data.get('results', {})})

@app.route('/scan/<scan_id>/results')
def scan_results(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    scan = db.get_scan(scan_id)
    if not scan:
        flash('Scan not found.', 'error')
        return redirect(url_for('history'))
    results = json.loads(scan['results']) if scan['results'] else {}
    return render_template('results.html', scan=scan, results=results)

# ─── Reports ──────────────────────────────────────────────────────────────────

@app.route('/report/<scan_id>/pdf')
def download_pdf(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    path = os.path.join('static', 'reports', f'{scan_id}.pdf')
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=f'VAPT_Report_{scan_id[:8]}.pdf')
    return jsonify({'error': 'Report not found'}), 404

@app.route('/report/<scan_id>/json')
def download_json(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    path = os.path.join('static', 'reports', f'{scan_id}.json')
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=f'VAPT_Report_{scan_id[:8]}.json')
    return jsonify({'error': 'Report not found'}), 404

# ─── History ──────────────────────────────────────────────────────────────────

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    scans = db.get_scans_by_user(session['user_id'])
    return render_template('history.html', scans=scans)

@app.route('/scan/<scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    db.delete_scan(scan_id, session['user_id'])
    return jsonify({'success': True})

# ─── Help ─────────────────────────────────────────────────────────────────────

@app.route('/help')
def help_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('help.html')

if __name__ == '__main__':
    db.init_db()
    os.makedirs('static/reports', exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)
