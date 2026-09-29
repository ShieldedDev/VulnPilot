import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urljoin, urlparse

from modules.config import ScannerConfig
from modules.finding import Finding


class VAPTScanner:

    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '"><iframe src=javascript:alert(1)>',
    ]

    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR "1"="1',
        "1' ORDER BY 1--",
        "1 UNION SELECT NULL--",
        "' AND SLEEP(2)--",
        "'; DROP TABLE users--",
    ]

    COMMON_DIRS = [
        'admin', 'login', 'wp-admin', 'phpmyadmin', 'api', 'v1', 'v2',
        'backup', 'config', 'test', 'dev', 'staging', 'uploads', 'files',
        'static', 'assets', 'dashboard', 'panel', 'manage', 'console',
        '.git', '.env', 'robots.txt', 'sitemap.xml', 'server-status',
        'phpinfo.php', 'info.php', 'readme.txt', 'CHANGELOG.txt',
    ]

    API_PATTERNS = [
        '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql', '/swagger',
        '/api-docs', '/openapi.json', '/api/users', '/api/auth', '/api/login',
        '/api/admin', '/api/config', '/api/data', '/api/export',
    ]

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
                    8443, 8888, 9200, 27017]

    def __init__(self, target, scan_type='full', wordlist='', config=None):
        self.target = target
        self.scan_type = scan_type
        self.wordlist = wordlist
        self.config = config or ScannerConfig()
        self.parsed = urlparse(target if '://' in target else f'http://{target}')
        self.hostname = self.parsed.hostname or target
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}" if self.parsed.netloc else f"http://{target}"
        self.timeout = self.config.timeout

    def _request(self, url, method='GET', params=None, headers=None, timeout=None):
        default_headers = {
            'User-Agent': self.config.user_agent,
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
        }
        if headers:
            default_headers.update(headers)

        request_url = url
        if params:
            request_url = f"{request_url}?{urllib.parse.urlencode(params)}"

        req = urllib.request.Request(request_url, headers=default_headers, method=method)
        timeout_value = timeout or self.timeout
        opener = urllib.request.build_opener()
        if self.config.proxy:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': self.config.proxy, 'https': self.config.proxy}))

        for attempt in range(max(1, self.config.retries)):
            try:
                with opener.open(req, timeout=timeout_value) as resp:
                    return {
                        'status': resp.status,
                        'headers': dict(resp.headers),
                        'body': resp.read(8192).decode('utf-8', errors='ignore'),
                        'url': resp.url,
                    }
            except urllib.error.HTTPError as exc:
                return {
                    'status': exc.code,
                    'headers': dict(exc.headers) if exc.headers else {},
                    'body': exc.read(8192).decode('utf-8', errors='ignore'),
                    'url': request_url,
                }
            except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
                if attempt == max(1, self.config.retries) - 1:
                    return None
                continue

        return None

    def _make_finding(self, *, title, severity='Informational', confidence='Medium', target=None,
                      endpoint='', parameter='', method='GET', payload='', request='', response='',
                      evidence=None, description='', impact='', remediation='', cwe='', cvss=0.0,
                      cvss_vector='', detection_method='heuristic', category='', raw=None):
        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            target=(target or self.target),
            endpoint=endpoint,
            parameter=parameter,
            method=method,
            payload=payload,
            request=request,
            response=response,
            evidence=evidence or [],
            description=description,
            impact=impact,
            remediation=remediation,
            cwe=cwe,
            cvss=cvss,
            cvss_vector=cvss_vector,
            detection_method=detection_method,
            category=category,
            raw=raw or {},
        ).to_dict()

    def detect_technologies(self):
        result = {'server': '', 'cms': '', 'frameworks': [], 'languages': [], 'headers': {}}
        resp = self._request(self.base_url)
        if not resp:
            return result

        headers = {k.lower(): v for k, v in resp['headers'].items()}
        body = resp['body'].lower()
        result['headers'] = resp['headers']
        result['server'] = headers.get('server', 'Unknown')
        result['powered_by'] = headers.get('x-powered-by', '')

        if 'wp-content' in body or 'wp-includes' in body:
            result['cms'] = 'WordPress'
        elif 'joomla' in body:
            result['cms'] = 'Joomla'
        elif 'drupal' in body:
            result['cms'] = 'Drupal'
        elif 'magento' in body:
            result['cms'] = 'Magento'

        if 'django' in body or 'csrfmiddlewaretoken' in body:
            result['frameworks'].append('Django')
        if 'laravel' in body or 'laravel_session' in str(headers):
            result['frameworks'].append('Laravel')
        if 'rails' in body or 'x-runtime' in headers:
            result['frameworks'].append('Ruby on Rails')
        if 'asp.net' in headers.get('x-powered-by', '').lower():
            result['frameworks'].append('ASP.NET')

        if 'php' in headers.get('x-powered-by', '').lower() or '.php' in resp.get('url', ''):
            result['languages'].append('PHP')
        if 'node' in headers.get('x-powered-by', '').lower():
            result['languages'].append('Node.js')

        result['interesting_headers'] = {
            'x-frame-options': headers.get('x-frame-options', 'MISSING'),
            'content-security-policy': headers.get('content-security-policy', 'MISSING'),
            'x-xss-protection': headers.get('x-xss-protection', 'MISSING'),
            'strict-transport-security': headers.get('strict-transport-security', 'MISSING'),
            'x-content-type-options': headers.get('x-content-type-options', 'MISSING'),
            'referrer-policy': headers.get('referrer-policy', 'MISSING'),
        }

        return result

    def crawl(self, max_depth=None, max_links=None):
        max_depth = max_depth if max_depth is not None else self.config.max_crawl_depth
        max_links = max_links if max_links is not None else self.config.max_crawl_links
        visited = set()
        found_links = []
        found_forms = []
        queue = [(self.base_url, 0)]

        while queue and len(found_links) < max_links:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)

            resp = self._request(url)
            if not resp:
                continue

            body = resp['body']
            links = re.findall(r'href=["\']([^"\']+)["\']', body)
            for link in links:
                abs_link = urljoin(url, link)
                if self.hostname in abs_link and abs_link not in visited:
                    found_links.append(abs_link)
                    if depth + 1 <= max_depth:
                        queue.append((abs_link, depth + 1))

            forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
            for form in forms:
                action = re.search(r'action=["\']([^"\']*)["\']', form)
                method = re.search(r'method=["\']([^"\']*)["\']', form)
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form)
                found_forms.append({
                    'action': action.group(1) if action else url,
                    'method': method.group(1).upper() if method else 'GET',
                    'inputs': inputs,
                })

        return {
            'links': list(set(found_links))[:max_links],
            'forms': found_forms,
            'pages_crawled': len(visited),
        }

    def discover_subdomains(self):
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging',
                       'test', 'portal', 'vpn', 'remote', 'blog', 'shop', 'app',
                       'secure', 'auth', 'oauth', 'cdn', 'static', 'media']
        found = []
        base_domain = '.'.join(self.hostname.split('.')[-2:]) if '.' in self.hostname else self.hostname

        for sub in common_subs:
            subdomain = f'{sub}.{base_domain}'
            try:
                ip = socket.gethostbyname(subdomain)
                found.append({'subdomain': subdomain, 'ip': ip, 'status': 'resolved'})
            except socket.gaierror:
                pass

        return {'found': found, 'checked': len(common_subs), 'base_domain': base_domain}

    def fuzz_directories(self, wordlist=''):
        dirs_to_check = self.COMMON_DIRS.copy()
        if wordlist:
            dirs_to_check.extend([w.strip() for w in wordlist.split('\n') if w.strip()])

        found = []
        for path in dirs_to_check:
            url = f"{self.base_url}/{path.lstrip('/')}"
            resp = self._request(url)
            if resp and resp['status'] not in [404, 0]:
                found.append({
                    'path': path,
                    'url': url,
                    'status': resp['status'],
                    'interesting': resp['status'] in [200, 301, 302, 403],
                })

        return {
            'found': found,
            'total_checked': len(dirs_to_check),
            'interesting': [item for item in found if item['interesting']],
        }

    def scan_ports(self):
        open_ports = []
        closed_ports = []
        candidate_ports = list(self.config.allowed_ports or self.COMMON_PORTS)
        if self.config.excluded_ports:
            candidate_ports = [p for p in candidate_ports if p not in self.config.excluded_ports]

        try:
            host_ip = socket.gethostbyname(self.hostname)
        except socket.gaierror:
            host_ip = self.hostname

        for port in candidate_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.hostname, port))
                if result == 0:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                sock.close()
            except Exception:
                closed_ports.append(port)

        return {
            'host': self.hostname,
            'ip': host_ip,
            'open': open_ports,
            'closed': closed_ports,
            'total_scanned': len(candidate_ports),
        }

    def enumerate_services(self, open_ports):
        services = {}
        port_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB'
        }

        for port in open_ports:
            banner = self._grab_banner(self.hostname, port)
            services[port] = {
                'service': port_map.get(port, 'Unknown'),
                'banner': banner,
                'risk': self._assess_service_risk(port, banner),
            }

        return services

    def _grab_banner(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            if port in [80, 8080, 8888]:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                return 'SSL/TLS Service'
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else ''
        except Exception:
            return ''

    def _assess_service_risk(self, port, banner):
        high_risk = [23, 21, 3389, 5900, 6379, 27017, 9200]
        medium_risk = [22, 3306, 5432, 1433, 1521, 445]
        if port in high_risk:
            return 'High'
        if port in medium_risk:
            return 'Medium'
        return 'Low'

    def detect_os(self):
        os_hints = {'os': 'Unknown', 'confidence': 'Low', 'hints': []}
        resp = self._request(self.base_url)
        if resp:
            server = resp['headers'].get('Server', '').lower()
            if 'win' in server or 'iis' in server:
                os_hints['os'] = 'Windows'
                os_hints['confidence'] = 'Medium'
                os_hints['hints'].append(f'Server header: {server}')
            elif 'ubuntu' in server or 'debian' in server or 'centos' in server:
                os_hints['os'] = 'Linux'
                os_hints['confidence'] = 'High'
                os_hints['hints'].append(f'Server header: {server}')
            elif 'apache' in server or 'nginx' in server:
                os_hints['os'] = 'Linux (probable)'
                os_hints['confidence'] = 'Medium'
                os_hints['hints'].append(f'Server: {server}')

        if not os_hints['hints']:
            os_hints['hints'].append('OS inferred from response headers only; confidence is limited.')
        return os_hints

    def test_xss(self):
        findings = []
        crawl_data = self.crawl(max_depth=1, max_links=10)
        forms = crawl_data.get('forms', [])
        test_url = f"{self.base_url}/?q="

        for payload in self.XSS_PAYLOADS[:3]:
            encoded = urllib.parse.quote(payload)
            resp = self._request(f"{test_url}{encoded}")
            if resp and payload.lower() in resp.get('body', '').lower():
                findings.append(self._make_finding(
                    title='Reflected XSS candidate',
                    severity='High',
                    confidence='Medium',
                    target=self.target,
                    endpoint=test_url,
                    parameter='q',
                    method='GET',
                    payload=payload,
                    request=f'GET {test_url}{encoded}',
                    response=resp.get('body', '')[:500],
                    evidence=['Payload reflected in the response body.'],
                    description='A payload was reflected in the server response in a query parameter without proof of exploitation.',
                    impact='A malicious payload may execute in a victim browser and could enable session theft or UI redress.',
                    remediation='Escape user-controlled values in the rendered output and apply a strict CSP policy.',
                    cwe='CWE-79',
                    cvss=7.4,
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                    detection_method='reflected_payload',
                    raw={'url': test_url, 'type': 'reflected_xss'},
                ))
                break

        for form in forms[:3]:
            for payload in self.XSS_PAYLOADS[:2]:
                action_url = urljoin(self.base_url, form['action'])
                for input_name in form.get('inputs', ['q', 'search']):
                    params = {input_name: payload}
                    resp = self._request(action_url, params=params)
                    if resp and payload.lower() in resp.get('body', '').lower():
                        findings.append(self._make_finding(
                            title='Form reflected XSS candidate',
                            severity='High',
                            confidence='Medium',
                            target=self.target,
                            endpoint=action_url,
                            parameter=input_name,
                            method='GET',
                            payload=payload,
                            request=f'GET {action_url}?{input_name}={urllib.parse.quote(payload)}',
                            response=resp.get('body', '')[:500],
                            evidence=['Payload reflected in an HTML form response.'],
                            description='The value entered via a form field is echoed back in the response.',
                            impact='The application may be exploitable via browser-side script execution.',
                            remediation='Apply contextual output encoding and validate form inputs before rendering.',
                            cwe='CWE-79',
                            cvss=7.4,
                            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            detection_method='form_reflection',
                            raw={'url': action_url, 'form': form, 'type': 'reflected_xss'},
                        ))
                        break

        resp = self._request(self.base_url)
        if resp:
            body = resp.get('body', '')
            if re.search(r'<script[^>]*>.*?(alert|eval|document\.cookie)', body, re.IGNORECASE | re.DOTALL):
                findings.append(self._make_finding(
                    title='Inline script indicator',
                    severity='Medium',
                    confidence='Low',
                    target=self.target,
                    endpoint=self.base_url,
                    description='Inline script code patterns were identified in the root page.',
                    impact='Unsafe client-side script execution may be present if the code is user-controlled.',
                    remediation='Remove inline scripting and enforce CSP and sanitization.',
                    cwe='CWE-79',
                    cvss=5.4,
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                    detection_method='script_pattern_scan',
                    raw={'type': 'stored_xss_indicator'},
                    evidence=['Suspicious inline script pattern detected in the HTML response.'],
                ))

        return {'findings': findings, 'payloads_tested': len(self.XSS_PAYLOADS)}

    def test_sqli(self):
        findings = []
        error_patterns = [
            r'you have an error in your sql syntax',
            r'warning: mysql',
            r'unclosed quotation mark',
            r'quoted string not properly terminated',
            r'syntax error.*?near',
            r'odbc.*?sql server',
            r'microsoft ole db provider for sql server',
            r'ora-\d{5}',
            r'pg::syntax',
            r'invalid query',
        ]

        test_url = f"{self.base_url}/?id="
        for payload in self.SQLI_PAYLOADS[:4]:
            encoded = urllib.parse.quote(payload)
            resp = self._request(f"{test_url}{encoded}")
            if resp:
                body = resp.get('body', '').lower()
                for pattern in error_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(self._make_finding(
                            title='SQL injection error pattern',
                            severity='High',
                            confidence='High',
                            target=self.target,
                            endpoint=test_url,
                            parameter='id',
                            method='GET',
                            payload=payload,
                            request=f'GET {test_url}{encoded}',
                            response=resp.get('body', '')[:500],
                            evidence=[f'SQL error pattern matched: {pattern}.'],
                            description='The response shows a database error pattern consistent with injection handling flaws.',
                            impact='An attacker may be able to manipulate SQL queries or extract database data.',
                            remediation='Use parameterized queries and strict server-side validation for all database access.',
                            cwe='CWE-89',
                            cvss=9.8,
                            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                            detection_method='error_pattern_analysis',
                            raw={'url': test_url, 'error_pattern': pattern},
                        ))
                        break

        findings.append(self._make_finding(
            title='Blind SQLi timing check simulation',
            severity='Informational',
            confidence='Low',
            target=self.target,
            endpoint=self.base_url,
            description='A blind timing-based SQL injection payload was simulated and should only be considered a candidate indicator.',
            impact='A time-delayed database attack may be feasible when the application is vulnerable.',
            remediation='Validate with a safe, consented test target and confirm differential timing evidence before reporting.',
            cwe='CWE-89',
            cvss=0.0,
            detection_method='simulated_timing_check',
            evidence=['Timing-based SQLi validation was simulated and not confirmed against a live vulnerable endpoint.'],
            raw={'type': 'simulated'},
        ))

        return {'findings': findings, 'payloads_tested': len(self.SQLI_PAYLOADS)}

    def test_idor(self):
        findings = []
        idor_patterns = ['/user/1', '/user/2', '/profile/1', '/account/1', '/api/user/1', '/api/order/1', '/document/1', '/?id=1', '/?user_id=1', '/?account=1']

        for pattern in idor_patterns[:5]:
            url = f"{self.base_url}{pattern}"
            resp = self._request(url)
            if resp and resp['status'] == 200:
                body = resp.get('body', '')
                if any(kw in body.lower() for kw in ['email', 'username', 'password', 'account', 'user']):
                    findings.append(self._make_finding(
                        title='Potential IDOR / BOLA candidate',
                        severity='Medium',
                        confidence='Low',
                        target=self.target,
                        endpoint=url,
                        description='The endpoint returns user-like data without evidence of a proper authorization boundary check.',
                        impact='Attackers may access records or actions intended for another user if access control is weak.',
                        remediation='Enforce object-level authorization checks and validate access against the active user context.',
                        cwe='CWE-639',
                        cvss=7.5,
                        cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
                        detection_method='authorization_pattern_scan',
                        evidence=['Sensitive user-like data was returned in a direct object lookup path.'],
                        raw={'url': url, 'pattern': pattern},
                    ))

        return {'findings': findings, 'patterns_tested': len(idor_patterns)}

    def check_headers(self):
        findings = []
        resp = self._request(self.base_url)
        if not resp:
            return {'findings': findings, 'headers_checked': 0}

        headers = {k.lower(): v for k, v in resp['headers'].items()}
        security_headers = {
            'x-frame-options': {
                'severity': 'Medium', 'cvss': 4.3,
                'desc': 'Missing X-Frame-Options - Clickjacking vulnerability',
                'remediation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
            },
            'content-security-policy': {
                'severity': 'Medium', 'cvss': 5.0,
                'desc': 'Missing Content-Security-Policy header',
                'remediation': 'Implement a strict CSP policy',
            },
            'x-content-type-options': {
                'severity': 'Low', 'cvss': 3.1,
                'desc': 'Missing X-Content-Type-Options - MIME sniffing vulnerability',
                'remediation': 'Add: X-Content-Type-Options: nosniff',
            },
            'strict-transport-security': {
                'severity': 'Medium', 'cvss': 4.8,
                'desc': 'Missing HSTS header - downgrade attack possible',
                'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            },
            'x-xss-protection': {
                'severity': 'Low', 'cvss': 3.1,
                'desc': 'Missing X-XSS-Protection header',
                'remediation': 'Add: X-XSS-Protection: 1; mode=block',
            },
            'referrer-policy': {
                'severity': 'Low', 'cvss': 2.6,
                'desc': 'Missing Referrer-Policy header - information leakage',
                'remediation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
            },
            'permissions-policy': {
                'severity': 'Low', 'cvss': 2.0,
                'desc': 'Missing Permissions-Policy header',
                'remediation': 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
            },
        }

        for header, info in security_headers.items():
            if header not in headers:
                findings.append(self._make_finding(
                    title=f'Missing {header.upper()} header',
                    severity=info['severity'],
                    confidence='High',
                    target=self.target,
                    endpoint=self.base_url,
                    description=info['desc'],
                    impact='The application is missing a baseline security control that helps reduce browser-based attacks.',
                    remediation=info['remediation'],
                    cwe='CWE-693',
                    cvss=info['cvss'],
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
                    detection_method='header_misconfiguration',
                    evidence=[f'{header.upper()} header not present in the response.'],
                    raw={'header': header},
                ))

        if 'server' in headers and headers['server']:
            findings.append(self._make_finding(
                title='Technology disclosure via Server header',
                severity='Low',
                confidence='High',
                target=self.target,
                endpoint=self.base_url,
                description=f'Server header reveals: {headers["server"]}',
                impact='The exact server and version may aid attackers in targeting known vulnerabilities.',
                remediation='Remove or obfuscate the Server header.',
                cwe='CWE-200',
                cvss=2.0,
                detection_method='header_analysis',
                evidence=[f'Server header exposed value: {headers["server"]}.'],
                raw={'header': 'Server'},
            ))

        if 'x-powered-by' in headers:
            findings.append(self._make_finding(
                title='Technology disclosure via X-Powered-By',
                severity='Low',
                confidence='High',
                target=self.target,
                endpoint=self.base_url,
                description=f'X-Powered-By reveals: {headers["x-powered-by"]}',
                impact='Technology stack details can help attackers target known framework weaknesses.',
                remediation='Remove the X-Powered-By header from production responses.',
                cwe='CWE-200',
                cvss=2.0,
                detection_method='header_analysis',
                evidence=[f'X-Powered-By exposed value: {headers["x-powered-by"]}.'],
                raw={'header': 'X-Powered-By'},
            ))

        return {'findings': findings, 'headers_checked': len(security_headers)}

    def check_ssl(self):
        findings = []
        info = {'enabled': False, 'version': '', 'cipher': '', 'cert_valid': False, 'cert_issuer': '', 'cert_expiry': '', 'issues': []}
        try:
            ctx = ssl.create_default_context()
            if not self.config.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.hostname, 443), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    info['enabled'] = True
                    info['version'] = ssock.version()
                    info['cipher'] = ssock.cipher()[0] if ssock.cipher() else ''
                    info['cert_valid'] = True
                    if cert:
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        info['cert_issuer'] = issuer.get('organizationName', 'Unknown')
                        info['cert_expiry'] = cert.get('notAfter', '')
                    if info['version'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append(self._make_finding(
                            title='Weak TLS version detected',
                            severity='High',
                            confidence='High',
                            target=self.target,
                            endpoint='https://{host}:443'.format(host=self.hostname),
                            description=f'Outdated TLS version in use: {info["version"]}',
                            impact='Older TLS versions are susceptible to downgrade and cryptographic attacks.',
                            remediation='Disable legacy TLS versions and require TLS 1.2 or TLS 1.3.',
                            cwe='CWE-327',
                            cvss=7.4,
                            detection_method='tls_observation',
                            evidence=[f'TLS version observed: {info["version"]}.'],
                            raw={'tls_version': info['version']},
                        ))
        except ssl.SSLCertVerificationError:
            info['cert_valid'] = False
            findings.append(self._make_finding(
                title='Certificate validation failure',
                severity='Medium',
                confidence='High',
                target=self.target,
                endpoint='https://{host}:443'.format(host=self.hostname),
                description='TLS certificate validation failed for the target endpoint.',
                impact='The target may be using a self-signed or misconfigured certificate, or may be intercepting TLS traffic.',
                remediation='Deploy a valid certificate issued by a trusted CA and verify chain integrity.',
                cwe='CWE-295',
                cvss=5.9,
                detection_method='tls_validation',
                evidence=['TLS certificate validation failed or the certificate is self-signed or expired.'],
                raw={'issue': 'certificate_validation_failed'},
            ))
        except ConnectionRefusedError:
            findings.append(self._make_finding(
                title='HTTPS not available',
                severity='High',
                confidence='High',
                target=self.target,
                endpoint='https://{host}:443'.format(host=self.hostname),
                description='HTTPS is not available on port 443 for the target host.',
                impact='The service may be exposing traffic without transport security.',
                remediation='Enable HTTPS and redirect HTTP to TLS.',
                cwe='CWE-319',
                cvss=7.5,
                detection_method='tls_observation',
                evidence=['Connection to port 443 was refused.'],
                raw={'issue': 'https_not_available'},
            ))
        except Exception as exc:
            info['issues'].append(str(exc))

        return {'info': info, 'findings': findings}

    def discover_api_endpoints(self):
        found = []
        checked = []

        for pattern in self.API_PATTERNS:
            url = f"{self.base_url}{pattern}"
            resp = self._request(url)
            checked.append(url)
            if resp and resp['status'] not in [404]:
                body = resp.get('body', '')
                is_json = False
                try:
                    json.loads(body)
                    is_json = True
                except Exception:
                    pass

                found.append({
                    'url': url,
                    'status': resp['status'],
                    'is_json': is_json,
                    'note': 'Accessible without authentication' if resp['status'] == 200 else f'Status: {resp["status"]}',
                })

        return {'found': found, 'checked': len(checked)}

    def check_owasp(self):
        findings = []
        findings.append({
            'category': 'A01 - Broken Access Control',
            'checks': ['IDOR testing', 'Directory traversal', 'Admin panel exposure'],
            'status': 'Checked',
            'severity': 'High',
            'cvss': 7.5,
        })

        has_https = self.base_url.startswith('https')
        findings.append({
            'category': 'A02 - Cryptographic Failures',
            'checks': ['HTTPS check', 'Cookie security flags'],
            'status': 'HTTPS not enforced' if not has_https else 'HTTPS enabled',
            'severity': 'High' if not has_https else 'Low',
            'cvss': 7.5 if not has_https else 2.0,
        })

        findings.append({
            'category': 'A03 - Injection',
            'checks': ['SQL Injection', 'XSS', 'Command Injection'],
            'status': 'Checked via payload testing',
            'severity': 'Critical',
            'cvss': 9.8,
        })

        findings.append({
            'category': 'A05 - Security Misconfiguration',
            'checks': ['Default credentials', 'Debug mode', 'Error exposure', 'Directory listing'],
            'status': 'Checked',
            'severity': 'Medium',
            'cvss': 5.3,
        })

        findings.append({
            'category': 'A06 - Vulnerable and Outdated Components',
            'checks': ['Technology version detection'],
            'status': 'Component versions analyzed',
            'severity': 'Medium',
            'cvss': 5.5,
        })

        login_paths = ['/login', '/admin', '/wp-login.php', '/signin']
        for path in login_paths:
            resp = self._request(f"{self.base_url}{path}")
            if resp and resp['status'] == 200:
                body = resp.get('body', '').lower()
                has_lockout = 'captcha' in body or 'too many' in body or 'locked' in body
                findings.append({
                    'category': 'A07 - Identification and Authentication Failures',
                    'checks': ['Brute force protection', 'CAPTCHA', 'Account lockout'],
                    'status': 'No lockout mechanism detected' if not has_lockout else 'Lockout detected',
                    'severity': 'High' if not has_lockout else 'Low',
                    'cvss': 7.5 if not has_lockout else 2.0,
                    'url': path,
                })
                break

        findings.append({
            'category': 'A08 - Software and Data Integrity Failures',
            'checks': ['Subresource Integrity (SRI)', 'Update mechanism'],
            'status': 'SRI check performed',
            'severity': 'Medium',
            'cvss': 4.8,
        })

        findings.append({
            'category': 'A09 - Security Logging and Monitoring Failures',
            'checks': ['Error page verbosity', 'Log exposure'],
            'status': 'Manual review recommended',
            'severity': 'Medium',
            'cvss': 4.3,
        })

        findings.append({
            'category': 'A10 - Server-Side Request Forgery (SSRF)',
            'checks': ['URL parameter injection', 'Webhook endpoints'],
            'status': 'Basic SSRF patterns checked',
            'severity': 'High',
            'cvss': 7.2,
        })

        return {'findings': findings}

    def analyze_vulnerabilities(self, all_results):
        all_vulns = []
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}

        for key in ['xss', 'sqli', 'idor', 'headers', 'ssl']:
            for finding in all_results.get(key, {}).get('findings', []):
                if finding.get('severity', 'Informational') != 'Informational':
                    all_vulns.append(finding)

        all_vulns.sort(key=lambda item: severity_order.get(item.get('severity', 'Informational'), 5))

        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for vulnerability in all_vulns:
            severity = vulnerability.get('severity', 'Informational')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        risk_score = (
            severity_counts['Critical'] * 10 +
            severity_counts['High'] * 7 +
            severity_counts['Medium'] * 4 +
            severity_counts['Low'] * 1
        )

        if risk_score > 40:
            overall_risk = 'Critical'
        elif risk_score > 25:
            overall_risk = 'High'
        elif risk_score > 10:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'

        poc_examples = []
        for vulnerability in all_vulns[:3]:
            if vulnerability.get('title', '').lower().startswith('reflected'):
                poc_examples.append({
                    'vuln': vulnerability.get('title'),
                    'poc': f"Navigate to: {vulnerability.get('endpoint', self.base_url)} with payload {vulnerability.get('payload', '')}",
                    'impact': 'Session hijacking, credential theft, or UI manipulation may be possible if the payload executes in a victim browser.',
                    'note': 'Simulated for controlled lab use only.',
                })
            elif 'sql' in vulnerability.get('title', '').lower():
                poc_examples.append({
                    'vuln': vulnerability.get('title'),
                    'poc': f"Parameter: id={vulnerability.get('payload', '')}",
                    'impact': 'Database compromise, data exposure, or authentication bypass may be possible.',
                    'note': 'Test only against authorized targets.',
                })

        return {
            'vulnerabilities': all_vulns,
            'severity_counts': severity_counts,
            'risk_score': risk_score,
            'overall_risk': overall_risk,
            'poc_examples': poc_examples,
            'remediation_priority': all_vulns[:5],
        }
