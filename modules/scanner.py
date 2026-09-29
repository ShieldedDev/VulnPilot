import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
from difflib import SequenceMatcher
from html.parser import HTMLParser
import urllib.request
from urllib.parse import urljoin, urlparse

from modules.config import ScannerConfig
from modules.finding import Finding


class _SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self.form = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag.lower() == 'a' and attributes.get('href'):
            self.links.append(attributes['href'])
        if tag.lower() == 'form':
            self.form = {
                'action': attributes.get('action', ''),
                'method': attributes.get('method', 'GET').upper(),
                'inputs': [],
                'fields': [],
            }
        elif self.form and tag.lower() in {'input', 'textarea', 'select'}:
            name = attributes.get('name')
            if name:
                self.form['inputs'].append(name)
                self.form['fields'].append({
                    'name': name,
                    'value': attributes.get('value', ''),
                    'type': attributes.get('type', tag).lower(),
                })

    def handle_endtag(self, tag):
        if tag.lower() == 'form' and self.form:
            self.forms.append(self.form)
            self.form = None

    def close(self):
        super().close()
        if self.form:
            self.forms.append(self.form)
            self.form = None


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
        "'",
        "' AND '1'='1",
        "' AND '1'='2",
        '"',
        '" AND "1"="1',
        '" AND "1"="2',
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

    def __init__(self, target, scan_type='full', wordlist='', config=None, auth_cookie=''):
        self.target = target
        self.scan_type = scan_type
        self.wordlist = wordlist
        self.config = config or ScannerConfig()
        self.auth_cookie = auth_cookie
        self.parsed = urlparse(target if '://' in target else f'http://{target}')
        self.hostname = self.parsed.hostname or target
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}" if self.parsed.netloc else f"http://{target}"
        self.timeout = self.config.timeout

    def _request(self, url, method='GET', params=None, headers=None, timeout=None, data=None):
        default_headers = {
            'User-Agent': self.config.user_agent,
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
        }
        if headers:
            default_headers.update(headers)
        if self.auth_cookie:
            default_headers.setdefault('Cookie', self.auth_cookie)

        request_url = url
        if params:
            separator = '&' if urllib.parse.urlsplit(request_url).query else '?'
            request_url = f"{request_url}{separator}{urllib.parse.urlencode(params)}"

        request_data = None
        if data is not None:
            request_data = urllib.parse.urlencode(data).encode('utf-8')
            default_headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        req = urllib.request.Request(request_url, data=request_data, headers=default_headers, method=method)
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

            parser = _SurfaceParser()
            parser.feed(resp['body'])
            parser.close()
            for link in parser.links:
                abs_link = urljoin(url, link).split('#', 1)[0]
                parsed_link = urlparse(abs_link)
                if (parsed_link.scheme in {'http', 'https'}
                        and parsed_link.netloc.lower() == self.parsed.netloc.lower()
                        and abs_link not in visited):
                    found_links.append(abs_link)
                    if depth + 1 <= max_depth:
                        queue.append((abs_link, depth + 1))

            for form in parser.forms:
                form['action'] = urljoin(url, form['action'] or url)
                form['source'] = url
                found_forms.append(form)

        return {
            'links': list(dict.fromkeys(found_links))[:max_links],
            'forms': found_forms,
            'pages_crawled': len(visited),
        }

    def _candidate_surfaces(self, crawl_data):
        surfaces = []
        seen = set()

        def add_surface(url, method, parameter, query_pairs, fields, field_types):
            key = (url, method, parameter)
            if key in seen:
                return
            seen.add(key)
            surfaces.append({
                'url': url,
                'method': method,
                'parameter': parameter,
                'query': list(query_pairs),
                'fields': dict(fields),
                'field_types': dict(field_types),
            })

        for link in crawl_data.get('links', []):
            parsed = urllib.parse.urlsplit(link)
            query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            if not query_pairs:
                continue
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
            for name, _ in query_pairs:
                add_surface(url, 'GET', name, query_pairs, {}, {})

        for form in crawl_data.get('forms', []):
            fields = form.get('fields', [])
            field_types = {field['name']: field.get('type', 'text') for field in fields}
            if any(value == 'password' for value in field_types.values()):
                continue
            form_url = form.get('action') or form.get('source') or self.base_url
            parsed = urllib.parse.urlsplit(form_url)
            query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
            form_fields = {field['name']: field.get('value', '') for field in fields}
            for name in form.get('inputs', []):
                if field_types.get(name) in {'hidden', 'submit', 'button', 'reset', 'file'}:
                    continue
                add_surface(url, form.get('method', 'GET').upper(), name, query_pairs, form_fields, field_types)
            for name, _ in query_pairs:
                add_surface(url, form.get('method', 'GET').upper(), name, query_pairs, form_fields, field_types)

        return surfaces

    @staticmethod
    def _probe_surface(surface, parameter_value):
        url = surface['url']
        method = surface['method']
        params = list(surface['query'])
        params = [(name, parameter_value if name == surface['parameter'] else value) for name, value in params]
        fields = dict(surface['fields'])
        if method == 'GET':
            params.extend((name, value) for name, value in fields.items() if name != surface['parameter'])
            params = [(name, parameter_value if name == surface['parameter'] else value) for name, value in params]
            query = urllib.parse.urlencode(params)
            parsed = urllib.parse.urlsplit(url)
            request_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ''))
            return request_url, 'GET', None

        fields[surface['parameter']] = parameter_value
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.urlencode(params)
        request_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ''))
        return request_url, 'POST', fields

    def _send_surface_probe(self, surface, value):
        url, method, data = self._probe_surface(surface, value)
        response = self._request(url, method=method, data=data)
        return url, method, data, response

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

    def test_xss(self, crawl_data=None):
        findings = []
        crawl_data = crawl_data or self.crawl(max_depth=2, max_links=30)
        surfaces = self._candidate_surfaces(crawl_data)[:20]
        payload = '<vulnpilot-probe>marker</vulnpilot-probe>'
        tested = 0

        for surface in surfaces:
            endpoint, method, data, response = self._send_surface_probe(surface, payload)
            tested += 1
            if not response or payload not in response.get('body', ''):
                continue
            content_type = next((value for key, value in response.get('headers', {}).items() if key.lower() == 'content-type'), '')
            if 'html' not in content_type.lower():
                continue
            encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
            if encoded_payload in response.get('body', ''):
                continue

            request_value = (data or {}).get(surface['parameter'], payload) if method == 'POST' else payload
            findings.append(self._make_finding(
                title='Unescaped reflected markup (XSS candidate)',
                severity='Medium',
                confidence='Medium',
                target=self.target,
                endpoint=endpoint,
                parameter=surface['parameter'],
                method=method,
                payload=payload,
                request=f'{method} {endpoint} parameter={surface["parameter"]} value={request_value}',
                response=response.get('body', '')[:500],
                evidence=['A harmless custom-element marker was returned unescaped in an HTML response; JavaScript execution was not attempted.'],
                description='User-controlled markup was reflected into an HTML response without HTML encoding. This is an XSS candidate; verify the exact browser context before classifying it as exploitable.',
                impact='If the value is interpreted as active markup in a browser context, an attacker may be able to inject content or script.',
                remediation='Apply context-aware output encoding and validate input before rendering it into HTML.',
                cwe='CWE-79',
                cvss=6.1,
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                detection_method='unescaped_html_reflection',
                raw={'type': 'reflected_xss_candidate'},
            ))

        return {'findings': findings, 'payloads_tested': tested, 'parameters_tested': len(surfaces)}

    def test_sqli(self, crawl_data=None):
        findings = []
        crawl_data = crawl_data or self.crawl(max_depth=2, max_links=30)
        surfaces = self._candidate_surfaces(crawl_data)[:16]
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

        tested = 0
        for surface in surfaces:
            original = next((value for name, value in surface['query'] if name == surface['parameter']), None)
            if original is None:
                original = surface['fields'].get(surface['parameter'], '')
            baseline_url, method, _, baseline = self._send_surface_probe(surface, original)
            tested += 1
            if not baseline:
                continue

            quote_probe = f"{original}'"
            error_url, _, _, error_response = self._send_surface_probe(surface, quote_probe)
            tested += 1
            baseline_body = baseline.get('body', '').lower()
            error_body = error_response.get('body', '').lower() if error_response else ''
            matched_error = next((pattern for pattern in error_patterns
                                  if re.search(pattern, error_body, re.IGNORECASE)
                                  and not re.search(pattern, baseline_body, re.IGNORECASE)), None)
            if matched_error:
                findings.append(self._make_finding(
                    title='Database error triggered by input (SQLi candidate)',
                    severity='High',
                    confidence='High',
                    target=self.target,
                    endpoint=error_url,
                    parameter=surface['parameter'],
                    method=method,
                    payload=quote_probe,
                    request=f'{method} {error_url} parameter={surface["parameter"]}',
                    response=error_response.get('body', '')[:500],
                    evidence=[f'Database error signature appeared only after the quote probe: {matched_error}.'],
                    description='A database error signature was introduced by a quote in a discovered input. Confirm with application-level review before remediation sign-off.',
                    impact='Unsafely composed database queries may disclose errors or permit query manipulation.',
                    remediation='Use parameterized queries and avoid exposing database errors in responses.',
                    cwe='CWE-89',
                    cvss=8.1,
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
                    detection_method='database_error',
                    raw={'error_pattern': matched_error},
                ))
                continue

            true_value = f"{original}' AND '1'='1"
            false_value = f"{original}' AND '1'='2"
            true_url, _, _, true_response = self._send_surface_probe(surface, true_value)
            false_url, _, _, false_response = self._send_surface_probe(surface, false_value)
            tested += 2
            if not true_response or not false_response:
                continue

            true_body = true_response.get('body', '')
            false_body = false_response.get('body', '')
            baseline_body = baseline.get('body', '')
            true_similarity = SequenceMatcher(None, baseline_body, true_body).ratio()
            false_similarity = SequenceMatcher(None, baseline_body, false_body).ratio()
            true_matches_baseline = true_response.get('status') == baseline.get('status') and true_similarity >= 0.9
            false_differs = (false_response.get('status') != baseline.get('status')
                             or (false_similarity <= 0.7 and abs(len(false_body) - len(baseline_body)) >= 8))
            if true_matches_baseline and false_differs:
                findings.append(self._make_finding(
                    title='Boolean SQL injection response differential',
                    severity='High',
                    confidence='Medium',
                    target=self.target,
                    endpoint=true_url,
                    parameter=surface['parameter'],
                    method=method,
                    payload=f"{true_value} / {false_value}",
                    request=f'{method} {true_url} and {false_url} with paired Boolean conditions',
                    response=f'True-condition similarity: {true_similarity:.2f}; false-condition similarity: {false_similarity:.2f}.',
                    evidence=['The true condition matched the baseline response while the false condition produced a materially different response.'],
                    description='Paired non-destructive Boolean conditions produced a repeatable-looking response differential on a discovered input. Dynamic content can affect this heuristic; independently verify before confirming.',
                    impact='A vulnerable query may expose or alter data based on attacker-controlled conditions.',
                    remediation='Use parameterized queries and validate the input according to its expected type.',
                    cwe='CWE-89',
                    cvss=8.1,
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
                    detection_method='boolean_response_diff',
                    raw={'true_similarity': true_similarity, 'false_similarity': false_similarity},
                ))

        return {'findings': findings, 'payloads_tested': tested, 'parameters_tested': len(surfaces)}

    def test_idor(self):
        return {
            'findings': [],
            'patterns_tested': 0,
            'status': 'Not assessed',
            'limitations': [
                'Reliable IDOR/BOLA validation requires two authorized user identities and a known object owned by each identity.'
            ],
        }

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

    def check_owasp(self, all_results=None):
        all_results = all_results or {}
        categories = [
            ('A01 - Broken Access Control', [], 'Requires two authorized identities and known object ownership.'),
            ('A02 - Cryptographic Failures', ['ssl'], 'TLS observations only; application-level cryptographic design is not tested.'),
            ('A03 - Injection', ['xss', 'sqli'], 'Bounded reflected-markup and SQL error/Boolean differential probes.'),
            ('A04 - Insecure Design', [], 'Requires business-logic and threat-model review.'),
            ('A05 - Security Misconfiguration', ['headers'], 'Response security-header checks only.'),
            ('A06 - Vulnerable and Outdated Components', [], 'Versioned component identification and advisory matching are not implemented.'),
            ('A07 - Identification and Authentication Failures', [], 'Authentication policy and account lifecycle checks are not implemented.'),
            ('A08 - Software and Data Integrity Failures', [], 'Build, update, and integrity controls are not tested.'),
            ('A09 - Security Logging and Monitoring Failures', [], 'Logging and alert-response behavior require application-side validation.'),
            ('A10 - Server-Side Request Forgery', [], 'SSRF probes are intentionally not run by this scanner.'),
        ]
        findings = []
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}

        for category, result_keys, limitation in categories:
            if not result_keys:
                findings.append({
                    'category': category,
                    'checks': [],
                    'status': 'Not assessed',
                    'severity': 'Informational',
                    'cvss': 0.0,
                    'note': limitation,
                })
                continue

            observed = [finding for key in result_keys
                        for finding in all_results.get(key, {}).get('findings', [])
                        if finding.get('severity') != 'Informational']
            observed.sort(key=lambda item: severity_order.get(item.get('severity', 'Informational'), 4))
            findings.append({
                'category': category,
                'checks': result_keys,
                'status': 'Potential findings identified' if observed else 'No finding identified by configured checks',
                'severity': observed[0].get('severity', 'Informational') if observed else 'Informational',
                'cvss': observed[0].get('cvss', {}).get('score', 0.0) if observed else 0.0,
                'finding_count': len(observed),
                'note': limitation,
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
