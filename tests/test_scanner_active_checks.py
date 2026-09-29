import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from modules.scanner import VAPTScanner


class TestTargetHandler(BaseHTTPRequestHandler):
    def _send(self, body, status=200):
        encoded = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        path = urlparse(self.path)
        if path.path == '/':
            protected_link = '<a href="/private?id=9">Private</a>' if self.headers.get('Cookie') == 'session=authorized-test' else ''
            self._send(
                '<a href="/item?id=7">Item</a>'
                '<form action="/search" method="post"><input name="term"></form>'
                + protected_link
            )
        elif path.path == '/item':
            item_id = parse_qs(path.query).get('id', [''])[0]
            if "AND '1'='2" in item_id:
                self._send('<p>No records</p>')
            else:
                self._send('<p>Record available</p>')
        elif path.path == '/private':
            self._send('<p>Private record</p>' if self.headers.get('Cookie') == 'session=authorized-test' else 'Unauthorized', 200 if self.headers.get('Cookie') == 'session=authorized-test' else 401)
        else:
            self._send('Not found', 404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        values = parse_qs(self.rfile.read(length).decode())
        term = values.get('term', [''])[0]
        self._send(f'<p>Results for {term}</p>')

    def log_message(self, format_string, *args):
        pass


class ScannerActiveCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), TestTargetHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_xss_check_uses_discovered_post_form(self):
        scanner = VAPTScanner(self.target)
        crawl = scanner.crawl()

        result = scanner.test_xss(crawl)

        finding = next(item for item in result['findings'] if item['cwe'] == 'CWE-79')
        self.assertEqual(finding['endpoint'], self.target + '/search')
        self.assertEqual(finding['parameter'], 'term')
        self.assertEqual(finding['method'], 'POST')
        self.assertEqual(finding['confidence'], 'Medium')

    def test_sqli_checks_discovered_query_and_never_reports_simulation(self):
        scanner = VAPTScanner(self.target)
        crawl = scanner.crawl()

        result = scanner.test_sqli(crawl)

        finding = next(item for item in result['findings'] if item['cwe'] == 'CWE-89')
        self.assertEqual(finding['endpoint'], self.target + '/item?id=7')
        self.assertEqual(finding['parameter'], 'id')
        self.assertIn(finding['detection_method'], {'boolean_response_diff', 'database_error'})
        self.assertFalse(any('simulation' in item['title'].lower() for item in result['findings']))

    def test_auth_cookie_reaches_protected_discovery(self):
        scanner = VAPTScanner(self.target, auth_cookie='session=authorized-test')

        crawl = scanner.crawl()

        self.assertTrue(any('/private?id=9' in link for link in crawl['links']))

    def test_owasp_summary_does_not_claim_unperformed_checks_as_vulnerabilities(self):
        result = VAPTScanner(self.target).check_owasp({})

        self.assertEqual(len(result['findings']), 10)
        self.assertTrue(all(item['severity'] == 'Informational' for item in result['findings']))
        self.assertTrue(all(item['status'] == 'Not assessed' for item in result['findings']))


if __name__ == '__main__':
    unittest.main()