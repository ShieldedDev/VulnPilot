import unittest

from modules.config import ScannerConfig
from modules.finding import Finding


class ScannerConfigTests(unittest.TestCase):
    def test_defaults_are_safe(self):
        config = ScannerConfig()
        self.assertGreater(config.timeout, 0)
        self.assertGreater(config.retries, 0)
        self.assertGreater(config.concurrency, 0)
        self.assertGreater(config.rate_limit, 0)
        self.assertTrue(config.user_agent)

    def test_scope_defaults_are_enforced(self):
        config = ScannerConfig()
        self.assertEqual(config.allowed_ports, [])
        self.assertEqual(config.excluded_ports, [])
        self.assertEqual(config.excluded_paths, [])
        self.assertEqual(config.allowed_paths, [])


class FindingTests(unittest.TestCase):
    def test_finding_is_normalized(self):
        finding = Finding(
            title='Missing security headers',
            severity='Medium',
            confidence='High',
            target='https://example.com',
            endpoint='/',
            evidence=['missing x-frame-options'],
            description='The application does not set X-Frame-Options.',
            remediation='Add X-Frame-Options with a strict policy.',
            cwe='CWE-1021',
        )

        payload = finding.to_dict()
        self.assertEqual(payload['title'], 'Missing security headers')
        self.assertEqual(payload['severity'], 'Medium')
        self.assertEqual(payload['confidence'], 'High')
        self.assertIn('evidence', payload)
        self.assertEqual(payload['status'], 'open')
        self.assertEqual(payload['cvss']['score'], 0.0)

    def test_finding_keeps_evidence_list(self):
        finding = Finding(
            title='Header check',
            severity='Low',
            confidence='Medium',
            target='https://example.com',
            endpoint='/',
            evidence=['Server header present'],
            description='The Server header leaks technology details.',
            remediation='Remove or mask the Server header.',
        )

        self.assertEqual(len(finding.evidence), 1)
        self.assertIn('Server header present', finding.evidence)


if __name__ == '__main__':
    unittest.main()
