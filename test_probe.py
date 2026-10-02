import hashlib
import os
import unittest
from unittest.mock import patch
import probe


class ProbeChecks(unittest.TestCase):
    def test_certificate_substitution_rejected(self):
        original = b'certificate observed on the authorized gateway'
        pin = hashlib.sha256(original).hexdigest()
        self.assertEqual(probe.check_pin(original, pin), pin)
        with self.assertRaises(probe.CertificatePinError):
            probe.check_pin(b'a substituted certificate', pin)

    def test_malformed_pin_rejected(self):
        with self.assertRaises(ValueError):
            probe.normalize_pin('not-a-certificate-hash')

    def test_report_redacts_nested_credentials(self):
        with patch.dict(os.environ, {'HNC_VPN_PASSWORD': 'test-vpn-secret',
                                     'HNC_HTTP_PASSWORD': 'test-http-secret'}):
            report = probe.redact({'error': ['failure: test-vpn-secret',
                                           {'nested': 'test-http-secret'}]})
        self.assertEqual(report, {'error': ['failure: [REDACTED]',
                                           {'nested': '[REDACTED]'}]})

    def test_health_requires_its_own_credential(self):
        with patch.dict(os.environ, {}, clear=True):
            result = probe.health_check('http://127.0.0.1:1678', True, 1)
        self.assertFalse(result['attempted'])
        self.assertEqual(result['error'], 'HNC_HTTP_PASSWORD is required')

    def test_target_url_rejects_embedded_password(self):
        with self.assertRaises(ValueError):
            probe.health_check('http://user:test-password@127.0.0.1:1678', False, 1)

    def test_wrong_server_identity_is_not_accepted(self):
        payload = {'service': 'hnc-http-shell', 'host': 'TEST-HOST-A',
                   'user': 'test-user'}
        self.assertTrue(probe.validate_identity(payload, 'TEST-HOST-A', 'test-user'))
        self.assertFalse(probe.validate_identity(payload, 'TEST-HOST-B', 'test-user'))
        self.assertFalse(probe.validate_identity(payload, 'TEST-HOST-A', 'other-user'))
        self.assertFalse(probe.validate_identity([], 'TEST-HOST-A', 'test-user'))


if __name__ == '__main__':
    unittest.main()
