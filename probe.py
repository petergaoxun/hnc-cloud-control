#!/usr/bin/env python3
"""Read-only preflight and HTTP identity checks; does not authenticate a VPN."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request


class CertificatePinError(Exception):
    pass


def normalize_pin(value):
    value = value.replace(':', '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError('Certificate SHA256 must contain exactly 64 hexadecimal digits')
    return value


def check_pin(certificate, expected):
    actual = hashlib.sha256(certificate).hexdigest()
    if not hmac.compare_digest(actual, normalize_pin(expected)):
        raise CertificatePinError('The gateway certificate does not match the expected SHA256')
    return actual


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, pin, verification=None, **kwargs):
        self.pin = normalize_pin(pin)
        self.verification = verification if verification is not None else {}
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs['context'] = context
        super().__init__(host, **kwargs)

    def connect(self):
        super().connect()
        try:
            check_pin(self.sock.getpeercert(binary_form=True), self.pin)
            self.verification['validated'] = True
        except Exception:
            self.close()
            raise


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pin, verification=None):
        self.pin = normalize_pin(pin)
        self.verification = verification if verification is not None else {}
        super().__init__()

    def https_open(self, request):
        def connect(host, **kwargs):
            return PinnedHTTPSConnection(host, pin=self.pin,
                                         verification=self.verification, **kwargs)
        return self.do_open(connect, request)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def redact(value):
    secrets = [os.environ.get(key, '') for key in
               ('HNC_VPN_PASSWORD', 'HNC_HTTP_PASSWORD')]
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, '[REDACTED]')
    return value


def tcp_check(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {'reachable': True}
    except OSError as exc:
        return {'reachable': False, 'error': str(exc)[:500]}


def gateway_check(host, port, pin, timeout):
    # A supplied pin validates the peer certificate. No VPN credentials are sent.
    context = ssl.create_default_context()
    if pin:
        normalize_pin(pin)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as peer:
                certificate = peer.getpeercert(binary_form=True)
                fingerprint = (check_pin(certificate, pin) if pin else
                               hashlib.sha256(certificate).hexdigest())
                return {'tlsEstablished': True, 'certificateValidated': True,
                        'validation': 'sha256-pin' if pin else 'system-ca-and-hostname',
                        'certificateSHA256': fingerprint, 'tlsVersion': peer.version(),
                        'vpnCredentialsSent': False}
    except (OSError, CertificatePinError) as exc:
        return {'tlsEstablished': False, 'certificateValidated': False,
                'error': str(exc)[:500], 'vpnCredentialsSent': False}


def gateway_http_check(host, port, pin, timeout):
    request = urllib.request.Request('https://{}:{}/'.format(host, port), method='GET')
    verification = {'validated': False if pin else None}
    handlers = [NoRedirectHandler()]
    if pin:
        handlers.append(PinnedHTTPSHandler(pin, verification))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            return {'httpStatus': response.status, 'certificateValidated': True,
                    'vpnCredentialsSent': False}
    except urllib.error.HTTPError as exc:
        # An HTTP rejection or redirect still follows validated TLS.
        return {'httpStatus': exc.code, 'certificateValidated': True,
                'vpnCredentialsSent': False}
    except (OSError, ValueError, urllib.error.URLError, CertificatePinError) as exc:
        return {'certificateValidated': verification['validated'], 'error': str(exc)[:500],
                'vpnCredentialsSent': False}


def validate_identity(payload, expected_host, expected_user):
    return (isinstance(payload, dict) and expected_host is not None
            and payload.get('service') == 'hnc-http-shell'
            and payload.get('host') == expected_host
            and payload.get('user') == expected_user)


def health_check(url, authenticate, timeout, expected_host=None, expected_user=None):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('A target must be an HTTP or HTTPS service URL')
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Credentials and query strings do not belong in target URLs')
    password = os.environ.get('HNC_HTTP_PASSWORD', '') if authenticate else ''
    if authenticate and not password:
        return {'attempted': False, 'error': 'HNC_HTTP_PASSWORD is required'}
    headers = {}
    username = expected_user or os.environ.get('HNC_HTTP_USER', '')
    if authenticate and not username:
        return {'attempted': False, 'error': 'HNC_HTTP_USER or --expected-user is required'}
    if authenticate:
        headers['Authorization'] = 'Basic ' + base64.b64encode(
            (username + ':' + password).encode('utf-8')).decode('ascii')
    request = urllib.request.Request(url.rstrip('/') + '/health', headers=headers)
    # Unlike the existing Windows client, this respects the cloud HTTP/HTTPS proxy.
    opener = urllib.request.build_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            content = response.read(32769)
            if len(content) > 32768:
                raise ValueError('Health response exceeds 32 KiB')
            payload = json.loads(content.decode('utf-8'))
            if not isinstance(payload, dict):
                raise ValueError('Health response must be a JSON object')
            matched = validate_identity(payload, expected_host, username)
            allowed = ('service', 'version', 'host', 'user', 'pid', 'python')
            return {'attempted': True, 'httpStatus': response.status,
                    'authenticated': authenticate and matched,
                    'identityMatched': matched, 'expectedHost': expected_host,
                    'identity': {key: payload.get(key) for key in allowed}}
    except urllib.error.HTTPError as exc:
        # Response bodies, cookies and authorization headers are not recorded.
        return {'attempted': True, 'httpStatus': exc.code, 'authenticated': False}
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return {'attempted': True, 'authenticated': False, 'error': str(exc)[:500]}


def runtime_check():
    capabilities = None
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('CapEff:'):
                capabilities = int(line.split()[1], 16)
    except OSError:
        pass
    tun = Path('/dev/net/tun')
    try:
        tun_character_device = stat.S_ISCHR(tun.stat().st_mode)
    except OSError:
        tun_character_device = False
    return {'os': platform.system(), 'release': platform.release(),
            'architecture': platform.machine(), 'python': platform.python_version(),
            'uid': os.geteuid() if hasattr(os, 'geteuid') else None,
            'tunCharacterDevice': tun_character_device,
            'effectiveNetAdminCapability': (bool(capabilities & (1 << 12))
                                             if capabilities is not None else None),
            'tools': {name: bool(shutil.which(name)) for name in
                      ('UniVPNCS', 'SecoClientCS', 'openconnect', 'docker', 'ip', 'sudo')},
            'proxyVariablePresent': {key: bool(os.environ.get(key)) for key in
                                     ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                                      'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')},
            'credentialsPresent': {key: bool(os.environ.get(key)) for key in
                                   ('HNC_VPN_PASSWORD', 'HNC_HTTP_PASSWORD')}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True, choices=('local', 'codex-cloud'))
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--cert-sha256')
    parser.add_argument('--targets', nargs='+', required=True)
    parser.add_argument('--expected-hosts', nargs='+')
    parser.add_argument('--expected-user')
    parser.add_argument('--authenticated-health', action='store_true')
    parser.add_argument('--timeout', type=float, default=5)
    parser.add_argument('--output', default='report.json')
    args = parser.parse_args()
    if args.expected_hosts and len(args.expected_hosts) != len(args.targets):
        parser.error('--expected-hosts must contain one host per target')
    if args.authenticated_health and not args.expected_hosts:
        parser.error('Authenticated acceptance requires --expected-hosts')
    expected_hosts = args.expected_hosts or [None] * len(args.targets)
    report = {'checkedAtUTC': datetime.now(timezone.utc).isoformat(),
              'declaredExecutionOrigin': args.origin,
              'runtime': runtime_check(),
              'gateway': {'host': args.gateway, 'port': args.port,
                          'tcp': tcp_check(args.gateway, args.port, args.timeout),
                          'tls': gateway_check(args.gateway, args.port,
                                               args.cert_sha256, args.timeout),
                          'httpWithConfiguredProxySettings': gateway_http_check(
                              args.gateway, args.port, args.cert_sha256, args.timeout)},
              'vpnAuthenticationAttempted': False, 'targets': []}
    for url, expected_host in zip(args.targets, expected_hosts):
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        report['targets'].append({'url': url,
                                 'directTcp': tcp_check(parsed.hostname, port, args.timeout),
                                 'healthViaConfiguredProxy': health_check(
                                     url, args.authenticated_health, args.timeout,
                                     expected_host, args.expected_user)})
    report = redact(report)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    Path(args.output).write_text(text + '\n', encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
