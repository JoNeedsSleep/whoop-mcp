"""Offline tests: synthetic files and mocked network/process boundaries only."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('receipt_check', Path(__file__).with_name('check.py'))
check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
CHALLENGE = ('Bearer resource_metadata="https://' + check.GATEWAY_HOST + '/.well-known/oauth-protected-resource"').encode()
GOOD_HEADER = b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: ' + CHALLENGE + b'\r\nContent-Length: 30\r\n\r\n'


class FakeTLS:
    def __init__(self, data=GOOD_HEADER + b'SECRET BODY MUST NOT BE READ', error=None):
        self.data = data; self.error = error; self.sent = b''; self.read = 0; self.closed = False; self.timeouts = []
    def settimeout(self, value): self.timeouts.append(value)
    def do_handshake(self):
        if self.error: raise self.error
    def selected_alpn_protocol(self): return 'http/1.1'
    def sendall(self, data): self.sent += data
    def recv(self, amount):
        assert amount == 1
        value = self.data[self.read:self.read + amount]; self.read += len(value); return value
    def close(self): self.closed = True


class ReceiptTests(unittest.TestCase):
    def probe(self, stream):
        raw = Mock(); context = Mock(); context.wrap_socket.return_value = stream
        with patch.object(check, 'tls_context', return_value=context), patch.object(check.socket, 'create_connection', return_value=raw) as connect:
            value = check.probe_gateway(time.monotonic() + 20)
        connect.assert_called_once(); self.assertEqual(connect.call_args.args[0], (check.GATEWAY_IP, 443))
        context.wrap_socket.assert_called_once_with(raw, server_hostname=check.GATEWAY_HOST, do_handshake_on_connect=False)
        self.assertTrue(stream.closed)
        return value

    def test_exact_tls_target_header_only_and_expected_challenge(self):
        stream = FakeTLS(); result = self.probe(stream)
        self.assertEqual(result['gateway_tls']['status'], 'pass')
        self.assertEqual(result['gateway_unauthenticated_boundary']['status'], 'pass')
        self.assertEqual(stream.read, len(GOOD_HEADER)); self.assertNotIn(b'Authorization', stream.sent)
        self.assertTrue(stream.sent.startswith(b'GET /data/snapshot HTTP/1.1\r\n'))
        self.assertTrue(all(0 < value <= 10 for value in stream.timeouts))

    def test_redirect_missing_duplicate_or_foreign_challenge_never_passes(self):
        for header in [b'HTTP/1.1 302 Found\r\nLocation: https://secret.invalid\r\n\r\n',
                       b'HTTP/1.1 401 Unauthorized\r\n\r\n',
                       GOOD_HEADER.replace(CHALLENGE, b'Bearer resource_metadata="https://evil.invalid"'),
                       GOOD_HEADER.replace(b'Content-Length: 30', b'WWW-Authenticate: ' + CHALLENGE)]:
            with self.subTest(header=header[:12]):
                self.assertEqual(self.probe(FakeTLS(header))['gateway_unauthenticated_boundary']['status'], 'fail')

    def test_invalid_or_oversized_headers_are_bounded_and_unknown(self):
        for data in [b'x' * 10000, b'HTTP/1.1 401\r\n bad-header\r\n\r\n', b'', b'HTTP/1.1 401\r\nX']:
            stream = FakeTLS(data); output = self.probe(stream)
            self.assertLessEqual(stream.read, 4096)
            self.assertEqual(output['gateway_unauthenticated_boundary']['status'], 'unknown')

    def test_tls_certificate_failure_and_deadline_are_not_healthy(self):
        stream = FakeTLS(error=ssl.SSLCertVerificationError('SECRET CERT ERROR'))
        output = self.probe(stream); self.assertEqual(output['gateway_tls']['status'], 'fail')
        self.assertNotIn('SECRET', json.dumps(output))
        output = self.probe(FakeTLS(error=socket.timeout('SECRET TIMEOUT')))
        self.assertEqual(output['gateway_tls']['status'], 'unknown')
        self.assertEqual(output['gateway_unauthenticated_boundary']['status'], 'unknown')

    def test_tls_roots_and_alpn_cannot_be_overridden_by_environment(self):
        context = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
        defaults = Mock(openssl_cafile='/fixed/roots.pem', openssl_capath='/fixed/roots')
        with patch.dict(os.environ, {'SSL_CERT_FILE': '/evil/root', 'SSL_CERT_DIR': '/evil/dir'}), \
             patch.object(check.ssl, 'SSLContext', return_value=context), \
             patch.object(check.ssl, 'get_default_verify_paths', return_value=defaults), \
             patch.object(check.os.path, 'isfile', return_value=True), patch.object(check.os.path, 'isdir', return_value=True):
            self.assertIs(check.tls_context(), context)
        context.load_verify_locations.assert_called_once_with(cafile='/fixed/roots.pem', capath='/fixed/roots')
        context.set_alpn_protocols.assert_called_once_with(['http/1.1'])

    def test_receipts_private_atomic_latest_and_no_network_output(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700); fd = check.private_directory(directory)
            self.addCleanup(os.close, fd)
            for value in [{'version': 1, 'result': 'incomplete'}, {'version': 1, 'result': 'attention'}]:
                check.write_receipt(fd, value)
            pointer = json.loads(Path(directory, 'latest.json').read_text())
            self.assertEqual(json.loads(Path(directory, pointer['receipt']).read_text())['result'], 'attention')
            receipts = list(Path(directory).glob('receipt-*.json')); self.assertEqual(len(receipts), 2)
            for file in [*receipts, Path(directory, 'latest.json')]:
                self.assertEqual(file.stat().st_mode & 0o777, 0o600); self.assertEqual(file.stat().st_nlink, 1)

    def test_unsafe_directory_symlink_pointer_hardlink_and_malformed_pointer_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent, 'private'); directory.mkdir(mode=0o700)
            alias = Path(parent, 'alias'); alias.symlink_to(directory)
            with self.assertRaises(ValueError): check.private_directory(str(alias))
            directory.chmod(0o755)
            with self.assertRaises(ValueError): check.private_directory(str(directory))
            directory.chmod(0o700); fd = check.private_directory(str(directory)); self.addCleanup(os.close, fd)
            target = Path(parent, 'target'); target.write_text('DO NOT CHANGE'); target.chmod(0o600)
            pointer = directory / 'latest.json'; pointer.symlink_to(target)
            with self.assertRaises(OSError): check.write_receipt(fd, {'version': 1})
            pointer.unlink(); os.link(target, pointer)
            with self.assertRaises(ValueError): check.write_receipt(fd, {'version': 1})
            pointer.unlink(); pointer.write_text('{"version":1,"receipt":"../../escape"}'); pointer.chmod(0o600)
            with self.assertRaises(ValueError): check.write_receipt(fd, {'version': 1})
            self.assertEqual(target.read_text(), 'DO NOT CHANGE')

    def test_quiet_main_records_unknown_and_explicit_not_checked_coverage(self):
        unknown = {'gateway_tls': check.result('unknown', 'not_observed'), 'gateway_unauthenticated_boundary': check.result('unknown', 'not_observed')}
        with tempfile.TemporaryDirectory() as directory, patch.object(check, 'probe_gateway', return_value=unknown), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            os.chmod(directory, 0o700)
            self.assertEqual(check.main(['--receipt-dir', directory]), 0)
            pointer = json.loads(Path(directory, 'latest.json').read_text())
            receipt = json.loads(Path(directory, pointer['receipt']).read_text())
        self.assertEqual(out.getvalue(), ''); self.assertEqual(err.getvalue(), '')
        self.assertEqual(receipt['result'], 'incomplete')
        for key in ('deployment_changes', 'configuration_changes', 'tailscale_changes', 'suspicious_login_activity', 'backend_upstream_health'):
            self.assertEqual(receipt['checks'][key]['status'], 'not_checked')


if __name__ == '__main__':
    unittest.main()
