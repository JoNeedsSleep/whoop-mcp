"""Quiet, on-demand local receipts. Standard library only; no provider mutations."""
import argparse
import datetime
import fcntl
import json
import os
import re
import signal
import socket
import ssl
import stat
import sys
import time
import uuid

GATEWAY_IP = '100.123.224.33'
GATEWAY_HOST = 'whoop-individual-staging-gateway-kill-2026-11-18.tail3104cf.ts.net'
RECEIPT_NAME = re.compile(r'receipt-[0-9]{8}T[0-9]{12}Z-[a-f0-9]{32}\.json\Z')
TLS_SECONDS = 10


def require(condition):
    if not condition:
        raise ValueError('LOCAL_CHECK_UNAVAILABLE')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)


def result(status, reason):
    return {'status': status, 'reason': reason}


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError()
    return value


def private_directory(directory):
    require(isinstance(directory, str) and os.path.isabs(directory) and os.path.normpath(directory) == directory
            and os.path.realpath(directory) == directory)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700):
        os.close(fd)
        require(False)
    return fd


def private_read(directory_fd, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= maximum)
        raw = b''
        while len(raw) <= maximum:
            chunk = os.read(fd, maximum + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(fd)
        require(len(raw) == before.st_size and len(raw) <= maximum and
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return raw
    finally:
        os.close(fd)


def tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Explicit compiled default roots avoid SSL_CERT_FILE / SSL_CERT_DIR overrides.
    defaults = ssl.get_default_verify_paths()
    cafile = defaults.openssl_cafile if os.path.isfile(defaults.openssl_cafile) else None
    capath = defaults.openssl_capath if os.path.isdir(defaults.openssl_capath) else None
    require(cafile is not None or capath is not None)
    context.load_verify_locations(cafile=cafile, capath=capath)
    context.set_alpn_protocols(['http/1.1'])
    require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED)
    return context


def probe_gateway(deadline):
    checks = {'gateway_tls': result('unknown', 'not_observed'),
              'gateway_unauthenticated_boundary': result('unknown', 'not_observed')}
    raw = stream = None
    try:
        deadline = min(deadline, time.monotonic() + TLS_SECONDS)
        context = tls_context()
        raw = socket.create_connection((GATEWAY_IP, 443), timeout=remaining(deadline))
        stream = context.wrap_socket(raw, server_hostname=GATEWAY_HOST, do_handshake_on_connect=False)
        stream.settimeout(remaining(deadline)); stream.do_handshake()
        require(stream.selected_alpn_protocol() in (None, 'http/1.1'))
        checks['gateway_tls'] = result('pass', 'certificate_hostname_verified')
        request = ('GET /data/snapshot HTTP/1.1\r\nHost: ' + GATEWAY_HOST +
                   '\r\nAccept: application/json\r\nConnection: close\r\n\r\n').encode('ascii')
        stream.settimeout(remaining(deadline)); stream.sendall(request)
        header = bytearray()
        # One application byte at a time stops exactly at the header delimiter;
        # no response body is read, parsed, persisted or displayed.
        while not header.endswith(b'\r\n\r\n') and len(header) < 4096:
            stream.settimeout(remaining(deadline))
            byte = stream.recv(1)
            if not byte:
                break
            header.extend(byte)
        require(header.endswith(b'\r\n\r\n'))
        line = bytes(header).split(b'\r\n', 1)[0]
        match = re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?', line)
        require(match is not None)
        status = int(match.group(1))
        challenges = []
        for row in bytes(header).split(b'\r\n')[1:-2]:
            require(b':' in row and not row.startswith((b' ', b'\t')))
            name, value = row.split(b':', 1)
            require(re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is not None)
            if name.lower() == b'www-authenticate':
                challenges.append(value.strip(b' \t'))
        expected_challenge = ('Bearer resource_metadata="https://' + GATEWAY_HOST + '/.well-known/oauth-protected-resource"').encode('ascii')
        accepted = status == 401 and challenges == [expected_challenge]
        checks['gateway_unauthenticated_boundary'] = result(
            'pass' if accepted else 'fail', 'expected_401_and_challenge' if accepted else 'unexpected_status_or_challenge')
    except ssl.SSLCertVerificationError:
        checks['gateway_tls'] = result('fail', 'certificate_verification_failed')
    except (TimeoutError, socket.timeout):
        checks['gateway_unauthenticated_boundary'] = result('unknown', 'deadline_or_network_timeout')
    except (OSError, ValueError, ssl.SSLError):
        checks['gateway_unauthenticated_boundary'] = result('unknown', 'connection_or_response_unavailable')
    finally:
        if stream is not None:
            stream.close()
        elif raw is not None:
            raw.close()
    return checks


def collect():
    checks = probe_gateway(time.monotonic() + TLS_SECONDS)
    for key in ('deployment_changes', 'configuration_changes', 'tailscale_changes',
                'suspicious_login_activity', 'backend_upstream_health'):
        checks[key] = result('not_checked', 'outside_current_coverage')
    statuses = [value['status'] for value in checks.values()]
    outcome = 'attention' if 'fail' in statuses else 'incomplete' if 'unknown' in statuses else 'checked_subset_passed'
    return {'version': 1, 'checkedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
            'result': outcome, 'checks': checks}


def write_receipt(directory_fd, receipt):
    raw = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    require(len(raw) <= 8192)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    name = 'receipt-' + stamp + '-' + uuid.uuid4().hex + '.json'
    require(RECEIPT_NAME.fullmatch(name) is not None)
    try:
        previous = decode(private_read(directory_fd, 'latest.json', 512))
        require(isinstance(previous, dict) and set(previous) == {'version', 'receipt'} and previous['version'] == 1
                and isinstance(previous['receipt'], str) and RECEIPT_NAME.fullmatch(previous['receipt']))
    except FileNotFoundError:
        pass
    def create(filename, content):
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(content); out.flush(); os.fsync(out.fileno())
        except BaseException:
            # Keep partial evidence; never overwrite a prior receipt.
            raise
    create(name, raw)
    pointer = 'latest-' + uuid.uuid4().hex + '.tmp'
    create(pointer, (json.dumps({'version': 1, 'receipt': name}) + '\n').encode('ascii'))
    os.replace(pointer, 'latest.json', src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt-dir', required=True)
    args = parser.parse_args(argv)
    directory_fd = private_directory(args.receipt_dir)
    lock_fd = None
    try:
        lock_fd = os.open('.check.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory_fd)
        lock = os.fstat(lock_fd)
        require(stat.S_ISREG(lock.st_mode) and lock.st_uid == os.getuid() and stat.S_IMODE(lock.st_mode) == 0o600 and lock.st_nlink == 1)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        write_receipt(directory_fd, collect())
        return 0
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(directory_fd)


def cancelled(_signal, _frame):
    raise KeyboardInterrupt()


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, cancelled)
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyboardInterrupt):
        # Normal unknown/failing checks are in the receipt. Only a failed receipt
        # write/configuration produces a fixed stderr error; never raw exceptions.
        print('Local security receipt unavailable.', file=sys.stderr)
        raise SystemExit(2)
