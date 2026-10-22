# Quiet local receipts

`check.py` makes one credential-free request to the existing private synthetic
gateway. It verifies TLS for the fixed gateway hostname at `100.123.224.33:443`,
then requires HTTP 401 and the exact expected Bearer resource-metadata challenge.
It reads at most 4096 header bytes, stops before the response body, follows no
redirects, retries nothing, and shares one ten-second network deadline. No WHOOP
data, login, token, provider API, subprocess or external monitoring account is
used. The script requires Python 3.11 or later and its standard library only.

This checks a TLS/authentication boundary, **not backend or WHOOP health**.
Every receipt explicitly marks deployment changes, configuration changes,
Tailscale changes, suspicious login activity and backend/upstream health as
`not_checked`. Unreachable services or unavailable local trust roots produce
`unknown`, never a healthy result. A successful receipt says only
`checked_subset_passed`; a compromised gateway can still return the expected 401.

Create an explicit directory owned by the current user with mode 0700. Invoke
the reviewed, hash-pinned script with an empty environment before Python starts:

```sh
/usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin \
  /absolute/path/to/python3 -I -B -S /absolute/path/to/check.py \
  --receipt-dir /absolute/private/receipt-directory
```

The empty environment excludes OpenSSL configuration and key-logging overrides;
`-I -B -S` excludes Python environment/site imports and bytecode writes. The
checker loads the Python/OpenSSL installation's compiled default CA locations
with hostname verification enabled. If those roots are unavailable it fails
closed; it never bypasses certificate errors.

Each successful invocation silently creates a new timestamped JSON receipt with
mode 0600 and atomically replaces a 0600 `latest.json` pointer containing only
that receipt's basename. Prior receipts are retained. A local lock prevents
overlapping runs; symlinked directories/files, hard-linked pointers and broad
permissions are rejected. Receipts contain only fixed outcomes/reasons and local
timestamps, never remote headers, bodies, errors, addresses or credentials.
No popup, email or alert is generated. Exit 0 means the receipt was written,
including an `unknown` or failing check; exit 2 means the receipt could not be
produced. A fixed error is the only normal stderr output.

An optional hourly local schedule must use the same reviewed script hash and
private directory. It works only while the laptop, scheduler and personal
Tailscale connection are available. A stale latest timestamp is a gap, not a
healthy observation; this is not an independent deadman or account audit.

The unittest suite uses synthetic files and mocked sockets/TLS only. Run it in
the approved isolated Python environment; there are no live requests in tests.
Live verification and schedule activation are separate operator actions.

## Validation and local activation — 2026-10-19

Independent review and all eight tests passed in a disposable, digest-pinned
Python 3.13.16 container. Twelve isolation checks verified an unprivileged
process, empty credential environment, read-only root, private scratch, no host
mounts or credential sockets, no capabilities, and no external network access.
The checker/test hashes matched before and after execution; cleanup was verified.
An initial harness preflight failed before project execution because its UID
assertion expected three values instead of four; that attempt was retained and
the corrected harness passed in a fresh container.

A separate credential-free live observation at `2026-10-19T18:53:13Z` verified
the private gateway certificate/hostname and exact unauthenticated 401 challenge.
It wrote a private receipt with result `checked_subset_passed`. This does not
establish upstream health or exclude compromise.

The owner's laptop now has the hourly Codex heartbeat `WHOOP local receipts`,
with routine notifications muted. It verifies the reviewed script SHA-256
`ae609ed99297b6fc62b8e45c065d050ad4d55d3a4cfe826c0cbb7df6ef1336ba`
before executing it with an empty environment. It performs no automatic fixes,
provider/account checks or real WHOOP activation. Changing the script requires
review and an explicit schedule update; a hash mismatch stops execution.
No service deployment or seven-day authentication setting changed.
