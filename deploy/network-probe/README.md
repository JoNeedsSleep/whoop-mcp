This one-time diagnostic tests whether the existing staging gateway can open a
TCP connection to the production database's current Railway private addresses.
It uses only Node built-ins in the already reviewed images. It creates no
service, image, account, SSH key or credential and reads no application files,
environment secrets, PostgreSQL rows, response bodies or authentication messages.
It sends zero application bytes. TCP reachability is enough to fail this gate;
TLS and database-role validation remain separate existing checks.

The single hostname is
`whoopindividualpostgreskill-2026.railway.internal`, port 5432. Positive mode
resolves both A and AAAA through system DNS, admits at most four canonical
RFC1918/ULA addresses in total, and requires every address to connect. Unexpected
address classes, incomplete resolution, excess addresses or any failed positive
connection produce no positive confirmation. Negative mode accepts only the
exact successful positive receipt, at most fifteen minutes old, and tests all
its addresses even when staging DNS cannot resolve the hostname. It never
substitutes staging DNS answers for the recorded targets.

The operator uses `command.mjs` only inside a reviewed offline fixture to format
the tested `probe.mjs` bytes, their independently recorded SHA256 and one exact
request. The generated Start Command uses absolute `setpriv --no-new-privs`,
then `env -i`, then Node. All four UID/GID values must be 1000 and the Node
environment must match four fixed values. The probe does not inspect `/proc` or
any other file; `setpriv` enforces NNP before Node. The isolated wrapper test
checks that kernel flag independently. No generic command, hostname, port,
resolver, TLS option or credential selector exists in the remote program.
The command is one line: a fixed `data:text/javascript;base64` import preserves
the exact reviewed program bytes without minification or an external loader.

Each DNS query has one attempt and a two-second resolver timeout, with a
three-second combined DNS deadline. At most four TCP attempts run concurrently,
one per address, each bounded to five seconds. The command has a twelve-second
overall cancellation deadline and at most one additional second to flush its
single metadata JSON record. It exits and performs no automatic retries.
Provider restart policy must be **Never** before it is installed.

The operator sequence is:

1. Keep health enablement blocked. Preserve the exact previous deployment/source
   and Start Command for both existing services. Confirm no bootstrap variable,
   migration credential or other newly delivered secret is needed by this test.
2. With the normal database running, execute positive mode on the existing
   production migration service using its pinned Node image. This temporarily
   replaces that service's job command and starts no migration or application.
   Record the explicit deployment ID, timestamp and the single
   `POSITIVE_CONFIRMED` result with all observed IP addresses.
3. Feed that exact receipt to the offline formatter; execute negative mode on the
   existing staging gateway within fifteen minutes. This temporarily interrupts
   gateway availability, reads no mounted state and starts no Tailscale process.
   It tests the container's Railway private network directly, without SOCKS.
   Any `CONNECTED` address produces `REACHABLE` and fails the isolation gate.
   Missing output, unknown errors, address drift or incomplete coverage is
   `UNKNOWN`, never a pass.
4. Restore the exact prior commands/source and verify the actual deployed
   manifests and normal service operation. A deliberately requested additional
   production positive check can bracket the negative test and confirm that the
   same targets remained available; no recheck is automatic.

`UNREACHABLE_OBSERVED` means that every recorded target timed out, refused the
connection or reported a fixed network-unreachable/permission error during this
bounded run. Correlate it with contemporaneous production success against the
same targets before accepting the gate. It is not permanent firewall
attestation, proof against provider compromise, or a claim that DNS failure
alone establishes isolation. A refused TCP connection without a healthy
production control is inconclusive.

Railway documents private networks as isolated per environment, but that is the
expected behavior, not the live evidence this diagnostic is meant to collect.
[Private networking](https://docs.railway.com/networking/private-networking/how-it-works).
Ordinary service SSH requires a registered account/workspace key; the existing
production project token must not be broadened for this check.
[Railway SSH](https://docs.railway.com/cli/ssh). The already authorized browser
service configuration flow can install these public commands without new
credentials. Configuration acknowledgment does not prove which command an
actual deployment ran; inspect the deployed manifest and associate its log
record explicitly.

The fresh isolated run `network-probe-20261020a/attempt-20261020T024500-82428823`
passed nine tests with zero failures/skips, all twelve isolation preflight
checks, all three source hashes before/after execution, and exact container
cleanup with no unresolved creates. Tests include a real loopback connection
that sends zero application bytes, refusal after the listener stops, timeout/
cancellation cleanup, malformed/stale receipts, both address families, and
the actual generated command with hostile inherited Node/OpenSSL settings.
The wrapper's NNP value was measured as 1 in the already restricted fixture;
this run does not claim an independent 0-to-1 transition measurement.

The public production-positive command is 12,203 bytes, SHA256
`0427256a861cca78e09c9b8741d090a3d53ef37265263c17d89e8545159a0eb6`.
Its payload matches tested `probe.mjs` SHA256
`9ff2236d04f6942e5629e8a88b13e8884698ae86e3b82777e7b2eb9aa591906d`
and only the fixed positive-mode request. The command was formatted inside the
offline fixture and was not run against Railway. Negative-command generation
must wait for the actual successful positive receipt and preserve its complete
target set. No live DNS/network isolation result, provider mutation, fresh
credential, image or service is established by this preparation.

The earlier nine-test run `attempt-20261020T023424-18132e1f` is retained.
Its multiline command was rejected by the provider's single-line form field
before saving. The follow-up changed only command encoding and its regression
assertions; the probe source and network limits are unchanged. Tests execute the
single-line wrapper and verify that decoding it reproduces every program byte.
