This one-time metadata diagnostic compares the fixed database hostname's A/AAAA
answers with the PostgreSQL container's actual interfaces. It does not bind a
listener, connect to PostgreSQL, read configuration or credentials, or change
the volume. Only fixed system-DNS queries use the network.

Run the independently reviewed public command in the existing provision image
as UID/GID 999, with restart policy Never. Its fixed `setpriv`/`env -i` prefix
sets no-new-privileges before Node. The single-line data URL contains only the
hash-pinned built-in-only source plus `main()`; it is not a remote script URL.
The command reads no stdin and accepts no hostname, resolver or file argument.

Output contains at most eight bounded interface names, sixteen numeric local
addresses and eight DNS addresses, their fixed scope classifications, internal
flags, and exact local-interface matches. It excludes MAC addresses, netmasks,
CIDRs, environment values and raw errors. DNS has a three-second combined
deadline; overall cancellation is five seconds with one additional second for
bounded output. Missing or incomplete evidence is `UNKNOWN`.

`COMPLETE` means the metadata collection completed. It does not prove that an
interface is the intended private ingress, that binding will succeed, or that
other services cannot connect. Multiple private interfaces need explicit
interpretation before any listener change. Do not use this output to select
every RFC1918/ULA interface or fall back to a wildcard. TLS hostname identity,
HBA/SCRAM, lack of public ingress and cross-environment isolation remain
independent controls. Restore the prior service command after this one attempt.

Eight tests passed in a fresh offline Node 22 fixture, including the actual
UID/GID-999 child, kernel no-new-privileges, hostile pre-main environment
stripping, and generated-command execution. All twelve isolation checks,
three-file integrity checks and exact-owned cleanup passed. Evidence:
`postgres-interface-probe-20261020a/attempt-20261020T025209-505bccd8`.
The 8,769-byte public command SHA-256 is
`a6f751b1464ef4c9d57ff6c5d16f607ded19d4ca7792b75f924a77c2d67568a8`.
This validates the diagnostic package; it is not a live interface or listener
result.
