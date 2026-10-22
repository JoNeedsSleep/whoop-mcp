The local-interface listener package passed focused offline validation on
2026-10-20 in `postgres-listener-20261020a/attempt-20261020T050251-13d49a32`.
Seven selector tests, twelve isolation checks, nine packaged source/mode checks
and two actual image-entrypoint refusal cases passed. The latter used no network
and confirmed rejection of the missing `railnet0` layout and unexpected
arguments, with hostile inherited pre-main variables stripped. All three
containers were removed and no unresolved creates remained.

The immutable normal image is
`sha256:f2d9d80a1369f24db27c9604450c33b9c7cc0ef0e4d66a505ab8c5fb8e9e3172`.
Its eleven-file public context is 30,720 bytes, SHA-256
`f1f084254b4615e885a0f7049dd0ef76f0be72e3b01ec0dda71bb48e479a7f72`.
It adds only the pinned Node binary, strict interface selector and fixed shell
entrypoint to the normal PostgreSQL recipe. The stored configuration, TLS
identity, HBA and provisioning workflow remain unchanged; the selected private
IPv4/ULA addresses override only the listener at startup. No wildcard binding
or dependency fetch was added.

These AMD64 checks used OrbStack translation. Positive binding on a real
`railnet0` interface, verified TLS through that listener and PostgreSQL running
as PID 1 were not measured in this package run and remain live verification
gates. Earlier synthetic database workflow evidence below does not establish
those new listener properties. The first attempt is retained: its seven units
passed, then a strict environment-array ordering check failed before guard
startup; cleanup passed. The reviewed retry compares the complete sorted
environment list without permitting extra or duplicate entries. Runtime
advisories remain unresolved. Current live status is recorded separately in
`README.md` and `../railway/ACTIVATION.md`; the records below retain their
historical scope.

The provider's stopped-volume inspection subsequently confirmed only an empty,
root-owned `lost+found` directory (0700) beneath the root-owned volume (0755),
with all application/PostgreSQL paths absent. The compatibility change permits
that exact initial layout without deleting, changing ownership or changing the
mode of `lost+found`; other names, unsafe metadata and populated state remain
refused. Root initialization verifies emptiness through a nofollow directory
handle. Later UID 999 phases can check protected metadata but cannot enumerate
that root-owned directory; they do not claim to recheck its contents.

The replacement init image
`sha256:e2cbcd4b925fdd5b107cf8123eb436db6c863218ce6b15b7a476a35555a79a2f`
and provision image
`sha256:c5f27662c6cf44acfc1f5a541c17d7fac60663fcba7d91eb0d4261bed13f71fc`
passed the full isolated workflow in
`postgres-lostfound-20261020a/attempt-20261020T021706-ea8e05b7`.
Twelve unit tests and sixteen workflow records passed; the latter include the
unit-test group and a repeated runtime check, not sixteen distinct tests.
Actual fixed init, configure, enable, standard migrations, finalize, verified
TLS/runtime negatives and same-volume restart passed on the synthetic provider
layout. Each completed phase preserved the directory inode, ownership, mode,
mtime and ctime, and UID 999 enumeration failed with EACCES. Twelve isolation
checks preceded project execution, source hashes matched before/after, and all
sixteen containers plus the single disposable volume were removed. The normal
PostgreSQL image remained exactly `60b49b54...`; its full digest is recorded below.
The new init/provision public contexts are each 40,960 bytes, respectively
`3bd9477306f15037b9b9e42fac323014b257e7d729e7ddebc23abf633b0c3341`
and `693c9f186014337630d5e43fc7422edab2643ed1ed4864b5f8dc5d2d6d9091ad`.
These results authorize no provider action by themselves and do not establish
successful live initialization, secret delivery or runtime advisory clearance.

The live private service exists, but its first secret-free initializer deployment
`b12ac7d8-6115-4f80-8c36-d93c3ceeb449` failed with the fixed preparation error.
No database credential delivery or real migration has occurred. Successful local
initialization below does not establish successful provider initialization.

A separate read-only volume inspector is prepared as image
`sha256:d92e226fb44024ec47717624a157f64df8caa219d92ab4502c40d3fe54644b99`.
Evidence `postgres-inspect-20261020a/attempt-20261020T020522-60d0dd0f`
records eight unit tests, twelve isolation checks and four actual packaged root
inspection cases, including empty, lost+found, unknown and partial/symlink state.
Fixed secret/argument refusals and pre-main environment clearing passed. Both
containers were removed with no unresolved creates. The four-file public context
is 20,480 bytes, SHA-256
`9849304b1edbc151bc92f307515967693ee496a8c190576b9329ca799767e82a`.
The inspector reports only fixed metadata and recognized version/state enums;
it performs no intentional writes and does not emit names, contents or targets.
The tests checked unchanged content, mtime and ctime; ordinary filesystem atime
updates remain possible. These observations are not an atomic state attestation.
Stop other volume consumers before live inspection. At that stage, an initializer compatibility
change or retry remained blocked until inspection identified the actual state.
The first local 7/8 fixture failure is retained with successful cleanup; only a
mistaken asynchronous symlink call in the test fixtures changed before the pass.

The separate fixed root initializer was packaged and verified on 2026-10-19 as
`sha256:060db668ff3108fde7ebe762c1b633ca9c1230f0b5b590483f58a7bfdf91acb1`.
Its recipe uses the same eight reviewed public source files and pinned bases,
adds no install/RUN step, and fixes `init` in the entrypoint. It receives no
bootstrap or application input. After twelve offline isolation checks and all
packaged hashes/modes passed, the actual entrypoint initialized one fresh
exclusive disposable volume, permanently dropped all real/effective IDs to 999,
cleared effective/permitted/inheritable/ambient capabilities, retained NNP and
seccomp, and left private directories with no PostgreSQL process or listener.
A second invocation against that populated volume failed closed. All three
containers and the exact temporary volume were verified removed. Evidence is
`postgres-init-20261019a/attempt-20261020T011652-07e5978c`; the public ten-file
upload context SHA-256 is
`89fff1259b869d0145eb81150f1c03fae36d2d3ff26b9f3eb59c4765f2dd6bfb`.
Use this image's default command for the separate secret-free root phase, then
stop it before the non-root provisioning image uses that volume. This closes the
previous packaging gap where the local workflow used a Docker user override;
it does not establish live provider controls or clear runtime advisories.

The fresh-volume preparation helper subsequently passed seven unit tests and 15 recorded workflow checks on 2026-10-19 (16 recorded entries, one of which represents the seven-unit-test group; runtime permissions were checked again after restart). The provision image is `sha256:7620ff401b77e3a4f800891857f797ffc20d374a6092b1f46ffe12c424f49b14`; the normal PostgreSQL image with the volume-owned socket path is `sha256:60b49b540aca8ec2be2fb552bf2539a39cbcc971f83d64b18be17127dab64c53`. Both were built offline from the pinned AMD64 bases without installs. The copied Node binary actually ran as version 22.23.3 in the provision image.

The run exercised separate sequential containers sharing one fresh, uniquely labeled local volume: secret-free root init with only CHOWN/FOWNER/SETUID/SETGID, then UID/GID 999 with no capabilities for configure, enable and finalize. Each helper had no network. The real configure shell bridge consumed only a synthetic envelope; the actual `migrationFromStdin` bridge applied the standard migrations over verified TLS/SCRAM while the normal packaged PostgreSQL entrypoint ran in the test container. Normal startup used `/var/lib/postgresql/data/run`, with no `/var/run/postgresql` runtime mount. Each successful helper phase had stopped PostgreSQL, removed its PID/socket and released its lock before the next container mounted the volume. Reinitialization/repeated phases and malformed input were refused with fixed output. Final migration-password/membership/CREATE revocation, six-table CRUD, denied DDL/ledger/server-file/program access, TLS/plaintext/wrong-password/CA/hostname negatives and same-volume restart passed.

Twelve Node isolation checks passed before project execution, PostgreSQL containers had checked identity/NNP/seccomp/capability/resource controls, all 199 source hashes matched before and after, and every owned container plus the disposable volume was confirmed removed. No unresolved creates remain. Evidence is `postgres-provision-20261019a/attempt-20261019T054957-bbd00bef`. The preceding failed attempt is preserved: its seven unit tests passed, then the harness encountered Docker's omitted empty `Cmd` field before any database phase; its cleanup passed. The retry changed only that metadata normalization.

These results do not test Railway secret delivery/history removal, real assigned DNS/certificates, concurrent provider deployments, forced-child-timeout/ambiguous-shutdown branches, or partial-state recovery. Those remain operator/review gates. The helper retains its lock if child or daemon termination cannot be confirmed; it intentionally offers no automatic recovery. Normal PostgreSQL clears inherited environment but does not itself reject provisioning-variable presence, so removal must be verified before the fresh normal deployment.

The earlier package run below used the previous runtime socket location. Its source/image/evidence are retained; the newer run above verifies the volume-owned path and complete preparation workflow.

On 2026-10-19, the allowlisted AMD64 image `sha256:059f044db71faa4a509e5922627024abcac262959654e6c10176faf757d3c24a` was built offline from the pinned base and exercised with a fresh disposable PostgreSQL cluster. The run passed the real configuration/HBA startup, fresh-only provisioning, standard Drizzle migration, held-migrator and extra-ledger finalization rejection, committed migration revocation, six-table runtime CRUD and forbidden DDL/ledger/server-file/program access, TLS/SCRAM negatives with positive controls, same-data restart and broad key-permission startup rejection. Twelve recorded checks include repeated runtime permission checks after restart/recovery; they are not twelve distinct test cases.

The test used 500,000,000 bytes of PostgreSQL memory and 0.5 vCPU, synthetic credentials/certificates with the exact fixture DNS SAN, and no external network, host mounts, SSH or forwarded credentials. Twelve Node isolation checks passed before project execution; UID 999/no-new-privileges/empty capabilities were also checked for PostgreSQL. Source integrity and removal of all three owned containers were verified, with no unresolved creates. Private evidence: `postgres-package-20261019a/attempt-20261019T053434-ebc34c32`. No provider/database activation occurred. This used the actual locked `pg` client with explicit TLS settings and the reviewed one-off migrator source; the canonical backend URI/CA-file parser and separately built migrator image have their own verification records.

The remaining matrix below is a validation plan, not a claim every listed case was exercised. In particular, provider routing/limits, private provisioning delivery, additional malformed-state cases, expired-leaf/missing-key cases and backup restoration remain separate gates. The earlier migration utility's 15 tests remain independent evidence. Preserve exact source/image inventories and all failed attempts.

Use only fresh disposable containers/volumes for the following isolated run, with synthetic secrets and certificates. Before copying or executing project files, verify no host binds/SSH/credentials, exact images, private namespaces, dropped capabilities, no-new-privileges, read-only roots, bounded resources and network isolation. Disable OrbStack's per-container CA injection. A shared container loopback or isolated internal network may represent the approved private hostname; do not broaden production binding or disable TLS to accommodate the fixture.

1. Build from the explicit Docker allowlist with network disabled and no dependency installation. Check image architecture, PostgreSQL version, UID/GID 999, entrypoint, `setpriv` availability, cleared environment, labels and mounts. Verify missing configuration/data/key stops startup; inherited `POSTGRES_*`, `PG*`, preload/proxy variables and vendor init-script directories cannot trigger alternate initialization. The base image's declared volume/port metadata must not produce an anonymous volume or published listener.
2. Initialize only an empty synthetic directory, render the exact fixture hostname, provide a matching synthetic CA/leaf/key and start with the normal configuration. Inspect `pg_settings`/`pg_file_settings`, `pg_hba_file_rules`, actual listeners and kernel identity/NNP. Verify both IPv4/IPv6 matching is intentional for the fixture, no unexpected listener and no HBA parse errors. Certificate key/chain/SAN and private modes must match the fixed paths.
3. Use the actual locked Node `pg` backend parser/Pool and migration process for successful CA- and hostname-verified TLS/SCRAM connections. Negative cases: plaintext even with correct credentials, wrong password, wrong CA, wrong hostname, expired leaf, unsupported user/database, TCP admin, peer wrong OS/database role, missing key and broadly readable key. All must fail without secret-bearing output. Test the final canonical backend URI and strict public CA-file guard, not a less restrictive fixture shortcut.
4. Apply `00-provision.sql` to a fresh cluster and confirm all three non-admin roles are NOLOGIN, no global privileged attributes, exact owner/member options, no PUBLIC database/schema privileges and no application role membership. Reapplying refuses and leaves existing content unchanged. Reject wrong current database/administrator and partial/pre-existing state without DROP/overwrite.
5. Store only synthetic SCRAM passwords through a private channel, apply `10-enable-migration.sql`, and confirm only the migrator can log in, its deadline is at most one hour, owner CREATE exists only on `whoop`, no global CREATEDB/CREATEROLE or ADMIN OPTION exists and runtime remains disabled. Run the standard reviewed Drizzle utility. Verify three exact ledger entries and six tables owned by `whoop_owner`; exercise duplicate and failed-migration cases without enabling runtime.
6. Apply finalization while holding a migration session: it must commit revocation, fail runtime enablement, and leave the existing session for explicit operator cleanup. Close that fixture session and rerun successfully. Also test incorrect/missing/duplicate ledger rows and extra tables/ownership drift: runtime remains disabled, migrator stays disabled, and no automatic destructive cleanup occurs. Confirm the temporary password, membership, CONNECT and per-database CREATE are gone after both successful and failing finalization.
7. Connect as the final runtime using the actual backend TLS client. Prove INSERT/SELECT/UPDATE/DELETE with synthetic rows on each of the six tables. Deny schema/table/temporary table/database/role creation, SET ROLE owner/admin, ledger reads/writes, TRUNCATE, server-file/program functions, replication and grants to other roles. Inspect ACLs/default privileges, memberships and owner identities rather than relying only on one denied operation. Never apply these destructive probes to a real database.
8. Restart the same disposable database container/volume, confirm data/TLS/roles persist and no init/migration runs again. Remove disposable secrets and exact-owned containers/volumes; verify absence. Record failures, bounded sanitized evidence, source integrity, isolation results and cleanup separately.

After a separate real deployment approval, verify only safe non-destructive observations on the provider: correct personal project/environment/image, private assigned DNS/SAN/CA/listener, no public TCP proxy/domain, actual UID/NNP/mount/cgroup limits, no unexpected credentials in runtime environment, and observed egress/provider-access limitations. Confirm admin access is local-peer only, fresh database emptiness, independently bounded migration-job authority, successful revocation and guarded runtime TLS before WHOOP consent. Test restoration using synthetic data in a separate approved restore target before promising a recovery objective. Do not label local synthetic checks as live provider guarantees.
