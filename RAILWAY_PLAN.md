# Proposed Railway deployment

Research checked against official documentation on 2026-10-18. The approved empty Railway project `whoop_individual_kill-2026-11-18` now exists, with ID `657e4033-3a47-4d99-ad5a-f934e2a11528`. Private runtime/transport source is implemented, but no application service has been deployed and no real WHOOP/Tailscale connection, DNS change or installed-client configuration has occurred. This is not a verified production setup. Keep the PR draft and unmerged. Website and School files remain outside this plan.

## Recommendation and security boundary

Railway Hobby is a reasonable small-hosting option **if all remote services are treated as potentially compromised**. The separately reviewed local MCP reader must remain offline and expose only its bundled tool definition and validated local cache. A separate, user-controlled sync process obtains the fixed seven-day snapshot; tool calls must never trigger remote requests. Remote hosting must contain no model-account credentials, personal files, SSH forwarding, GitHub token or Railway administrator/deployment token.

Railway does **not** satisfy the earlier requirement for independently enforced, default-deny remote egress. A Railway employee states that service IPv4 internet access cannot be disabled, destination/DNS allowlists are unavailable, and services within one environment have no per-service network allowlist. A proxy environment variable, application URL validation or Tailscale routing would not stop compromised code from opening a direct internet connection. Accepting this limitation is necessary before choosing this deployment; it must not be described as equivalent to the verified offline testing containers. [Railway's explicit egress-policy answer](https://station.railway.com/questions/technical-inquiry-network-isolation-fo-09930e2a)

Remote compromise can expose WHOOP health data and WHOOP-specific credentials, fabricate plausible metrics, and deny service. Local numeric schema validation cannot authenticate health values or eliminate information encoded in permitted numbers. The local cache and parser are the client-facing boundary, not a promise that Railway or the remote gateway stays trusted.

## Small initial layout

Use one dedicated project/environment containing only this application, with one replica per service:

| Service | Persistent data | Runtime credentials |
| --- | --- | --- |
| WHOOP backend | Dedicated PostgreSQL database | WHOOP OAuth credentials, dedicated DB role, session secret, summary-token verifier hash |
| PostgreSQL | Its own volume | Dedicated database credentials; no unrelated databases |
| Gateway data endpoint | Its own SQLite volume | Dedicated owner-secret verifier and WHOOP-summary machine credential; separate client grants |

Start in **US East, Virginia** (`us-east4-eqdc4a`), with all services in the same region. This is a proposed placement, not a user-selected or provisioned region. Railway also documents California, Amsterdam and Singapore. Moving a service with a volume causes a volume migration and downtime. [Railway regions](https://docs.railway.com/deployments/regions)

PostgreSQL should have no public domain or TCP proxy. Use its private connection URL and a restricted application role. Railway private traffic is encrypted with WireGuard and scoped to the project/environment, but this is a shared remote trust domain: separate service names do not establish an independent security boundary between the backend and gateway. Keep all unrelated applications out. [Private networking](https://docs.railway.com/networking/private-networking), [private domain scope](https://docs.railway.com/networking/domains/working-with-domains)

The default PostgreSQL template is a single node, not automatic-failover high availability. Enable appropriate volume backups and test restore separately before real data. Backup storage adds cost; restoring gateway state can resurrect old grants, so revoke grants before reopening restored ingress. [PostgreSQL service](https://docs.railway.com/databases/postgresql), [backup and restore behavior](https://docs.railway.com/guides/postgres-backups-restores)

## Cost estimate

Hobby has a **$5/month minimum**, including the first $5 of resource usage; it is not $5 plus all usage. Published container rates are RAM **$10/GB-month**, CPU **$20/vCPU-month**, volume storage **$0.15/GB-month**, and outbound traffic **$0.05/GB**. Hobby advertises volume capacity up to 5 GB. [Railway pricing](https://docs.railway.com/pricing), [plan limits](https://docs.railway.com/pricing/plans)

An illustrative combined average of 0.75 GB RAM, 0.05 vCPU, 2 GB of volume data and 1 GB outbound traffic gives **$8.85/month** before taxes and backup storage. These are assumptions, not measurements or a provider quote. Budget roughly **$8–15/month initially**, measure the complete backend/PostgreSQL/gateway/Tailscale footprint, and revise the estimate if memory stays higher. At 1.25 GB average RAM with the same other assumptions, the calculation is $13.85/month. Railway's billing explanation confirms that idle services still consume billable memory. [Understanding the bill](https://docs.railway.com/pricing/understanding-your-bill)

No Railway Agent, model API usage, managed HA database, extra replica or external monitoring service is included in this estimate. Set a deliberate spending limit/alert before a later approved deployment; understand that a hard limit may stop service.

## Protected ingress and remaining integration work

Keep Railway public domains and public TCP proxies absent. The [private runtime source package](deploy/railway/README.md) implements **Tailscale userspace networking and Serve**, never Funnel, for browser/login/sync ingress. Userspace mode works without a tunnel device or extra kernel capabilities; Serve applies tailnet access controls and can present HTTPS. Real enrollment, certificates and deployed topology remain unverified. [Userspace networking](https://tailscale.com/docs/concepts/userspace-networking), [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve)

Use a dedicated, narrowly tagged node identity. Tailnet policy must permit the intended user devices to reach only the service's required HTTPS port and prevent the remote node from initiating connections to the laptop or unrelated tailnet nodes. A default allow-all tailnet would defeat this boundary. The remote node still holds a node credential even after its enrollment key is removed; no Tailscale administrator/API/OAuth credential belongs there.

The gateway listens only on `127.0.0.1:8787`; the backend defaults to loopback and its private wrapper fixes `127.0.0.1:8080`. Each remote wrapper runs its own userspace daemon in the same container namespace, with Serve HTTPS443 forwarding only to that role's loopback listener. Gateway-to-backend requests also retain HTTPS hostname/certificate verification through a fixed Unix relay to the approved backend tailnet IP:443. No HTTP fallback, broader proxy trust or public app listener was added. WHOOP browser callbacks still need their exact approved private HTTPS route exercised from the user's tailnet browser.

Backend startup applies migrations only with explicit `RUN_MIGRATIONS=true`; the private wrapper forces `RUN_MIGRATIONS=false`. Treat migration review, backups and execution against the dedicated database as a separate approved operation. Each daemon has its own scoped node credential and private state, never a Tailscale administrator/API credential. The remote app and its daemon share one remote trust domain, so restrictive external tailnet policy remains necessary after app compromise.

Railway Pro's static outbound IP feature is a source-address feature, not an outbound firewall, and upgrading does not establish the missing deny-by-default policy. [Static outbound IPs](https://docs.railway.com/networking/static-outbound-ips)

### Implemented local private route and remaining activation gates

`restricted-local/launch.mjs` now has an explicit private-transport configuration alongside the unchanged public-IPv4 mode. Private mode creates a dedicated per-client userspace Tailscale container with its own node state and a Unix socket that relays to exactly one approved gateway tailnet IPv4:443. It does not mount host Tailscale state, use host networking, or rely on OrbStack routing through the laptop's VPN. The application receives no general SOCKS proxy or Tailscale administrative socket. Sync has `network:none`; login permits only its loopback-published callback and established replies. The offline reader still sees only its read-only numeric cache.

The local transport's namespace firewall is installed before its daemon starts. It permits public IPv4 TCP 443 and DNS only to Cloudflare `1.1.1.1` on UDP/TCP 53, with private/reserved/metadata destinations and IPv6 denied. Direct UDP peer traffic is blocked; real HTTPS/DERP fallback remains an activation check. Public HTTPS access is not a Tailscale-domain allowlist, and this firewall cannot restrict destinations inside an encrypted tailnet connection after transport compromise. External policy must allow each local transport identity only the exact gateway on TCP 443, and the gateway only its exact backend on TCP 443; review overlapping grants and test denied reverse/unrelated access.

The [local operator guide](restricted-local/README.md) specifies private config, separate `transport-init`, manual `transport-enroll` and foreground `transport-start` commands. Atomic container ownership and a state lock prevent concurrent writers; unclean shutdown fails closed on stale locks/sockets and requires inspected operator recovery. No enrollment or account connection occurs from an MCP call. Gateway grants remain fixed at seven days, sync admission at most hourly per client, and cache validity at most 90 minutes or the grant deadline.

Source preparation and synthetic isolation/TLS tests do not establish a working deployed tailnet. Before activation, separately approve and verify actual node enrollment/tag identity, complete ACLs and negative access, Serve certificate issuance/renewal, real cookie/proxy behavior, WHOOP's exact callback, both local callbacks, installed Codex/Claude reader configuration and revocation/expiry behavior. Do not expose a public Railway endpoint or disable certificate checks to bypass these gates.

## Release controls

Draft PR status does not prevent deployment. Keep GitHub autodeploy, PR environments and image auto-updates disabled. After separate approval, use an explicitly reviewed immutable image/revision and confirm the selected source before release. Railway can automatically deploy pushes to a linked branch; enabling PR environments can create a copy of the environment when a PR opens. [Autodeploy controls](https://docs.railway.com/deployments/github-autodeploys), [PR environments](https://docs.railway.com/guides/preview-deployments-with-pr-environments)

Before any real account connection, verify the actual runtime/ingress configuration, absence of public DB access and administrative credentials, tailnet negative-access checks, TLS hostname checks, local sync restrictions, offline reader isolation, cache expiry and revocation behavior, and the exact migration/backup plan. This document does not authorize or claim those operations have happened.
