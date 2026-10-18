# Proposed Railway deployment

Research checked against official documentation on 2026-10-18. This is a proposal, not a deployed or verified production setup. No Railway resources, purchases, account connections, DNS records or client configuration were created. Keep the PR draft and unmerged. Website and School files are outside this plan.

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

Keep Railway public domains and public TCP proxies absent. Use reviewed **Tailscale userspace networking and Serve**, never Funnel, for browser/login/sync ingress. Userspace mode works without a tunnel device or extra kernel capabilities; Serve applies tailnet access controls and can present HTTPS. This is a design choice requiring implementation and verification, not an already functioning Railway package. [Userspace networking](https://tailscale.com/docs/concepts/userspace-networking), [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve)

Use a dedicated, narrowly tagged node identity. Tailnet policy must permit the intended user devices to reach only the service's required HTTPS port and prevent the remote node from initiating connections to the laptop or unrelated tailnet nodes. A default allow-all tailnet would defeat this boundary. The remote node still holds a node credential even after its enrollment key is removed; no Tailscale administrator/API/OAuth credential belongs there.

The current gateway listens only on `127.0.0.1`. Its Tailscale ingress must share that network namespace, or an independently reviewed topology change is needed. The gateway also requires HTTPS for the upstream WHOOP origin, while Railway's private-DNS examples use HTTP. Preserve verified TLS or explicitly review a protected-backend adaptation; do not silently disable certificate checks, broaden proxy trust or bind a public listener to make deployment work. WHOOP browser callbacks need their own approved private HTTPS route and must be exercised from the user's tailnet browser.

Railway Pro's static outbound IP feature is a source-address feature, not an outbound firewall, and upgrading does not establish the missing deny-by-default policy. [Static outbound IPs](https://docs.railway.com/networking/static-outbound-ips)

### Current local launcher does not support this private route

`restricted-local/launch.mjs` accepts a pinned **public IPv4 address only**. It rejects Tailscale's `100.64.0.0/10` range and all IPv6 destinations, maps the approved HTTPS hostname to that one address, and limits the sync container's outbound traffic to that address on TCP 443. Consequently, the current launcher and the proposed private Tailscale ingress are **not yet a working end-to-end deployment**. A public Railway address does not substitute for the protected ingress proposed above.

OrbStack container routing to the user's tailnet has not been verified. Before activation, separately design and approve the private transport, then test its routing, TLS identity, fixed destination, negative-access controls and absence of host credentials or broad tailnet access. Merely allowing a tailnet IP in the parser would not establish these properties. Keep the existing allowed-IP policy unchanged during this review; do not use host networking, mount Tailscale state or other host credentials into application containers, or expose a public Railway endpoint as an implicit workaround. This remaining integration work blocks claiming that the Railway proposal can already be activated with the local launcher.

## Release controls

Draft PR status does not prevent deployment. Keep GitHub autodeploy, PR environments and image auto-updates disabled. After separate approval, use an explicitly reviewed immutable image/revision and confirm the selected source before release. Railway can automatically deploy pushes to a linked branch; enabling PR environments can create a copy of the environment when a PR opens. [Autodeploy controls](https://docs.railway.com/deployments/github-autodeploys), [PR environments](https://docs.railway.com/guides/preview-deployments-with-pr-environments)

Before any real account connection, verify the actual runtime/ingress configuration, absence of public DB access and administrative credentials, tailnet negative-access checks, TLS hostname checks, local sync restrictions, offline reader isolation, cache expiry and revocation behavior, and the exact migration/backup plan. This document does not authorize or claim those operations have happened.
