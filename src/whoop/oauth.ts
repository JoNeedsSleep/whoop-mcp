import type { WhoopTokenSet } from "./types.js";

const AUTH_BASE = "https://api.prod.whoop.com/oauth/oauth2";
export const WHOOP_SCOPES = [
  "read:recovery",
  "read:sleep",
  "read:workout",
  "read:cycles",
  "read:profile", // required for fail-closed identity check; WHOOP also exposes email with this scope
  "offline",
];
type Creds = { clientId: string; clientSecret: string };
type FetchImpl = typeof fetch;

export function buildAuthorizeUrl(p: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
}): string {
  const u = new URL(`${AUTH_BASE}/auth`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", p.clientId);
  u.searchParams.set("redirect_uri", p.redirectUri);
  u.searchParams.set("scope", WHOOP_SCOPES.join(" "));
  u.searchParams.set("state", p.state);
  u.searchParams.set("code_challenge", p.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

function parseTokenResponse(data: any): WhoopTokenSet {
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: new Date(Date.now() + Number(data.expires_in) * 1000),
    scopes: String(data.scope ?? "").split(" ").filter(Boolean),
  };
}

async function tokenRequest(body: URLSearchParams, fetchImpl: FetchImpl): Promise<WhoopTokenSet> {
  const res = await fetchImpl(`${AUTH_BASE}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`WHOOP token endpoint ${res.status}`);
  return parseTokenResponse(await res.json());
}

export function exchangeCodeForTokens(
  code: string,
  redirectUri: string,
  creds: Creds,
  codeVerifier: string,
  fetchImpl: FetchImpl = fetch,
): Promise<WhoopTokenSet> {
  return tokenRequest(
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      code_verifier: codeVerifier,
    }),
    fetchImpl,
  );
}

export function refreshWhoopTokens(
  refreshToken: string,
  creds: Creds,
  fetchImpl: FetchImpl = fetch,
): Promise<WhoopTokenSet> {
  return tokenRequest(
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      scope: "offline",
    }),
    fetchImpl,
  );
}
