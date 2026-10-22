export interface TokenSummary { id: string; label: string | null; createdAt: string; lastUsedAt: string | null; type: "oauth" | "pat"; expiresAt: string; }

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}
export const isUnauthorized = (e: unknown) => e instanceof ApiError && e.status === 401;

const H = { "X-Requested-With": "fetch", "Content-Type": "application/json" };
async function j<T>(res: Response): Promise<T> {
  if (!res.ok) throw new ApiError(res.status, (await res.json().catch(() => ({}))).error ?? `HTTP ${res.status}`);
  return res.json() as Promise<T>;
}
export const api = {
  session: () => fetch("/dashboard/api/session", { credentials: "include" }).then(j<{ connected: boolean }>),
  listTokens: () => fetch("/dashboard/api/tokens", { credentials: "include" }).then(j<{ tokens: TokenSummary[] }>),
  createToken: (label?: string) =>
    fetch("/dashboard/api/tokens", { method: "POST", credentials: "include", headers: H, body: JSON.stringify({ label }) }).then(j<{ token: string }>),
  revokeToken: (id: string) =>
    fetch(`/dashboard/api/tokens/${encodeURIComponent(id)}`, { method: "DELETE", credentials: "include", headers: H }).then((r) => { if (!r.ok) throw new ApiError(r.status, `HTTP ${r.status}`); }),
  revokeAllTokens: () =>
    fetch("/dashboard/api/tokens", { method: "DELETE", credentials: "include", headers: H }).then((r) => { if (!r.ok) throw new ApiError(r.status, `HTTP ${r.status}`); }),
  updateTokenLabel: (id: string, label: string | null) =>
    fetch(`/dashboard/api/tokens/${encodeURIComponent(id)}`, {
      method: "PATCH", credentials: "include", headers: H, body: JSON.stringify({ label }),
    }).then((r) => { if (!r.ok) throw new ApiError(r.status, `HTTP ${r.status}`); }),
  deleteAccount: () =>
    fetch("/dashboard/api/account", { method: "DELETE", credentials: "include", headers: H }).then((r) => { if (!r.ok) throw new ApiError(r.status, `HTTP ${r.status}`); }),
};
export const connectUrl = "/dashboard/connect";
