import { createHash, timingSafeEqual } from "node:crypto";

export const FLOW_TTL_MS = 10 * 60_000;
export const BROWSER_COOKIE_OPTIONS = {
  secure: true, httpOnly: true, sameSite: "lax" as const, path: "/",
};
export const nonceHash = (raw: string) => createHash("sha256").update(raw).digest("hex");

export function flowCookieName(state: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(state)) throw new Error("Invalid flow state");
  return `__Host-whoop_flow_${state}`;
}

export function browserMatchesFlow(cookieHeader: string | undefined, state: string, expectedHash: unknown): boolean {
  if (typeof expectedHash !== "string" || !/^[0-9a-f]{64}$/.test(expectedHash)) return false;
  const prefix = `${flowCookieName(state)}=`;
  const matches = (cookieHeader ?? "").split(";").map((part) => part.trim()).filter((part) => part.startsWith(prefix));
  // Reject ambiguous cookie headers rather than choosing an attacker-controlled copy.
  if (matches.length !== 1) return false;
  const nonce = matches[0].slice(prefix.length);
  if (!/^[A-Za-z0-9_-]{43}$/.test(nonce)) return false;
  return timingSafeEqual(Buffer.from(nonceHash(nonce), "hex"), Buffer.from(expectedHash, "hex"));
}
