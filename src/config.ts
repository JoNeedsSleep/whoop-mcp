import { z } from "zod";

// Explicit deployment configuration only: never derive security origins from a request.
export const httpsOrigin = z.string().url().refine((raw) => {
  const u = new URL(raw);
  return u.protocol === "https:" && !u.username && !u.password &&
    u.pathname === "/" && !u.search && !u.hash && raw === u.origin;
}, "must be a canonical HTTPS origin without a path or trailing slash");
export const httpsCallback = z.string().url().max(2048).refine((raw) => {
  const u = new URL(raw);
  return u.protocol === "https:" && !u.username && !u.password && !u.hash &&
    !raw.includes("*") && u.href === raw;
}, "must be an exact HTTPS callback URL without credentials, fragments or wildcards");

export interface AppConfig {
  databaseUrl: string; encryptionKey: string;
  whoopClientId: string; whoopClientSecret: string;
  publicBaseUrl: string; port: number; sessionSecret: string;
  allowedWhoopUserId: string;
  approvedClientRedirectUris: string[];
  enableLegacyDirectMcp: boolean;
  gatewayServiceTokenSha256?: string;
}

const Schema = z.object({
  DATABASE_URL: z.string().min(1),
  ENCRYPTION_KEY: z.string().regex(/^[0-9a-fA-F]{64}$/, "must be 32-byte hex"),
  WHOOP_CLIENT_ID: z.string().min(1),
  WHOOP_CLIENT_SECRET: z.string().min(1),
  PUBLIC_BASE_URL: httpsOrigin,
  ENABLE_LEGACY_DIRECT_MCP: z.enum(["false", "true"]).default("false"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  SESSION_SECRET: z.string().min(32),
  ALLOWED_WHOOP_USER_ID: z.string().regex(/^[1-9][0-9]{0,15}$/).refine((v) => Number.isSafeInteger(Number(v))),
  APPROVED_CLIENT_REDIRECT_URIS: z.array(httpsCallback).max(8),
  GATEWAY_SERVICE_TOKEN_SHA256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
});

export function loadConfig(env: NodeJS.ProcessEnv): AppConfig {
  const p = Schema.parse({ ...env,
    APPROVED_CLIENT_REDIRECT_URIS: (env.APPROVED_CLIENT_REDIRECT_URIS ?? "")
      .split(",").map((v) => v.trim()).filter(Boolean),
  });
  return {
    databaseUrl: p.DATABASE_URL, encryptionKey: p.ENCRYPTION_KEY,
    whoopClientId: p.WHOOP_CLIENT_ID, whoopClientSecret: p.WHOOP_CLIENT_SECRET,
    publicBaseUrl: p.PUBLIC_BASE_URL, port: p.PORT, sessionSecret: p.SESSION_SECRET,
    allowedWhoopUserId: p.ALLOWED_WHOOP_USER_ID,
    approvedClientRedirectUris: p.APPROVED_CLIENT_REDIRECT_URIS,
    enableLegacyDirectMcp: p.ENABLE_LEGACY_DIRECT_MCP === "true",
    gatewayServiceTokenSha256: p.GATEWAY_SERVICE_TOKEN_SHA256,
  };
}
