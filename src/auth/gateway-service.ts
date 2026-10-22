import { createHash, timingSafeEqual } from "node:crypto";

// A dedicated machine credential for exactly the bounded summary endpoint.
// It is not accepted by dashboard, OAuth or legacy MCP authentication.
export function verifyGatewayServiceToken(header: unknown, expectedHash?: string): boolean {
  if (!expectedHash || !/^[a-f0-9]{64}$/.test(expectedHash) || typeof header !== "string" ||
      !/^Bearer whoopgw_service_[A-Za-z0-9_-]{43}$/.test(header)) return false;
  const digest = createHash("sha256").update(header.slice(7)).digest();
  return timingSafeEqual(digest, Buffer.from(expectedHash, "hex"));
}
