import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { verifyGatewayServiceToken } from "../src/auth/gateway-service.js";
const token = `whoopgw_service_${"a".repeat(43)}`;
const hash = createHash("sha256").update(token).digest("hex");
describe("dedicated summary credential", () => {
  it("accepts only the exact dedicated bearer and configured hash", () => {
    expect(verifyGatewayServiceToken(`Bearer ${token}`, hash)).toBe(true);
    for (const value of [undefined, [], token, `bearer ${token}`, `Bearer ${token} `,
      `Bearer whoopmcp_pat_${"a".repeat(43)}`, `Bearer whoopgw_service_${"b".repeat(43)}`]) {
      expect(verifyGatewayServiceToken(value, hash)).toBe(false);
    }
  });
  it("fails closed when disabled or misconfigured, and supports rotation", () => {
    for (const expected of [undefined, "", "invalid", "0".repeat(64)]) {
      expect(verifyGatewayServiceToken(`Bearer ${token}`, expected)).toBe(false);
    }
    const replacement = `whoopgw_service_${"b".repeat(43)}`;
    const replacementHash = createHash("sha256").update(replacement).digest("hex");
    expect(verifyGatewayServiceToken(`Bearer ${token}`, replacementHash)).toBe(false);
    expect(verifyGatewayServiceToken(`Bearer ${replacement}`, replacementHash)).toBe(true);
  });
});
