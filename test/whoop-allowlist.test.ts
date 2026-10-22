import { describe, it, expect } from "vitest";
import { isWhoopUserAllowed } from "../src/auth/whoop-callback.js";
import { WHOOP_SCOPES } from "../src/whoop/oauth.js";
describe("single-user identity", () => {
  it("accepts only the configured stable numeric ID", () => {
    expect(isWhoopUserAllowed(42, "42")).toBe(true);
    for (const value of [41, "42", null, {}, NaN, Infinity, -42, 42.1]) expect(isWhoopUserAllowed(value, "42")).toBe(false);
    expect(isWhoopUserAllowed(42, "")).toBe(false);
  });
  it("removes body scope, while explicitly retaining profile for identity", () => {
    expect(WHOOP_SCOPES).not.toContain("read:body_measurement");
    expect(WHOOP_SCOPES).toContain("read:profile");
  });
});
