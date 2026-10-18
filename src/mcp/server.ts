import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { WhoopClient } from "../whoop/client.js";
import { makeToolHandlers, RANGE_SCHEMA } from "./tools.js";
import type { TokenStore } from "../auth/token-store.js";
import type { CredentialProvider } from "../whoop/credentials.js";

export function registerWhoopTools(
  server: McpServer,
  clientFor: (userId: string) => WhoopClient,
  userIdOf: (extra: any) => string,
): void {
  const h = makeToolHandlers(clientFor);
  const reg = (name: string, description: string, shape: any, fn: any) =>
    server.registerTool(name, { description, inputSchema: shape },
      async (args: any, extra: any) => fn(args, { userId: userIdOf(extra) }));

  reg("get_recovery", "Get WHOOP recovery records (score, HRV, RHR, SpO2, skin temp).", RANGE_SCHEMA, h.get_recovery);
  reg("get_sleep", "Get WHOOP sleep records (stages, performance, respiratory rate).", RANGE_SCHEMA, h.get_sleep);
  reg("get_workouts", "Get WHOOP workouts (strain, HR zones, distance).", RANGE_SCHEMA, h.get_workouts);
  reg("get_cycles", "Get WHOOP physiological cycles (daily strain, energy).", RANGE_SCHEMA, h.get_cycles);
  reg("get_daily_summary", "Get combined recovery + sleep + strain for a single date (YYYY-MM-DD).",
    { date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD") }, h.get_daily_summary);
}

export function buildMcpServer(deps: { tokenStore: TokenStore; credentials: CredentialProvider }): McpServer {
  const server = new McpServer({ name: "whoop-mcp", version: "0.1.0" });
  const clientFor = (userId: string) =>
    new WhoopClient(
      () => deps.tokenStore.getValidAccessToken(userId),
      async () => deps.tokenStore.forceRefreshAccessToken(userId),
    );
  registerWhoopTools(server, clientFor, (extra: any) => extra?.authInfo?.extra?.userId);
  return server;
}
