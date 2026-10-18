import { z } from "zod";
import type { WhoopClient } from "../whoop/client.js";

const RangeSchema = { start: z.iso.datetime().optional(), end: z.iso.datetime().optional(), limit: z.number().int().min(1).max(50).optional() };
type ClientFactory = (userId: string) => WhoopClient;

function ok(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data) }], structuredContent: data as any };
}
function fail(e: unknown) {
  const msg = e instanceof Error && /not connected|reconnect/i.test(e.message)
    ? "Your WHOOP account isn't connected. Open the dashboard to connect it."
    : "WHOOP request failed.";
  return { content: [{ type: "text" as const, text: msg }], isError: true };
}

export function makeToolHandlers(clientFor: ClientFactory) {
  const wrap = (fn: (c: WhoopClient, args: any) => Promise<unknown>) =>
    async (args: any, ctx: { userId: string }) => {
      try { return ok(await fn(clientFor(ctx.userId), args)); } catch (e) { return fail(e); }
    };
  return {
    get_recovery: wrap((c, a) => c.getRecovery({ start: a.start, end: a.end, limit: a.limit }).then((r) => ({ records: r }))),
    get_sleep: wrap((c, a) => c.getSleep({ start: a.start, end: a.end, limit: a.limit }).then((r) => ({ records: r }))),
    get_workouts: wrap((c, a) => c.getWorkouts({ start: a.start, end: a.end, limit: a.limit }).then((r) => ({ records: r }))),
    get_cycles: wrap((c, a) => c.getCycles({ start: a.start, end: a.end, limit: a.limit }).then((r) => ({ records: r }))),
    get_daily_summary: wrap(async (c, a) => {
      const start = `${a.date}T00:00:00.000Z`;
      const end = new Date(new Date(start).getTime() + 86_400_000).toISOString();
      const range = { start, end, limit: 10 };
      const [recovery, sleep, cycles] = await Promise.all([c.getRecovery(range), c.getSleep(range), c.getCycles(range)]);
      return { date: a.date, recovery: recovery[0] ?? null, sleep: sleep[0] ?? null, cycle: cycles[0] ?? null };
    }),
  };
}
export const RANGE_SCHEMA = RangeSchema;
