import type { WhoopClient } from "./client.js";

export function utcDay(value: unknown): string {
  if (typeof value !== "string" || !/^20\d{2}-\d{2}-\d{2}$/.test(value) ||
      !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().slice(0, 10) !== value) {
    throw new Error("Invalid date");
  }
  return value;
}

// This projection reduces normal exposure. Only the separately trusted gateway can
// enforce validation when this server is compromised.
export async function healthSummary(client: WhoopClient, requestedDate: string) {
  const date = utcDay(requestedDate);
  const range = { start: `${date}T00:00:00.000Z`,
    end: new Date(Date.parse(date) + 86400000).toISOString(), limit: 1 };
  const [recovery, sleep, cycles] = await Promise.all([
    client.getRecovery(range), client.getSleep(range), client.getCycles(range),
  ]);
  const r = recovery[0]?.score;
  const s = sleep[0]?.score;
  const c = cycles[0]?.score;
  const stages = s?.stage_summary;
  const sleepMs = stages ? stages.total_light_sleep_time_milli + stages.total_slow_wave_sleep_time_milli + stages.total_rem_sleep_time_milli : null;
  const data = {
    recovery_score: r?.recovery_score ?? null, hrv_ms: r?.hrv_rmssd_milli ?? null,
    resting_heart_rate: r?.resting_heart_rate ?? null, sleep_ms: sleepMs,
    sleep_performance: s?.sleep_performance_percentage ?? null, strain: c?.strain ?? null,
  };
  return { date, status: Object.values(data).some((v) => v !== null) ? "AVAILABLE" : "NO_DATA", ...data };
}
