const API_BASE = "https://api.prod.whoop.com/developer";
type FetchImpl = typeof fetch;
type Range = { start?: string; end?: string; limit?: number };

export class WhoopClient {
  constructor(
    private getAccessToken: () => Promise<string>,
    private forceRefresh: (rejectedAccessToken: string) => Promise<string>,
    private fetchImpl: FetchImpl = fetch,
  ) {}

  private async raw(path: string, query: Record<string, string> = {}, token?: string): Promise<Response> {
    const at = token ?? await this.getAccessToken();
    const url = new URL(API_BASE + path);
    for (const [k, v] of Object.entries(query)) if (v != null) url.searchParams.set(k, v);
    return this.fetchImpl(url.toString(), { headers: { Authorization: `Bearer ${at}` }, redirect: "error", signal: AbortSignal.timeout(10_000) });
  }

  private async json<T>(path: string, query: Record<string, string> = {}): Promise<T> {
    const accessToken = await this.getAccessToken();
    let res = await this.raw(path, query, accessToken);
    if (res.status === 401) {
      const at = await this.forceRefresh(accessToken);
      res = await this.raw(path, query, at);
      if (res.status === 401) throw new Error("WHOOP authorization failed — please reconnect your WHOOP account.");
    }
    if (res.status === 429) {
      const reset = Math.min(Number(res.headers.get("X-RateLimit-Reset") ?? "5"), 30);
      await new Promise((r) => setTimeout(r, reset * 1000));
      res = await this.raw(path, query);
    }
    if (!res.ok) throw new Error(`WHOOP API ${res.status} on ${path}`);
    return res.json() as Promise<T>;
  }

  private async collection(path: string, range: Range = {}): Promise<any[]> {
    const out: any[] = [];
    let nextToken: string | undefined;
    const limit = range.limit ?? 25;
    let pages = 0;
    do {
      if (++pages > 4) throw new Error("WHOOP pagination limit exceeded");
      const q: Record<string, string> = { limit: String(Math.min(limit, 25)) };
      if (range.start) q.start = range.start;
      if (range.end) q.end = range.end;
      if (nextToken) q.nextToken = nextToken;
      const page = await this.json<{ records: any[]; next_token?: string | null }>(path, q);
      out.push(...page.records);
      nextToken = page.next_token ?? undefined;
    } while (nextToken && out.length < limit);
    return out.slice(0, limit);
  }

  getRecovery(range?: Range) { return this.collection("/v2/recovery", range); }
  getSleep(range?: Range) { return this.collection("/v2/activity/sleep", range); }
  getWorkouts(range?: Range) { return this.collection("/v2/activity/workout", range); }
  getCycles(range?: Range) { return this.collection("/v2/cycle", range); }
  getProfile() { return this.json<any>("/v2/user/profile/basic"); }
  getBodyMeasurement() { return this.json<any>("/v2/user/measurement/body"); }
}
