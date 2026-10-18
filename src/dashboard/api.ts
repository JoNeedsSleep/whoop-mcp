import express, { Router, type Request, type Response } from "express";
import type { TokenStore } from "../auth/token-store.js";

export interface DashboardApiDeps {
  tokenStore: TokenStore;
}

function userId(req: Request): string | undefined {
  return req.session?.userId as string | undefined;
}
function requireSession(req: Request, res: Response): string | undefined {
  const id = userId(req);
  if (!id) { res.status(401).json({ error: "not connected" }); return undefined; }
  return id;
}
function requireXhr(req: Request, res: Response): boolean {
  if (!req.get("x-requested-with")) { res.status(403).json({ error: "missing X-Requested-With" }); return false; }
  return true;
}

export function createDashboardApiRouter(deps: DashboardApiDeps): Router {
  const router = Router();
  router.use(express.json());

  router.get("/session", (req, res) => {
    res.json({ connected: Boolean(userId(req)) });
  });

  router.get("/tokens", async (req, res) => {
    const id = requireSession(req, res); if (!id) return;
    res.json({ tokens: await deps.tokenStore.listMcpTokens(id) });
  });

  router.delete("/tokens", async (req, res) => {
    const id = requireSession(req, res); if (!id) return;
    if (!requireXhr(req, res)) return;
    await deps.tokenStore.revokeAllMcpTokens(id);
    res.status(204).end();
  });

  router.post("/tokens", async (req, res) => {
    const id = requireSession(req, res); if (!id) return;
    if (!requireXhr(req, res)) return;
    const label = typeof req.body?.label === "string" && req.body.label.trim() ? req.body.label.trim() : undefined;
    if ((label?.length ?? 0) > 100) { res.status(400).json({ error: "label too long" }); return; }
    const token = await deps.tokenStore.issueMcpToken(id, "pat", label);
    res.json({ token });
  });

  router.patch("/tokens/:id", async (req, res) => {
    const id = requireSession(req, res); if (!id) return;
    if (!requireXhr(req, res)) return;
    const raw = req.body?.label;
    const trimmed = typeof raw === "string" ? raw.trim() : "";
    if (trimmed.length > 100) { res.status(400).json({ error: "label too long" }); return; }
    const label = trimmed ? trimmed : null;
    await deps.tokenStore.updateMcpTokenLabel(id, req.params.id, label);
    res.status(204).end();
  });

  router.delete("/tokens/:id", async (req, res) => {
    const id = requireSession(req, res); if (!id) return;
    if (!requireXhr(req, res)) return;
    await deps.tokenStore.revokeMcpTokenById(id, req.params.id);
    res.status(204).end();
  });

  router.delete("/account", async (req, res) => {
    const id = requireSession(req, res); if (!id) return;
    if (!requireXhr(req, res)) return;
    await deps.tokenStore.deleteUser(id);
    req.session = null;
    res.status(204).end();
  });

  return router;
}
