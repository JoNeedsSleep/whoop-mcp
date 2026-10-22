import { collectSnapshot } from '../local-view/snapshot.mjs';
import { validateSnapshot } from '../../restricted-local/policy.mjs';
import { CACHE_TTL_MS, writeCache } from '../../restricted-local/cache.mjs';
import { requestOAuth, validateTokenResponse } from './oauth.mjs';
import { withLockedState } from './state.mjs';

// Single shared refresh/collection, then two independent reader-only caches.
// Every credentialed network attempt is charged durably before it starts.
export async function syncOnce({ signal, now = Date.now, upstream = requestOAuth, collect = collectSnapshot, ...locations } = {}) {
  let deadlineTimer; let abort; let controller; let deadlineElapsed = false;
  try {
    return await withLockedState(async store => {
      if (signal?.aborted) return { status: 'unavailable' };
      let state = store.read(); const startedAt = now();
      if (!Number.isSafeInteger(startedAt) || startedAt < 0 || Object.is(startedAt, -0)) throw Error();
      if (!state.grant) { store.removeCaches(); return { status: 'reauthorize' }; }
      const revoke = async token => { try { await upstream('revoke', { token }); } catch { /* Fixed outcome; never retain credentials to retry indefinitely. */ } };
      // No expired credential can reach refresh/health. Erase durable authority
      // and caches first; the single bounded revocation uses only this RAM copy.
      if (startedAt >= state.grant.authorizationExpiresAt || state.interruptedRefresh || state.phase === 'refreshing') {
        const token = state.grant.accessToken; store.discard(); await revoke(token); return { status: 'reauthorize' };
      }
      if (!store.admit()) return { status: 'limited' };
      let grant = state.grant;
      if (startedAt < grant.authorizedAt || (state.lastSeenAt !== null && startedAt < state.lastSeenAt)) return { status: 'limited' };
      controller = new AbortController(); abort = () => controller.abort();
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
      deadlineTimer = setTimeout(() => { deadlineElapsed = true; abort(); }, grant.authorizationExpiresAt - startedAt);
      // Reserve enough access-token lifetime for the bounded 60-second snapshot.
      if (grant.accessExpiresAt <= startedAt + 65000) {
        let cleanupToken = grant.accessToken;
        try {
          store.beginRefresh();
          const raw = await upstream('refresh', { clientId: grant.clientId, clientSecret: grant.clientSecret, refreshToken: grant.refreshToken }, { signal: controller.signal });
          if (typeof raw?.access_token === 'string' && /^[\x21-\x7e]{1,4096}$/.test(raw.access_token)) cleanupToken = raw.access_token;
          const receivedAt = now(); const tokens = validateTokenResponse(raw, receivedAt);
          if (controller.signal.aborted) throw Error();
          store.replaceTokens(grant.refreshToken, tokens, { signal: controller.signal });
          grant = store.read().grant;
        } catch {
          try { store.discard(); } catch { /* The durable generation marker still blocks health and future refresh. */ }
          await revoke(cleanupToken); return { status: 'reauthorize' };
        }
      }
      const capturedAt = now();
      if (controller.signal.aborted || capturedAt < startedAt || capturedAt >= grant.authorizationExpiresAt) {
        if (deadlineElapsed || capturedAt >= grant.authorizationExpiresAt) { store.discard(); await revoke(grant.accessToken); return { status: 'reauthorize' }; }
        return { status: 'unavailable' };
      }
      let snapshot;
      try { snapshot = validateSnapshot(await collect({ token: grant.accessToken, signal: controller.signal, now: capturedAt }), capturedAt); }
      catch {
        if (deadlineElapsed || now() >= grant.authorizationExpiresAt) { store.discard(); await revoke(grant.accessToken); return { status: 'reauthorize' }; }
        return { status: 'unavailable' };
      }
      const finishedAt = now();
      if (deadlineElapsed || finishedAt >= grant.authorizationExpiresAt) { store.discard(); await revoke(grant.accessToken); return { status: 'reauthorize' }; }
      if (controller.signal.aborted || finishedAt < capturedAt || finishedAt - capturedAt > 60000 || finishedAt >= grant.accessExpiresAt) return { status: 'unavailable' };
      const expiresAt = Math.min(capturedAt + CACHE_TTL_MS, grant.authorizationExpiresAt);
      try {
        for (const [clientId, filename] of Object.entries(store.cachePaths)) {
          writeCache(filename, { version: 1, clientId, syncedAt: capturedAt, expiresAt, authorizationExpiresAt: grant.authorizationExpiresAt, snapshot }, finishedAt);
        }
      } catch { store.removeCaches(); return { status: 'unavailable' }; }
      return { status: 'updated' };
    }, { ...locations, now });
  } catch (error) { return { status: error?.message === 'LOCAL_SYNC_BUSY' ? 'busy' : 'unavailable' }; }
  finally { clearTimeout(deadlineTimer); if (abort) signal?.removeEventListener('abort', abort); controller?.abort(); }
}

export async function revokeAuthorization({ upstream = requestOAuth, ...options } = {}) {
  try {
    return await withLockedState(async store => {
      const grant = store.read().grant; store.discard();
      if (!grant) return { status: 'revoked' };
      try { await upstream('revoke', { token: grant.accessToken }); return { status: 'revoked' }; }
      catch { return { status: 'revocation-unconfirmed' }; }
    }, options);
  } catch (error) { return { status: error?.message === 'LOCAL_SYNC_BUSY' ? 'busy' : 'unavailable' }; }
}
