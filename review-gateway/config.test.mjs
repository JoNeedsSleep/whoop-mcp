import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { parseGatewayConfig, readPrivateToken, validateStorage } from "./config.mjs";
const config = () => ({ publicOrigin: "https://gateway.example", upstreamOrigin: "https://whoop.example",
  upstreamTokenFile: "/run/secrets/whoop-service-token", ownerSecretHash: "a".repeat(64),
  databaseFile: "/data/gateway.sqlite", port: 8090,
  clients: [{clientId:"codex"}, {clientId:"claude-code"}] });
test("gateway configuration has distinct explicit HTTPS trust domains and bounded paths", () => {
  assert.equal(parseGatewayConfig(config()).port, 8090);
  for (const patch of [{publicOrigin:"http://localhost"},{publicOrigin:"https://gateway.example/"},
    {upstreamOrigin:"https://gateway.example"},{upstreamTokenFile:"relative"},{databaseFile:":memory:"},
    {port:80},{port:NaN},{ownerSecretHash:"secret"},{clients:[]},{unexpected:"value"}]) {
    assert.throws(() => parseGatewayConfig({...config(), ...patch}));
  }
});
test("provisioning keeps random keys out of logs, refuses overwrite, and checks private paths", t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-config-"));
  t.after(() => fs.rmSync(directory, {recursive:true, force:true}));
  const script = new URL("./provision.mjs", import.meta.url);
  const result = spawnSync(process.execPath, [script.pathname, directory], {encoding:"utf8"});
  assert.equal(result.status, 0, result.stderr);
  const owner = fs.readFileSync(path.join(directory,"owner-key"),"utf8").trim();
  const service = readPrivateToken(path.join(directory,"whoop-service-token"));
  assert.match(owner, /^[A-Za-z0-9_-]{43}$/);
  assert.match(service, /^whoopgw_service_[A-Za-z0-9_-]{43}$/);
  assert.ok(!(result.stdout+result.stderr).includes(owner));
  assert.ok(!(result.stdout+result.stderr).includes(service));
  const hashes = JSON.parse(fs.readFileSync(path.join(directory,"hashes.json"),"utf8"));
  assert.equal(hashes.ownerSecretHash, createHash("sha256").update(owner).digest("hex"));
  assert.equal(hashes.GATEWAY_SERVICE_TOKEN_SHA256, createHash("sha256").update(service).digest("hex"));
  const second = spawnSync(process.execPath, [script.pathname, directory], {encoding:"utf8"});
  assert.notEqual(second.status,0);
  assert.equal(fs.readFileSync(path.join(directory,"owner-key"),"utf8").trim(), owner);
  validateStorage(path.join(directory,"gateway.sqlite"));
  fs.symlinkSync(path.join(directory,"owner-key"),path.join(directory,"link"));
  assert.throws(() => readPrivateToken(path.join(directory,"link")));
  assert.throws(() => validateStorage(path.join(directory,"link")));
  fs.chmodSync(path.join(directory,"whoop-service-token"),0o644);
  assert.throws(() => readPrivateToken(path.join(directory,"whoop-service-token")));
  fs.chmodSync(directory,0o755);
  assert.throws(() => validateStorage(path.join(directory,"gateway.sqlite")));
});
