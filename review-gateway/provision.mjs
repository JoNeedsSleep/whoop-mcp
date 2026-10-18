// Run only in the approved dedicated gateway environment, never in the WHOOP service.
// Generated secrets are written to new private files, never printed or accepted as arguments.
import fs from "node:fs";
import path from "node:path";
import { randomBytes, createHash } from "node:crypto";
const directory = process.argv[2];
try {
  if (!directory || !path.isAbsolute(directory)) throw new Error("INVALID_DIRECTORY");
  const info = fs.lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid() || (info.mode & 0o077)) throw new Error("INVALID_DIRECTORY");
  process.umask(0o077);
  const owner = randomBytes(32).toString("base64url");
  const service = `whoopgw_service_${randomBytes(32).toString("base64url")}`;
  fs.writeFileSync(path.join(directory, "owner-key"), owner + "\n", { flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(directory, "whoop-service-token"), service + "\n", { flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(directory, "hashes.json"), JSON.stringify({
    ownerSecretHash: createHash("sha256").update(owner).digest("hex"),
    GATEWAY_SERVICE_TOKEN_SHA256: createHash("sha256").update(service).digest("hex"),
  }, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log("Created private owner-key, whoop-service-token and hashes.json. Import secrets into the approved store; never paste them in chat.");
} catch {
  console.error("Provisioning failed; choose a private, owned directory with no existing key files. Partial files are preserved.");
  process.exitCode = 1;
}
