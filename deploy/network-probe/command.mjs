import { createHash } from 'node:crypto';
import { validateRequest } from './probe.mjs';

// Pure public-source formatter. Execute only inside the reviewed offline fixture.
// The source hash must come from the independently reviewed test inventory.
export function buildCommand(source, expectedSha256, request, now = Date.now()) {
  if (typeof source !== 'string' || Buffer.byteLength(source) > 16_384 ||
      !/^[a-f0-9]{64}$/.test(expectedSha256) ||
      createHash('sha256').update(source).digest('hex') !== expectedSha256) {
    throw new Error('NETWORK_PROBE_COMMAND_UNAVAILABLE');
  }
  validateRequest(request, now);
  const program = `${source}\nawait main(${JSON.stringify(request)});\n`;
  // A data URL keeps the provider's single-line field compatible without
  // changing/minifying any reviewed program byte. The program imports built-ins only.
  const evaluator = `await import(${JSON.stringify(`data:text/javascript;base64,${Buffer.from(program).toString('base64')}`)});`;
  const quote = text => `'${text.replaceAll("'", "'\\''")}'`;
  return '/usr/bin/setpriv --no-new-privs -- /usr/bin/env -i ' +
    'PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp NODE_ENV=production UV_USE_IO_URING=0 ' +
    `/usr/local/bin/node --input-type=module -e ${quote(evaluator)}`;
}
