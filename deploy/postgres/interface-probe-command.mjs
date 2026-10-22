import { createHash } from 'node:crypto';

// Format only independently pinned public source inside an isolated fixture.
export function buildCommand(source, expectedSha256) {
  if (typeof source !== 'string' || Buffer.byteLength(source) > 16384 ||
      !/^[a-f0-9]{64}$/.test(expectedSha256) ||
      createHash('sha256').update(source).digest('hex') !== expectedSha256) {
    throw new Error('POSTGRES_NETWORK_COMMAND_UNAVAILABLE');
  }
  const program = `${source}\nawait main();\n`;
  const evaluator = `await import(${JSON.stringify('data:text/javascript;base64,' + Buffer.from(program).toString('base64'))});`;
  return '/usr/bin/setpriv --no-new-privs -- /usr/bin/env -i ' +
    'PATH=/usr/local/bin:/usr/lib/postgresql/17/bin:/usr/bin:/bin HOME=/tmp LANG=C UV_USE_IO_URING=0 ' +
    `/usr/local/bin/node --input-type=module -e '${evaluator}'`;
}
