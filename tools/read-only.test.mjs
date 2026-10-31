// Read-only mode refuses writes before any request, and logSearch takes plain words only.
// Runs against a dead URL, so a broken guard cannot reach a firewall.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';

async function calls(readOnly, cases) {
  const child = spawn(process.execPath, [new URL('../index.js', import.meta.url).pathname], {
    env: { ...process.env, OPNSENSE_URL: 'https://127.0.0.1:9', OPNSENSE_API_KEY: 'x', OPNSENSE_API_SECRET: 'y',
           OPNSENSE_VERIFY_SSL: 'false', OPNSENSE_READ_ONLY: String(readOnly) },
    stdio: ['pipe', 'pipe', 'ignore'],
  });
  let buf = '';
  const pending = new Map();
  let id = 0;
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) { const m = JSON.parse(line); pending.get(m.id)?.(m); }
    }
  });
  const rpc = (method, params) => new Promise((r) => {
    const n = ++id; pending.set(n, r);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: n, method, params }) + '\n');
  });
  await rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '0' } });
  const out = [];
  for (const [name, method, params] of cases) {
    const r = await rpc('tools/call', { name, arguments: { method, params } });
    out.push(r.result?.content?.[0]?.text ?? r.error?.message ?? '');
  }
  child.kill();
  return out;
}

const WRITES = [
  ['firewall_manage', 'filterApply', {}],
  ['firewall_manage', 'filterSetRule', { uuid: 'x', data: {} }],
  ['wireguard_manage', 'serviceReconfigure', {}],
  ['ids_manage', 'settingsSetRule', {}],
  // Discovered as mutating: false, but they write.
  ['core_manage', 'backupRevertBackup', { args: ['config-1.xml'] }],
  ['core_manage', 'snapshotsActivate', { args: ['x'] }],
  ['routes_manage', 'routesDelroute', { args: ['x'] }],
  ['diagnostics_manage', 'interfaceCarpStatus', { args: ['maintenance'] }],
  ['captiveportal_manage', 'accessLogon', { args: ['0'] }],
];
const READS = [
  ['firewall_manage', 'filterSearchRule', {}],
  ['ids_manage', 'settingsGet', {}],
  ['diagnostics_manage', 'logSearch', { args: ['core', 'audit'] }],
  ['core_manage', 'backupBackups', { args: ['this'] }],
  ['diagnostics_manage', 'systemSystemInformation', {}],
];

test('read-only refuses writes and lets reads through', async () => {
  const out = await calls(true, [...WRITES, ...READS]);
  out.slice(0, WRITES.length).forEach((t) => assert.match(t, /Read-only server/));
  out.slice(WRITES.length).forEach((t) => assert.doesNotMatch(t, /Read-only server/));
});

test('without read-only, writes reach the client', async () => {
  const out = await calls(false, WRITES);
  out.forEach((t) => assert.doesNotMatch(t, /Read-only server/));
});

test('logSearch refuses a segment that is not a plain word', async () => {
  const [t] = await calls(false, [['diagnostics_manage', 'logSearch', { args: ['core', 'audit/clear'] }]]);
  assert.match(t, /plain words only/);
});

test('a path parameter cannot climb to another endpoint', async () => {
  const out = await calls(false, [
    ['firewall_manage', 'filterGetRule', { uuid: '../../core/backup/revertBackup' }],
    ['firewall_manage', 'aliasGetItem', { uuid: '%2e%2e' }],
  ]);
  out.forEach((t) => assert.match(t, /one plain word|Refused request path/));
});
