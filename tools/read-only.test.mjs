// Read-only mode refuses writes before any request, and logSearch takes plain words only.
// Runs against a dead URL, so a broken guard cannot reach a firewall.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';

async function calls(readOnly, cases) {
  const child = spawn(process.execPath, [new URL('../index.js', import.meta.url).pathname], {
    env: { ...process.env, OPNSENSE_URL: 'https://127.0.0.1:9', OPNSENSE_API_KEY: 'x', OPNSENSE_API_SECRET: 'y',
           OPNSENSE_VERIFY_SSL: 'false', OPNSENSE_READ_ONLY: readOnly ? '1' : 'false' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let buf = '';
  let stderr = '';
  let exited = null;
  const pending = new Map();
  let id = 0;
  child.stderr.on('data', (d) => { stderr = (stderr + d).slice(-2000); });
  child.stdin.on('error', () => {});
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) { const m = JSON.parse(line); pending.get(m.id)?.(m); }
    }
  });
  // Every call is answered: by the server, by its exit, or by a 15 s timer that keeps
  // the event loop alive. A dead server fails the test with its own stderr, never hangs it.
  const fail = (why) => ({ error: { message: why + (stderr ? ': ' + stderr.trim() : '') } });
  child.on('exit', (code) => {
    exited = 'server exited ' + code;
    for (const r of pending.values()) r(fail(exited));
    pending.clear();
  });
  const rpc = (method, params) => new Promise((r) => {
    if (exited) return r(fail(exited));
    const n = ++id;
    const t = setTimeout(() => { if (pending.delete(n)) r(fail('timeout')); }, 15000);
    pending.set(n, (m) => { clearTimeout(t); r(m); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: n, method, params }) + '\n');
  });
  const init = await rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '0' } });
  assert.ok(init.result, 'server did not start: ' + (init.error?.message ?? ''));
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
  // A write action carried as a path parameter.
  ['firmware_manage', 'firmwareLog', { args: ['clear'] }],
  ['firmware_manage', 'firmwareLog', { args: ['cLear'] }],
  ['firmware_manage', 'firmwareLog', { args: ['CLEAR'] }],
];
const READS = [
  ['firewall_manage', 'filterSearchRule', {}],
  ['ids_manage', 'settingsGet', {}],
  ['diagnostics_manage', 'logSearch', { args: ['core', 'audit'] }],
  ['core_manage', 'backupBackups', { args: ['this'] }],
  ['diagnostics_manage', 'systemSystemInformation', {}],
  ['firmware_manage', 'firmwareDetails', { args: ['os-wireguard'] }],
  ['firmware_manage', 'firmwareLog', {}],
  ['firewall_manage', 'filterGetRule', { uuid: '0add3b2c-1d4e-4f5a-9b6c-7d8e9f0a1b2c' }],
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
