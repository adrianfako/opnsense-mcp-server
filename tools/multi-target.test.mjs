// One server, several firewalls: the schema takes a required firewall, each call goes to
// that firewall's client, readOnly holds per target, and a bad name sends nothing.
// Drives the built index.js over stdio against two mock OPNsense HTTP servers.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const INDEX = join(dirname(fileURLToPath(import.meta.url)), '..', 'index.js');

async function mock(name, seen) {
  const http = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      seen.push({ name, method: req.method, url: req.url, auth: req.headers.authorization });
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ firewall: name }));
    });
  });
  await new Promise((r) => http.listen(0, '127.0.0.1', r));
  return http;
}

function start(env) {
  const child = spawn(process.execPath, [INDEX], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  let buf = '';
  let stderr = '';
  const pending = new Map();
  child.stderr.on('data', (d) => { stderr += d; });
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) { const m = JSON.parse(line); pending.get(m.id)?.(m); }
    }
  });
  child.on('exit', () => { for (const r of pending.values()) r({ error: { message: 'exited: ' + stderr } }); });
  let id = 0;
  const rpc = (method, params) => new Promise((r) => {
    pending.set(++id, r);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  return { child, rpc, stderr: () => stderr };
}

const BASE = { ...process.env, OPNSENSE_URL: '', OPNSENSE_API_KEY: '', OPNSENSE_API_SECRET: '', OPNSENSE_READ_ONLY: '' };
const INIT = { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '0' } };

async function withTargets(fn) {
  const seen = [];
  const a = await mock('alpha', seen);
  const b = await mock('beta', seen);
  const dir = mkdtempSync(join(tmpdir(), 'opnsense-mcp-'));
  writeFileSync(join(dir, 'alpha.json'), JSON.stringify({ OPNSENSE_API_KEY: 'ka', OPNSENSE_API_SECRET: 'SECRET-A' }));
  writeFileSync(join(dir, 'beta.json'), JSON.stringify({ OPNSENSE_API_KEY: 'kb', OPNSENSE_API_SECRET: 'SECRET-B' }));
  const file = join(dir, 'targets.json');
  writeFileSync(file, JSON.stringify({ targets: {
    beta: { url: 'http://127.0.0.1:' + b.address().port, credentials: join(dir, 'beta.json'), readOnly: true, label: 'fw-beta' },
    alpha: { url: 'http://127.0.0.1:' + a.address().port, credentials: join(dir, 'alpha.json') },
  } }));
  const s = start({ ...BASE, OPNSENSE_TARGETS: file });
  try {
    assert.ok((await s.rpc('initialize', INIT)).result, s.stderr());
    const call = (firewall, name, method, params = {}) =>
      s.rpc('tools/call', { name, arguments: { ...(firewall === undefined ? {} : { firewall }), method, params } });
    await fn({ rpc: s.rpc, call, seen, stderr: s.stderr });
  } finally {
    s.child.kill();
    a.close();
    b.close();
  }
}

const basic = (k, s) => 'Basic ' + Buffer.from(k + ':' + s).toString('base64');

test('targets file: every tool requires firewall with the sorted target names', () => withTargets(async ({ rpc }) => {
  const { result } = await rpc('tools/list', {});
  assert.ok(result.tools.length > 0);
  for (const t of result.tools) {
    assert.deepEqual(t.inputSchema.properties.firewall.enum, ['alpha', 'beta']);
    assert.ok(t.inputSchema.required.includes('firewall'), t.name);
    assert.ok(t.inputSchema.properties.method.enum.length > 0);
  }
  assert.equal(result.tools[0].inputSchema.properties.firewall.description, 'Which firewall: alpha, beta (fw-beta)');
}));

test('calls go to the named firewall with its own credentials', () => withTargets(async ({ call, seen, stderr }) => {
  const ra = await call('alpha', 'diagnostics_manage', 'systemSystemInformation');
  const rb = await call('beta', 'diagnostics_manage', 'systemSystemInformation');
  assert.match(ra.result.content[0].text, /"alpha"/);
  assert.match(rb.result.content[0].text, /"beta"/);
  assert.deepEqual(seen.map((r) => [r.name, r.auth]), [['alpha', basic('ka', 'SECRET-A')], ['beta', basic('kb', 'SECRET-B')]]);
  assert.match(stderr(), /Calling alpha diagnostics\.systemSystemInformation/);
  assert.doesNotMatch(stderr(), /SECRET-/);
}));

test('readOnly on one target refuses its writes only', () => withTargets(async ({ call, seen }) => {
  const rb = await call('beta', 'firewall_manage', 'filterApply');
  assert.match(rb.result.content[0].text, /^Error calling beta firewall_manage\.filterApply: .*Read-only beta firewall/);
  const ra = await call('alpha', 'firewall_manage', 'filterApply');
  assert.match(ra.result.content[0].text, /"alpha"/);
  assert.deepEqual(seen.map((r) => [r.name, r.method]), [['alpha', 'POST']]);
}));

test('an unknown or missing firewall is refused before any request', () => withTargets(async ({ call, seen }) => {
  for (const fw of ['gamma', undefined, '__proto__']) {
    const r = await call(fw, 'diagnostics_manage', 'systemSystemInformation');
    assert.equal(r.error?.code, -32602, JSON.stringify(r));
    assert.match(r.error.message, /Use one of: alpha, beta/);
  }
  assert.equal(seen.length, 0);
}));

test('without a targets file the old single-target schema is served', async () => {
  const s = start({ ...BASE, OPNSENSE_URL: 'https://127.0.0.1:9', OPNSENSE_API_KEY: 'x', OPNSENSE_API_SECRET: 'y' });
  try {
    assert.ok((await s.rpc('initialize', INIT)).result, s.stderr());
    const { result } = await s.rpc('tools/list', {});
    for (const t of result.tools) {
      assert.equal(t.inputSchema.properties.firewall, undefined);
      assert.ok(!(t.inputSchema.required || []).includes('firewall'));
    }
  } finally {
    s.child.kill();
  }
});
