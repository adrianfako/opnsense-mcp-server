// End-to-end check: drive the built index.js over stdio and call read-only
// methods against a live firewall. Covers one method from every fork mechanism
// (generated route table, pseudo-module, plugin-namespaced module, path
// parameter, captive-portal fallback, hand-written override) so a broken route
// table or a bad build fails here rather than mid-session.
//
//   node tools/smoke.mjs <mcp-server-name-from-.claude.json> [extra:calls...]
//
// Exits non-zero if any call fails.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_CALLS = [
  'core_manage:systemStatus',
  'diagnostics_manage:systemSystemInformation',   // generated route, new module coverage
  'firewall_manage:filterSearchRule',             // hand-written override still wins
  'firewall_manage:migrationCountRules',          // added in this fork, 26.x migration API
  'firewall_manage:sourceNatGet',                 // 26.7-only controller action
  'firewall_manage:filterListCategories',
  'firmware_manage:firmwareStatus',               // remapped base path /api/core/firmware
  'interfaces_manage:vlanSettingsSearchItem',
  'kea_manage:dhcpv4SearchReservation',
  'wireguard_manage:clientGetClient',             // uuid-optional template fetch
  'ntpd_manage:serviceStatus',                    // module the client omits entirely
  'hostdiscovery_manage:serviceSearch',
  'radvd_manage:settingsSearchEntry',
  'captiveportal_manage:serviceSearchTemplates',  // moved controller, version fallback
  'unbound_manage:diagnosticsDumpcache',
  'routes_manage:routesSearchroute',
];

const [server, ...extra] = process.argv.slice(2);
if (!server) {
  console.error('usage: node tools/smoke.mjs <mcp-server-name> [tool:method[:jsonParams] ...]');
  process.exit(2);
}
const calls = extra.length ? extra : DEFAULT_CALLS;

const claudeConfig = join(process.env.USERPROFILE || process.env.HOME, '.claude.json');
const entry = JSON.parse(readFileSync(claudeConfig, 'utf8')).mcpServers[server];
if (!entry) {
  console.error(`no mcpServers entry named ${server} in ${claudeConfig}`);
  process.exit(2);
}

const child = spawn(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), '..', 'index.js')], {
  env: { ...process.env, ...entry.env },
  stdio: ['pipe', 'pipe', 'pipe'],
});
child.stderr.on('data', () => {});

let buf = '';
const pending = new Map();
child.stdout.on('data', (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (pending.has(msg.id)) pending.get(msg.id)(msg);
  }
});

let id = 0;
const rpc = (method, params) =>
  new Promise((res) => {
    const myId = ++id;
    pending.set(myId, res);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: myId, method, params }) + '\n');
  });

await rpc('initialize', {
  protocolVersion: '2024-11-05',
  capabilities: {},
  clientInfo: { name: 'smoke', version: '0' },
});
child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

const list = await rpc('tools/list', {});
console.log(`${server}: ${list.result.tools.length} tools listed`);

let failed = 0;
for (const c of calls) {
  const [tool, method, ...rest] = c.split(':');
  const params = rest.length ? JSON.parse(rest.join(':')) : {};
  const r = await rpc('tools/call', { name: tool, arguments: { method, params } });
  const text = (r.result?.content?.[0]?.text ?? JSON.stringify(r.error)).replace(/\s+/g, ' ');
  const bad = /^Error calling/.test(text);
  if (bad) failed++;
  console.log(`${bad ? 'FAIL' : 'ok  '} ${tool}.${method}  ${text.slice(0, Number(process.env.SLICE || 160))}`);
}
child.kill();
console.log(failed ? `${failed}/${calls.length} FAILED` : `all ${calls.length} passed`);
process.exit(failed ? 1 : 0);
