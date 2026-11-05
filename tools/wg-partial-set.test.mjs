// A partial wireguard set must keep the fields it does not send (servers above
// all). Drives the built index.js over stdio against a mock OPNsense HTTP server.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const UUID = '11111111-2222-3333-4444-555555555555';
const LIVE = {
  client: {
    enabled: '1',
    name: 'site-b',
    pubkey: 'PUBKEY=',
    serveraddress: '203.0.113.7',
    serverport: '51820',
    keepalive: '25',
    tunneladdress: ['10.9.0.2/32', '10.20.0.0/24'],
    servers: {
      'aaaa-srv': { value: 'wg0', selected: 1 },
      'bbbb-srv': { value: 'wg1', selected: 0 },
      'cccc-srv': { value: 'wg2', selected: 1 },
    },
  },
};

async function withServer(fn) {
  const posts = [];
  const http = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'GET' && req.url === '/api/wireguard/client/get_client/' + UUID) return res.end(JSON.stringify(LIVE));
      if (req.method === 'GET' && req.url.startsWith('/api/wireguard/client/get_client/')) return res.end('[]');
      if (req.method === 'POST') {
        posts.push({ url: req.url, body: JSON.parse(body || '{}') });
        return res.end(JSON.stringify({ result: 'saved' }));
      }
      res.statusCode = 404;
      res.end('{}');
    });
  });
  await new Promise((r) => http.listen(0, '127.0.0.1', r));
  const child = spawn(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), '..', 'index.js')], {
    env: { ...process.env, OPNSENSE_URL: 'http://127.0.0.1:' + http.address().port, OPNSENSE_API_KEY: 'k', OPNSENSE_API_SECRET: 's', OPNSENSE_READ_ONLY: '' },
    stdio: ['pipe', 'pipe', 'ignore'],
  });
  let buf = '';
  const pending = new Map();
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const msg = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      pending.get(msg.id)?.(msg);
    }
  });
  let id = 0;
  const rpc = (method, params) => new Promise((res) => {
    pending.set(++id, res);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  const call = (method, params) => rpc('tools/call', { name: 'wireguard_manage', arguments: { method, params } })
    .then((r) => r.result.content[0].text);
  try {
    await rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '0' } });
    await fn(call, posts);
  } finally {
    child.kill();
    http.close();
  }
}

test('partial clientSetClient keeps servers and the other live fields', () => withServer(async (call, posts) => {
  const text = await call('clientSetClient', { uuid: UUID, item: { client: { tunneladdress: '10.9.0.3/32' } } });
  assert.match(text, /saved/);
  assert.equal(posts.length, 1);
  assert.equal(posts[0].url, '/api/wireguard/client/set_client/' + UUID);
  assert.deepEqual(posts[0].body, {
    client: {
      enabled: '1',
      name: 'site-b',
      pubkey: 'PUBKEY=',
      serveraddress: '203.0.113.7',
      serverport: '51820',
      keepalive: '25',
      tunneladdress: '10.9.0.3/32',
      servers: 'aaaa-srv,cccc-srv',
    },
  });
}));

test('partial set of one flag keeps the multi-selects as comma keys', () => withServer(async (call, posts) => {
  await call('clientSetClient', { uuid: UUID, item: { client: { enabled: '0' } } });
  assert.equal(posts[0].body.client.enabled, '0');
  assert.equal(posts[0].body.client.servers, 'aaaa-srv,cccc-srv');
  assert.equal(posts[0].body.client.tunneladdress, '10.9.0.2/32,10.20.0.0/24');
}));

test('set on an unknown uuid is refused, nothing posted', () => withServer(async (call, posts) => {
  const text = await call('clientSetClient', { uuid: 'missing', item: { client: { enabled: '0' } } });
  assert.match(text, /^Error calling/);
  assert.equal(posts.length, 0);
}));
