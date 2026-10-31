#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const toolsData = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'tools-generated.json'), 'utf8'));

// The live MVC API surface, discovered off a box running the newest OPNsense
// (see tools/discover_routes.py + tools/probe_verbs.py). This is the source of
// truth for what exists; @richard-stovall/opnsense-typescript-client 0.5.3 ships
// a spec that is several releases stale and has been wrong about routes, verbs
// and whole controllers.
const apiRoutes: Record<string, Record<string, { path: string; post: boolean; params: number; search: boolean }>> =
  JSON.parse(fs.readFileSync(path.join(__dirname, 'api-routes.json'), 'utf8'));

const PLUGIN_MODULES = ['telegraf', 'dmidecode', 'hwprobe'];

// OPNsense serves every log (core/audit, core/system, wireguard/wireguard, ...) through
// one catch-all action on diagnostics/LogController, so discover_routes.py never sees
// it. Kept here, not in api-routes.json, so a route refresh does not drop it. The
// caller is attached in ensureClient (it checks the segments: the same path takes a
// `clear` action).
(apiRoutes.diagnostics ??= {}).logSearch = { path: '/api/diagnostics/log', post: true, params: 2, search: true, mutating: false } as any;

for (const [key, routes] of Object.entries(apiRoutes)) {
  const names = Object.keys(routes);
  let tool = toolsData.tools.find((t: any) => (t.module === 'plugins' ? t.submodule : t.module) === key);
  if (!tool) {
    const isPlugin = PLUGIN_MODULES.includes(key);
    tool = {
      name: isPlugin ? `plugin_${key}_manage` : `${key}_manage`,
      module: isPlugin ? 'plugins' : key,
      ...(isPlugin ? { submodule: key } : {}),
      description: `${key} management - ${names.length} available methods including: ${names.slice(0, 5).join(', ')}...`,
      inputSchema: JSON.parse(JSON.stringify(toolsData.tools[0].inputSchema)),
      methods: [],
    };
    toolsData.tools.push(tool);
  }
  tool.methods = [...new Set([...tool.methods, ...names])].sort();
  tool.inputSchema.properties.method.enum = tool.methods;
  // Only the leading count is refreshed. The rest of the description is
  // hand-written per tool (firewall_manage carries the write-body cheat sheet)
  // and must survive the merge intact.
  tool.description = tool.description.replace(
    /\b\d+ available methods\b/,
    `${tool.methods.length} available methods`
  );
}
toolsData.coreTools = toolsData.tools.filter((t: any) => t.module !== 'plugins').length;
toolsData.pluginTools = toolsData.tools.filter((t: any) => t.module === 'plugins').length;
toolsData.totalTools = toolsData.tools.length;

const serverCode = `#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { OPNsenseClient } from '@richard-stovall/opnsense-typescript-client';

// Embedded modular tool definitions
const TOOLS = ${JSON.stringify(toolsData.tools, null, 2)};

// Method documentation for help
const METHOD_DOCS = ${JSON.stringify(toolsData.methodDocs, null, 2)};

// Discovered MVC API surface — see src/api-routes.json and the note in build.ts.
const API_ROUTES = ${JSON.stringify(apiRoutes)};
const PLUGIN_MODULES = ${JSON.stringify(PLUGIN_MODULES)};

// One caller for every discovered route. The dispatcher hands methods
// (uuid, body) or (body), so: leading primitives fill the path parameters the
// controller action declares, and the first object is the body. Two-parameter
// actions (toggleRuleLog(uuid, log), toggleroute(uuid, enabled)) take both
// segments. Anything more exotic goes through params.args.
// OPNsense *Get* actions return every <select> option, not just the chosen one:
// a d_nat rule ships ~150 protocol entries at "selected": 0. Measured on a live
// 26.7 box that is 7,546 bytes where 773 carry information (89.8% waste), and
// what is left is exactly the collapsed body the matching *Set* expects, so the
// model no longer hand-collapses option maps (the empty-destination trap).
// One selected -> the bare key (write-ready). Several -> an array, because the
// separator is per-family (alias content = newline, categories = comma) and
// guessing one here would corrupt writes. None -> "".
// WireGuard private keys and PSKs are dropped, never masked: every result lands
// in a transcript, and a masked value fed back into a *Set* would overwrite the
// real key (OPNsense leaves a field that is not in the body as it is).
const SECRET_FIELDS = new Set(['privkey', 'psk']);
function pruneOptions(node) {
  if (Array.isArray(node)) return node.map(pruneOptions);
  if (node === null || typeof node !== 'object') return node;
  const vals = Object.values(node);
  const isOptionMap =
    vals.length > 0 &&
    vals.every(
      (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && 'selected' in v
    );
  if (isOptionMap) {
    const chosen = Object.keys(node).filter((k) => {
      const s = node[k].selected;
      return s === 1 || s === '1' || s === true;
    });
    return chosen.length === 1 ? chosen[0] : chosen.length === 0 ? '' : chosen;
  }
  const out = {};
  for (const [k, v] of Object.entries(node)) if (!SECRET_FIELDS.has(k)) out[k] = pruneOptions(v);
  return out;
}

// Read-only mode (OPNSENSE_READ_ONLY=true or --read-only) checks every request the
// client sends, not the method name or the discovered "mutating" flag: that flag is
// wrong for actions like revertBackup, snapshots/activate and routes/delroute. A
// request goes out only when its action (the word after /api/<module>/<controller>/)
// is a read. Anything else is refused, so it fails closed.
// First camel word of the action: a read verb or a read noun. No camel word may be a
// write word; a lowercase compound (getroute, listlocalzones) passes on a read prefix
// when no write word sits inside it.
const READ_FIRST = new Set(('get search show status list info log is dump dumpcache dumpinfra stats count ' +
  'backups system version health memory statistics totals top interfaces pf rule cache ca mac running ' +
  'upgradestatus providers zones meta view tree timeserie aliases accounts find diff report services ' +
  'templates pools user gps swanctl raw reverse searchroute connection').split(' '));
const READ_PREFIX = ['get', 'search', 'list', 'dump', 'show'];
const WRITE = new Set(('set add del delete apply toggle toggleroute reconfigure restart start stop upload revert ' +
  'flush kill reboot halt update upgrade install remove reset save import clear drop lock unlock connect ' +
  'disconnect generate gen run exec activate expire logon logoff reload store carp register sync create ' +
  'rename move clone restore revoke renew sign issue kick disable enable wake fetch download commit rollback ' +
  'cancel abort purge rotate trigger test export new psk key otp seed stream').split(' '));
function camelWords(a) {
  return (String(a).match(/[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])/g) || []).map((w) => w.toLowerCase());
}
function isReadRequest(url) {
  const parts = String(url).split('?')[0].split('/').filter(Boolean);
  if (parts[0] !== 'api' || parts.length < 4) return false;
  if (parts[1] === 'diagnostics' && parts[2] === 'log') return parts.length === 5;
  const words = camelWords(parts[3]);
  if (!words.length || words.some((w) => WRITE.has(w))) return false;
  const first = words[0];
  if (READ_FIRST.has(first)) return true;
  return READ_PREFIX.some((v) => first.startsWith(v)) && ![...WRITE].some((w) => first.slice(3).includes(w));
}
// Every path segment a caller supplies (uuid, name, module) is one plain word, so a
// value cannot climb to another endpoint (../core/backup/revertBackup).
const PLAIN_SEGMENT = /^[A-Za-z0-9_.:@-]+$/;
function checkSegment(v) {
  const t = String(v);
  if (!PLAIN_SEGMENT.test(t) || t === '.' || t === '..') {
    throw new Error('Path parameter must be one plain word (letters, digits, _ . : @ -), got: ' + t.slice(0, 40));
  }
  return t;
}
function badPath(url) {
  const p = String(url).split('?')[0];
  if (p.includes('%') || p.includes('//') || p.includes(String.fromCharCode(92))) return true;
  return p.split('/').some((s) => s === '.' || s === '..');
}

function makeRoute(mod, r) {
  const seg = (v) => v !== undefined && v !== null && typeof v !== 'object';
  return function (a, b) {
    let url = r.path;
    let body;
    if (r.params > 0 && seg(a)) {
      url += '/' + checkSegment(a);
      if (r.params > 1 && seg(b)) {
        url += '/' + checkSegment(b);
      } else {
        body = b;
      }
    } else {
      body = typeof a === 'object' && a !== null ? a : b;
    }
    if (!r.post) {
      return mod.http.get(url, undefined);
    }
    return mod.http.post(url, body || (r.search ? { current: 1, rowCount: 200 } : {}), undefined);
  };
}

class OPNsenseMCPServer {
  constructor(config) {
    this.config = config;
    this.client = null;
    this.server = new Server(
      {
        name: 'opnsense-mcp-server',
        version: '0.7.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
  }

  ensureClient() {
    if (!this.client) {
      this.client = new OPNsenseClient({
        baseUrl: this.config.url,
        apiKey: this.config.apiKey,
        apiSecret: this.config.apiSecret,
        verifySsl: this.config.verifySsl ?? true,
      });

      // Read-only: check every request at the HTTP client, after all routes and fork
      // fixes built their URL. Path tricks are refused in every mode.
      const __http = this.client.http;
      const __readOnly = !!this.config.readOnly;
      for (const verb of ['get', 'post', 'put', 'delete', 'patch']) {
        const orig = __http[verb] && __http[verb].bind(__http);
        if (!orig) continue;
        __http[verb] = (url, ...rest) => {
          if (badPath(url)) throw new Error('Refused request path: ' + String(url).slice(0, 80));
          if (__readOnly && !isReadRequest(url)) {
            throw new McpError(ErrorCode.InvalidRequest, 'Read-only server: ' + verb.toUpperCase() + ' ' + String(url).split('?')[0] + ' can change the firewall and is refused. Firewall changes go through make firewall.');
          }
          return orig(url, ...rest);
        };
      }

      // Attach every discovered route. These OVERWRITE the client's own methods
      // on purpose — the routes come from a live box, the client's spec does
      // not — and they create the modules the client omits entirely (backup,
      // hostdiscovery, ntpd, radvd). The hand-written fork fixes below run
      // afterwards and still win where they exist.
      for (const [mod, routes] of Object.entries(API_ROUTES)) {
        const parent = PLUGIN_MODULES.includes(mod) ? this.client.plugins : this.client;
        if (!parent[mod]) parent[mod] = {};
        const target = parent[mod];
        if (!target.http) target.http = this.client.http;
        for (const [name, r] of Object.entries(routes)) {
          target[name] = makeRoute(target, r);
        }
      }

      // logSearch(module, scope, body?): POST /api/diagnostics/log/<module>/<scope>, the
      // bootgrid search the GUI log pages use. Segments are plain words only: the same
      // controller clears a log on <module>/<scope>/clear.
      const __diag = this.client.diagnostics;
      __diag.logSearch = (module, scope, body) => {
        const word = /^[a-z0-9_]+$/;
        if (!word.test(String(module)) || !word.test(String(scope))) {
          throw new Error('logSearch takes params.args = [module, scope, {searchPhrase?, rowCount?}], plain words only (e.g. ["core", "audit"])');
        }
        return __diag.http.post('/api/diagnostics/log/' + module + '/' + scope,
          { current: 1, rowCount: 200, searchPhrase: '', ...(body && typeof body === 'object' ? body : {}) });
      };

      // OPNsense 26.7 moved the captive-portal template actions off
      // ServiceController onto a TemplateController. The fleet is all 26.7 as of
      // 2026-08-12, but the pre-26.7 method names are kept working on both
      // versions — new route first, old route on 404 — so this server stays
      // usable against a 26.1.x box.
      const __cp = this.client.captiveportal;
      if (__cp && __cp.http) {
        for (const verb of ['getTemplate', 'saveTemplate', 'delTemplate', 'searchTemplates']) {
          const name = 'service' + verb[0].toUpperCase() + verb.slice(1);
          const post = verb !== 'getTemplate';
          __cp[name] = async (a, b) => {
            const call = (base) => post
              ? __cp.http.post('/api/captiveportal/' + base + '/' + verb, (typeof a === 'object' ? a : b) || {})
              : __cp.http.get('/api/captiveportal/' + base + '/' + verb + (a ? '/' + a : ''));
            try {
              return await call('template');
            } catch (e) {
              if (e && e.response && e.response.status === 404) return await call('service');
              throw e;
            }
          };
        }
      }

      // FORK FIX (filter_base 404): @richard-stovall/opnsense-typescript-client
      // 0.5.3 maps 8 firewall model-base methods to /api/firewall/filter_base/*,
      // which 404 on OPNsense. The real route is /api/firewall/filter/* (verified
      // vs live OPNsense 2026-06-10: filter/get=401, filter/apply=411 EXIST;
      // filter_base/get=404). filterBaseApply being broken = firewall changes
      // never applied. Re-map the 8 to the correct route. Upstream bug.
      const __fw = this.client.firewall;
      if (__fw && __fw.http) {
        __fw.filterBaseGet = (config) => __fw.http.get('/api/firewall/filter/get', config);
        __fw.filterBaseSet = (data, config) => __fw.http.post('/api/firewall/filter/set', data, config);
        // 26.7 removed savepoint/revert/cancel_rollback (404 on /filter/* and
        // /filter_base/*, probed 2026-09-22); they are filtered out of the method
        // enum in generate-tools.ts so nothing builds a rollback that cannot exist.
        __fw.filterBaseApply = (rev, data, config) => __fw.http.post('/api/firewall/filter/apply' + (rev ? '/' + rev : ''), data, config);
        // REMOVED UPSTREAM in OPNsense 26.7: savepoint / revert / cancel_rollback
        // are gone from FilterBaseController and 404 on every 26.7 box (whole
        // fleet, verified 2026-08-12). The apply action also lost its
        // rollback-revision argument. Kept for boxes on 26.1.x and so names stay
        // resolvable; the rollback-before-apply pattern now needs a config.xml
        // snapshot instead (see infrastructure/tools/firewall/reconcile_firewall.py).
        __fw.filterBaseListCategories = (config) => __fw.http.get('/api/firewall/filter/list_categories', config);
        __fw.filterBaseListNetworkSelectOptions = (config) => __fw.http.get('/api/firewall/filter/list_network_select_options', config);
        // FORK ADD (d_nat / port-forward): OPNsense 26.x added a Destination NAT
        // (port-forward) MVC controller at /api/firewall/d_nat/* — absent from
        // opnsense-typescript-client 0.5.3 (stale spec), so the MCP could not manage
        // port-forwards. Mirror source_nat. Verified live 2026-06-10 (search/get/set/
        // toggle/apply all 200). Method names also added to tools-generated.json.
        __fw.dNatGet = (config) => __fw.http.get('/api/firewall/d_nat/get', config);
        __fw.dNatSet = (data, config) => __fw.http.post('/api/firewall/d_nat/set', data, config);
        __fw.dNatSearchRule = (data, config) => __fw.http.post('/api/firewall/d_nat/searchRule', data, config);
        __fw.dNatAddRule = (data, config) => __fw.http.post('/api/firewall/d_nat/addRule', data, config);
        __fw.dNatGetRule = (uuid, config) => __fw.http.get('/api/firewall/d_nat/getRule/' + (uuid || ''), config);
        __fw.dNatSetRule = (uuid, data, config) => __fw.http.post('/api/firewall/d_nat/setRule/' + uuid, data, config);
        __fw.dNatDelRule = (uuid, data, config) => __fw.http.post('/api/firewall/d_nat/delRule/' + uuid, data, config);
        __fw.dNatToggleRule = (uuid, data, config) => __fw.http.post('/api/firewall/d_nat/toggleRule/' + (uuid || ''), data, config);
        __fw.dNatApply = (rev, data, config) => __fw.http.post('/api/firewall/d_nat/apply' + (rev ? '/' + rev : ''), data, config);
        // FORK ADD (missing list/search): the client omits searchRule + the *SearchItem
        // grid endpoints (real controller actions), so the MCP could not ENUMERATE
        // rules/aliases/groups/categories — getRule needs a uuid, and "list" returned
        // []. searchRule is the key one (lists firewall rules). Verified vs live
        // OPNsense controllers 2026-06-10. No-arg call POSTs an empty body -> all rows.
        // searchRule/searchItem 400 on an empty POST body, so default to a wide page
        // (caller can still pass {current,rowCount,searchPhrase,sort} to override).
        __fw.filterSearchRule = (data, config) => __fw.http.post('/api/firewall/filter/searchRule', data || { current: 1, rowCount: 200 }, config);
        __fw.aliasSearchItem = (data, config) => __fw.http.post('/api/firewall/alias/searchItem', data || { current: 1, rowCount: 200 }, config);
        __fw.groupSearchItem = (data, config) => __fw.http.post('/api/firewall/group/searchItem', data || { current: 1, rowCount: 200 }, config);
        __fw.categorySearchItem = (data, config) => __fw.http.post('/api/firewall/category/searchItem', data || { current: 1, rowCount: 200 }, config);
        __fw.filterBaseListPortSelectOptions = (config) => __fw.http.get('/api/firewall/filter/list_port_select_options', config);
        __fw.filterToggleRuleLog = (uuid, data, config) => __fw.http.post('/api/firewall/filter/toggleRuleLog/' + (uuid || ''), data, config);
        __fw.filterFlushInspectCache = (data, config) => __fw.http.post('/api/firewall/filter/flushInspectCache', data, config);
        // FORK ADD (NAT search/apply): client 0.5.3 also omits searchRule and
        // apply for source_nat / one_to_one / npt, so those rule families could
        // be written but never ENUMERATED or APPLIED via the MCP (writes only
        // stage config). Routes verified live 2026-06-11 (homelab OPNsense:
        // searchRule 200 for all three).
        __fw.sourceNatSearchRule = (data, config) => __fw.http.post('/api/firewall/source_nat/searchRule', data || { current: 1, rowCount: 200 }, config);
        __fw.sourceNatApply = (data, config) => __fw.http.post('/api/firewall/source_nat/apply', data || {}, config);
        __fw.oneToOneSearchRule = (data, config) => __fw.http.post('/api/firewall/one_to_one/searchRule', data || { current: 1, rowCount: 200 }, config);
        __fw.oneToOneApply = (data, config) => __fw.http.post('/api/firewall/one_to_one/apply', data || {}, config);
        __fw.nptSearchRule = (data, config) => __fw.http.post('/api/firewall/npt/searchRule', data || { current: 1, rowCount: 200 }, config);
        __fw.nptApply = (data, config) => __fw.http.post('/api/firewall/npt/apply', data || {}, config);
        // FORK FIX (no-uuid template fetch): the upstream GetRule/GetItem
        // methods URL-format an undefined uuid (/getRule/undefined), which
        // returns [] (or 500 for alias/getItem) instead of the empty editable
        // model. That template is the authoritative write schema per family
        // (see firewall_manage description), so make uuid optional like the
        // fork's dNatGetRule already is.
        __fw.filterGetRule = (uuid, config) => __fw.http.get('/api/firewall/filter/getRule/' + (uuid || ''), config);
        __fw.sourceNatGetRule = (uuid, config) => __fw.http.get('/api/firewall/source_nat/getRule/' + (uuid || ''), config);
        __fw.oneToOneGetRule = (uuid, config) => __fw.http.get('/api/firewall/one_to_one/getRule/' + (uuid || ''), config);
        __fw.nptGetRule = (uuid, config) => __fw.http.get('/api/firewall/npt/getRule/' + (uuid || ''), config);
        __fw.aliasGetItem = (uuid, config) => __fw.http.get('/api/firewall/alias/getItem/' + (uuid || ''), config);
        __fw.groupGetItem = (uuid, config) => __fw.http.get('/api/firewall/group/getItem/' + (uuid || ''), config);
        __fw.categoryGetItem = (uuid, config) => __fw.http.get('/api/firewall/category/getItem/' + (uuid || ''), config);
      }
      // FORK ADD (interfaces searchItem + bridge): the client omits every interface
      // *SettingsSearchItem (the box controllers have searchItem) and the entire
      // BridgeSettings controller. Verified live 2026-06-10 (vlan_settings/searchItem
      // = 17 rows on eu-6). Same stale-spec gap as the firewall searchRule.
      const __if = this.client.interfaces;
      if (__if && __if.http) {
        const S = (p) => (data, config) => __if.http.post('/api/interfaces/' + p + '/searchItem', data || { current: 1, rowCount: 200 }, config);
        __if.vlanSettingsSearchItem = S('vlan_settings');
        __if.vxlanSettingsSearchItem = S('vxlan_settings');
        __if.laggSettingsSearchItem = S('lagg_settings');
        __if.loopbackSettingsSearchItem = S('loopback_settings');
        __if.neighborSettingsSearchItem = S('neighbor_settings');
        __if.gifSettingsSearchItem = S('gif_settings');
        __if.greSettingsSearchItem = S('gre_settings');
        __if.vipSettingsSearchItem = S('vip_settings');
        const B = '/api/interfaces/bridge_settings/';
        __if.bridgeSettingsSearchItem = (data, config) => __if.http.post(B + 'searchItem', data || { current: 1, rowCount: 200 }, config);
        __if.bridgeSettingsGetItem = (uuid, config) => __if.http.get(B + 'getItem/' + (uuid || ''), config);
        __if.bridgeSettingsAddItem = (data, config) => __if.http.post(B + 'addItem', data, config);
        __if.bridgeSettingsSetItem = (uuid, data, config) => __if.http.post(B + 'setItem/' + uuid, data, config);
        __if.bridgeSettingsDelItem = (uuid, data, config) => __if.http.post(B + 'delItem/' + uuid, data, config);
        __if.bridgeSettingsReconfigure = (data, config) => __if.http.post(B + 'reconfigure', data, config);
      }
      // GUARD: do NOT remap the CORE firewall writes (alias/filter/group/category/
      // source_nat add/set/del/toggle/reconfigure). OPNsense's core MVC controllers
      // use camelCase actions (addItem/setItem/addRule/toggleItem/reconfigure) and the
      // upstream client maps them CORRECTLY — they work unmodified. Verified live
      // 2026-06-11: firewall aliasSetItem -> {result:"saved"}. The breakage below is
      // specific to the WireGuard PLUGIN, which uniquely uses SNAKE_CASE commands.
      // If a future write "fails", check the controller's real action casing first;
      // only snake_case-command plugins need a remap here.
      //
      // FORK FIX (wireguard writes): opnsense-typescript-client 0.5.3 maps the
      // WireGuard client/server WRITE actions to wrong routes/bodies, so every
      // add/set/del returned a bare {result:"failed"} (GETs were fine). Same class
      // as upstream issue #4. Re-map to the real plugin routes. OPNsense uses
      // SNAKE_CASE for these commands — verified live 2026-06-11: POST
      // /api/wireguard/client/set_client/<uuid> with body {client:{...}} =
      // {result:"saved"} (camelCase setClient -> {result:"failed"}). Body passed
      // straight through (caller sends {client:{...}} / {server:{...}}).
      const __wg = this.client.wireguard;
      if (__wg && __wg.http) {
        const WG = '/api/wireguard/';
        __wg.clientAddClient = (data, config) => __wg.http.post(WG + 'client/add_client', data, config);
        __wg.clientSetClient = (uuid, data, config) => __wg.http.post(WG + 'client/set_client/' + uuid, data, config);
        __wg.clientDelClient = (uuid, config) => __wg.http.post(WG + 'client/del_client/' + uuid, {}, config);
        __wg.clientToggleClient = (uuid, data, config) => __wg.http.post(WG + 'client/toggle_client/' + (uuid || ''), data, config);
        __wg.serverAddServer = (data, config) => __wg.http.post(WG + 'server/add_server', data, config);
        __wg.serverSetServer = (uuid, data, config) => __wg.http.post(WG + 'server/set_server/' + uuid, data, config);
        __wg.serverDelServer = (uuid, config) => __wg.http.post(WG + 'server/del_server/' + uuid, {}, config);
        __wg.serverToggleServer = (uuid, data, config) => __wg.http.post(WG + 'server/toggle_server/' + (uuid || ''), data, config);
        __wg.generalSet = (data, config) => __wg.http.post(WG + 'general/set', data, config);
        // FORK FIX (no-uuid template fetch): upstream clientGetClient/serverGetServer
        // URL-format an undefined uuid (.../get_client/undefined) -> [] instead of the
        // empty editable model. That template is the authoritative write schema (the
        // {client:{...}} / {server:{...}} body), so make uuid optional — the bare route
        // .../get_client returns the empty template (verified live 2026-06-15).
        __wg.clientGetClient = (uuid, config) => __wg.http.get(WG + 'client/get_client/' + (uuid || ''), config);
        __wg.serverGetServer = (uuid, config) => __wg.http.get(WG + 'server/get_server/' + (uuid || ''), config);
        __wg.serviceReconfigure = (data, config) => __wg.http.post(WG + 'service/reconfigure', data || {}, config);
        __wg.serviceRestart = (data, config) => __wg.http.post(WG + 'service/restart', data || {}, config);
        __wg.serviceStart = (data, config) => __wg.http.post(WG + 'service/start', data || {}, config);
        __wg.serviceStop = (data, config) => __wg.http.post(WG + 'service/stop', data || {}, config);
      }

      // FORK FIX (firmware wrong base path): opnsense-typescript-client 0.5.3 maps
      // the ENTIRE firmware module to /api/firmware/* — which 404s ("Endpoint not
      // found"). The real controller is /api/core/firmware/*. Verified live
      // 2026-07-31 on fw-leon (OPNsense 26.7.1) AND fw-doda (26.1.9): the 404 is
      // NOT version-specific — it's a stale base path, broken on every version.
      // status/running/info/health/upgradestatus/connection/get/getOptions = GET
      // (confirmed 200); the mutating actions are POST; per-package actions carry
      // the pkg in the path. Read methods restore firmware/update visibility; the
      // POST/action methods are remapped for correctness but are disruptive — do
      // not fire them casually.
      const __firm = this.client.firmware;
      if (__firm && __firm.http) {
        const FW = '/api/core/firmware/';
        // reads (GET)
        __firm.firmwareStatus = (config) => __firm.http.get(FW + 'status', config);
        __firm.firmwareRunning = (config) => __firm.http.get(FW + 'running', config);
        __firm.firmwareInfo = (config) => __firm.http.get(FW + 'info', config);
        __firm.firmwareHealth = (config) => __firm.http.get(FW + 'health', config);
        __firm.firmwareUpgradestatus = (config) => __firm.http.get(FW + 'upgradestatus', config);
        __firm.firmwareConnection = (config) => __firm.http.get(FW + 'connection', config);
        __firm.firmwareGet = (config) => __firm.http.get(FW + 'get', config);
        __firm.firmwareGetOptions = (config) => __firm.http.get(FW + 'getOptions', config);
        __firm.firmwareChangelog = (version, config) => __firm.http.get(FW + 'changelog/' + (version || ''), config);
        __firm.firmwareLog = (clear, config) => __firm.http.get(FW + 'log/' + (clear || ''), config);
        __firm.firmwareLicense = (pkg, config) => __firm.http.get(FW + 'license/' + (pkg || ''), config);
        // mutating actions (POST)
        __firm.firmwareCheck = (data, config) => __firm.http.post(FW + 'check', data || {}, config);
        __firm.firmwareAudit = (data, config) => __firm.http.post(FW + 'audit', data || {}, config);
        __firm.firmwareUpdate = (data, config) => __firm.http.post(FW + 'update', data || {}, config);
        __firm.firmwareUpgrade = (data, config) => __firm.http.post(FW + 'upgrade', data || {}, config);
        __firm.firmwareSet = (data, config) => __firm.http.post(FW + 'set', data || {}, config);
        __firm.firmwarePoweroff = (data, config) => __firm.http.post(FW + 'poweroff', data || {}, config);
        __firm.firmwareReboot = (data, config) => __firm.http.post(FW + 'reboot', data || {}, config);
        __firm.firmwareResyncPlugins = (data, config) => __firm.http.post(FW + 'resyncPlugins', data || {}, config);
        __firm.firmwareSyncPlugins = (data, config) => __firm.http.post(FW + 'syncPlugins', data || {}, config);
        // per-package actions (POST, pkg in path)
        __firm.firmwareInstall = (pkg, config) => __firm.http.post(FW + 'install/' + (pkg || ''), {}, config);
        __firm.firmwareReinstall = (pkg, config) => __firm.http.post(FW + 'reinstall/' + (pkg || ''), {}, config);
        __firm.firmwareRemove = (pkg, config) => __firm.http.post(FW + 'remove/' + (pkg || ''), {}, config);
        __firm.firmwareLock = (pkg, config) => __firm.http.post(FW + 'lock/' + (pkg || ''), {}, config);
        __firm.firmwareUnlock = (pkg, config) => __firm.http.post(FW + 'unlock/' + (pkg || ''), {}, config);
        __firm.firmwareDetails = (pkg, config) => __firm.http.post(FW + 'details/' + (pkg || ''), {}, config);
      }

      // FORK FIX (kea dhcpv4 reservations): opnsense-typescript-client 0.5.3 maps
      // dhcpv4GetReservation to the wrong route — it returns [] even when reservations
      // exist. Verified live 2026-06-20: raw POST /api/kea/dhcpv4/searchReservation
      // returned 85 reservations on eu-6 while the client method returned []. Listing
      // needs searchReservation (POST); the single editable model is getReservation/<uuid>
      // (GET) — verified live read-side. add/set/del share the /api/kea/dhcpv4/ controller
      // (camelCase actions, like the core firewall — NOT snake_case like the WG plugin).
      const __kea = this.client.kea;
      if (__kea && __kea.http) {
        const KR = '/api/kea/dhcpv4/';
        // Overloaded: a uuid string -> the one editable model; a params object
        // {searchPhrase,current,rowCount} or nothing -> the full list (search).
        __kea.dhcpv4GetReservation = (a, config) => {
          if (typeof a === 'string' && a) return __kea.http.get(KR + 'getReservation/' + a, config);
          const body = (a && typeof a === 'object') ? a : {};
          return __kea.http.post(KR + 'searchReservation', { current: 1, rowCount: 200, ...body }, config);
        };
        __kea.dhcpv4AddReservation = (data, config) => __kea.http.post(KR + 'addReservation', data, config);
        __kea.dhcpv4SetReservation = (uuid, data, config) => __kea.http.post(KR + 'setReservation/' + uuid, data, config);
        __kea.dhcpv4DelReservation = (uuid, config) => __kea.http.post(KR + 'delReservation/' + (uuid || ''), {}, config);
      }
    }
    return this.client;
  }

  setupHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.getAvailableTools(),
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      const tool = TOOLS.find(t => t.name === name);
      if (!tool) {
        throw new McpError(ErrorCode.MethodNotFound, \`Tool \${name} not found\`);
      }

      // Skip plugin tools if not enabled
      if (tool.module === 'plugins' && !this.config.includePlugins) {
        throw new McpError(ErrorCode.MethodNotFound, \`Plugin tools not enabled. Use --plugins flag to enable.\`);
      }

      try {
        const result = await this.callModularTool(tool, args);
        return {
          content: [{ type: 'text', text: JSON.stringify(pruneOptions(result), null, 2) }],
        };
      } catch (error) {
        console.error('Tool call error:', {
          tool: tool.name,
          module: tool.module,
          args,
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined
        });
        
        // Extract more details from axios errors
        let errorMessage = 'Unknown error';
        if (error instanceof Error) {
          errorMessage = error.message;
          if (error.response) {
            const response = error.response;
            errorMessage = \`HTTP \${response.status}: \${response.statusText}\\n\`;
            if (response.data) {
              errorMessage += \`Response: \${JSON.stringify(response.data, null, 2)}\`;
            }
          }
        }
        
        return {
          content: [{
            type: 'text',
            text: \`Error calling \${tool.name}.\${args.method || 'unknown'}: \${errorMessage}\`
          }],
        };
      }
    });
  }

  getAvailableTools() {
    return TOOLS.filter(tool => {
      // Include all non-plugin tools
      if (tool.module !== 'plugins') return true;
      // Include plugin tools only if enabled
      return this.config.includePlugins;
    }).map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema
    }));
  }

  async callModularTool(tool, args) {
    const client = this.ensureClient();
    
    // Validate method parameter
    if (!args.method) {
      throw new Error(\`Missing required parameter 'method'. Available methods: \${tool.methods.join(', ')}\`);
    }
    
    if (!tool.methods.includes(args.method)) {
      throw new Error(\`Invalid method '\${args.method}'. Available methods: \${tool.methods.join(', ')}\`);
    }
    
    // Get the module
    let moduleObj;
    if (tool.module === 'plugins' && tool.submodule) {
      moduleObj = client.plugins[tool.submodule];
    } else {
      moduleObj = client[tool.module];
    }

    if (!moduleObj) {
      throw new Error(\`Module \${tool.module} not found\`);
    }

    // Get the method
    const method = moduleObj[args.method];
    if (!method || typeof method !== 'function') {
      throw new Error(\`Method \${args.method} not found in module \${tool.module}\`);
    }

    // Call the method with params (if provided)
    console.error(\`Calling \${tool.module}.\${args.method} with params:\`, args.params);
    
    // Extract params, excluding the method field
    const { method: _, params = {}, ...otherArgs } = args;
    const callParams = { ...params, ...otherArgs };

    // Power-user escape hatch: explicit ordered positional args, for methods whose
    // signature isn't covered by the uuid/body convention below (e.g.
    // backupDownload(host, backup, config), clientPsk(...), etc.). Pass
    // params.args = [arg1, arg2, ...].
    if (Array.isArray(callParams.args)) {
      return await method.apply(moduleObj, callParams.args);
    }

    // The @richard-stovall/opnsense-typescript-client methods take POSITIONAL
    // args (uuid, data, config) — NOT a single options bag. Passing one object
    // made uuid land as the whole object (empty GETs, "uuid not in URL path",
    // failed set/add/del). Map our generic params to positional args.
    // Fixes upstream issues #1 (delHostOverride uuid) and #4 (writes always fail).
    const { uuid, item, data } = callParams;
    const body = item !== undefined ? item : data;
    if (uuid !== undefined) {
      return body !== undefined
        ? await method.call(moduleObj, uuid, body)
        : await method.call(moduleObj, uuid);
    }
    if (body !== undefined) {
      return await method.call(moduleObj, body);
    }
    // search / list / no-arg getters take (config?) — keep prior behavior.
    if (Object.keys(callParams).length > 0) {
      return await method.call(moduleObj, callParams);
    }
    return await method.call(moduleObj);
  }

  async start() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('OPNsense MCP server v0.7.0 (modular) started');
    console.error(\`Core tools: ${toolsData.coreTools} modules\`);
    console.error(\`Plugin tools: ${toolsData.pluginTools} modules (\${this.config.includePlugins ? 'enabled' : 'disabled'})\`);
    console.error(\`Total available: \${this.config.includePlugins ? '${toolsData.totalTools}' : '${toolsData.coreTools}'} modules\`);
  }
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const config = {
    url: '',
    apiKey: '',
    apiSecret: '',
    verifySsl: true,
    includePlugins: false,
    readOnly: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--url':
      case '-u':
        config.url = args[++i];
        break;
      case '--api-key':
      case '-k':
        config.apiKey = args[++i];
        break;
      case '--api-secret':
      case '-s':
        config.apiSecret = args[++i];
        break;
      case '--no-verify-ssl':
        config.verifySsl = false;
        break;
      case '--plugins':
        config.includePlugins = true;
        break;
      case '--read-only':
        config.readOnly = true;
        break;
      case '--help':
      case '-h':
        showHelp();
        process.exit(0);
        break;
    }
  }

  return config;
}

function showHelp() {
  console.log(\`
OPNsense MCP Server v0.7.0 (Modular Edition)

Usage: opnsense-mcp-server --url <url> --api-key <key> --api-secret <secret> [options]

Required:
  -u, --url <url>           OPNsense API URL (e.g., https://192.168.1.1)
  -k, --api-key <key>       API Key for authentication
  -s, --api-secret <secret> API Secret for authentication

Options:
  --no-verify-ssl           Disable SSL certificate verification
  --plugins                 Include plugin tools (adds ${toolsData.pluginTools} plugin modules)
  --read-only               Refuse every method that can change the firewall
  -h, --help                Show this help message

Environment Variables:
  OPNSENSE_URL              OPNsense API URL
  OPNSENSE_API_KEY          API Key
  OPNSENSE_API_SECRET       API Secret
  OPNSENSE_VERIFY_SSL       Set to 'false' to disable SSL verification
  INCLUDE_PLUGINS           Set to 'true' to include plugin tools
  OPNSENSE_READ_ONLY        Set to 'true' for read-only mode

Examples:
  # Basic usage (${toolsData.coreTools} core modules)
  opnsense-mcp-server --url https://192.168.1.1 --api-key mykey --api-secret mysecret

  # With plugins enabled (${toolsData.totalTools} total modules)
  opnsense-mcp-server --url https://192.168.1.1 --api-key mykey --api-secret mysecret --plugins

Tool Usage:
  Each tool represents a module and accepts a 'method' parameter to specify the operation.
  
  Example: firewall_manage
  - method: "aliasSearchItem" - Search firewall aliases
  - method: "aliasAddItem" - Add a new alias
  - method: "aliasSetItem" - Update an existing alias (requires uuid in params)
  
  Parameters are passed in the 'params' object:
  {
    "method": "aliasSearchItem",
    "params": {
      "searchPhrase": "web",
      "current": 1,
      "rowCount": 20
    }
  }

Based on @richard-stovall/opnsense-typescript-client v0.5.3
\`);
}

// Main entry point
async function main() {
  const config = parseArgs();
  
  // Use environment variables as fallback
  config.url = config.url || process.env.OPNSENSE_URL || '';
  config.apiKey = config.apiKey || process.env.OPNSENSE_API_KEY || '';
  config.apiSecret = config.apiSecret || process.env.OPNSENSE_API_SECRET || '';
  if (!config.verifySsl || process.env.OPNSENSE_VERIFY_SSL === 'false') {
    config.verifySsl = false;
  }
  if (config.includePlugins || process.env.INCLUDE_PLUGINS === 'true') {
    config.includePlugins = true;
  }
  if (config.readOnly || process.env.OPNSENSE_READ_ONLY === 'true') {
    config.readOnly = true;
  }

  // Validate required arguments
  if (!config.url || !config.apiKey || !config.apiSecret) {
    console.error('Error: Missing required arguments\\n');
    showHelp();
    process.exit(1);
  }

  // Create and start server
  const server = new OPNsenseMCPServer(config);
  await server.start();
}

// Run the server
main().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
`;

fs.writeFileSync(path.join(__dirname, '..', 'index.js'), serverCode);
console.log('Built index.js successfully');
console.log(`Total tools: ${toolsData.totalTools} modules`);
console.log(`Core tools: ${toolsData.coreTools} modules`);
console.log(`Plugin tools: ${toolsData.pluginTools} modules`);