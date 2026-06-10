#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Read the tools data from parent directory
const toolsData = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'tools-generated.json'), 'utf8'));

// Generate the single-file server with modular tools
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

class OPNsenseMCPServer {
  constructor(config) {
    this.config = config;
    this.client = null;
    this.server = new Server(
      {
        name: 'opnsense-mcp-server',
        version: '0.6.0',
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
        __fw.filterBaseApply = (rev, data, config) => __fw.http.post('/api/firewall/filter/apply' + (rev ? '/' + rev : ''), data, config);
        __fw.filterBaseSavepoint = (data, config) => __fw.http.post('/api/firewall/filter/savepoint', data, config);
        __fw.filterBaseRevert = (rev, data, config) => __fw.http.post('/api/firewall/filter/revert' + (rev ? '/' + rev : ''), data, config);
        __fw.filterBaseCancelRollback = (rev, data, config) => __fw.http.post('/api/firewall/filter/cancel_rollback' + (rev ? '/' + rev : ''), data, config);
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
        __fw.filterSearchRule = (data, config) => __fw.http.post('/api/firewall/filter/searchRule', data || { current: 1, rowCount: 5000 }, config);
        __fw.aliasSearchItem = (data, config) => __fw.http.post('/api/firewall/alias/searchItem', data || { current: 1, rowCount: 5000 }, config);
        __fw.groupSearchItem = (data, config) => __fw.http.post('/api/firewall/group/searchItem', data || { current: 1, rowCount: 5000 }, config);
        __fw.categorySearchItem = (data, config) => __fw.http.post('/api/firewall/category/searchItem', data || { current: 1, rowCount: 5000 }, config);
        __fw.filterBaseListPortSelectOptions = (config) => __fw.http.get('/api/firewall/filter/list_port_select_options', config);
        __fw.filterToggleRuleLog = (uuid, data, config) => __fw.http.post('/api/firewall/filter/toggleRuleLog/' + (uuid || ''), data, config);
        __fw.filterFlushInspectCache = (data, config) => __fw.http.post('/api/firewall/filter/flushInspectCache', data, config);
      }
      // FORK ADD (interfaces searchItem + bridge): the client omits every interface
      // *SettingsSearchItem (the box controllers have searchItem) and the entire
      // BridgeSettings controller. Verified live 2026-06-10 (vlan_settings/searchItem
      // = 17 rows on eu-6). Same stale-spec gap as the firewall searchRule.
      const __if = this.client.interfaces;
      if (__if && __if.http) {
        const S = (p) => (data, config) => __if.http.post('/api/interfaces/' + p + '/searchItem', data || { current: 1, rowCount: 5000 }, config);
        __if.vlanSettingsSearchItem = S('vlan_settings');
        __if.vxlanSettingsSearchItem = S('vxlan_settings');
        __if.laggSettingsSearchItem = S('lagg_settings');
        __if.loopbackSettingsSearchItem = S('loopback_settings');
        __if.neighborSettingsSearchItem = S('neighbor_settings');
        __if.gifSettingsSearchItem = S('gif_settings');
        __if.greSettingsSearchItem = S('gre_settings');
        __if.vipSettingsSearchItem = S('vip_settings');
        const B = '/api/interfaces/bridge_settings/';
        __if.bridgeSettingsSearchItem = (data, config) => __if.http.post(B + 'searchItem', data || { current: 1, rowCount: 5000 }, config);
        __if.bridgeSettingsGetItem = (uuid, config) => __if.http.get(B + 'getItem/' + (uuid || ''), config);
        __if.bridgeSettingsAddItem = (data, config) => __if.http.post(B + 'addItem', data, config);
        __if.bridgeSettingsSetItem = (uuid, data, config) => __if.http.post(B + 'setItem/' + uuid, data, config);
        __if.bridgeSettingsDelItem = (uuid, data, config) => __if.http.post(B + 'delItem/' + uuid, data, config);
        __if.bridgeSettingsReconfigure = (data, config) => __if.http.post(B + 'reconfigure', data, config);
      }
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
        __wg.serviceReconfigure = (data, config) => __wg.http.post(WG + 'service/reconfigure', data || {}, config);
        __wg.serviceRestart = (data, config) => __wg.http.post(WG + 'service/restart', data || {}, config);
        __wg.serviceStart = (data, config) => __wg.http.post(WG + 'service/start', data || {}, config);
        __wg.serviceStop = (data, config) => __wg.http.post(WG + 'service/stop', data || {}, config);
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
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
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
    console.error('OPNsense MCP server v0.6.0 (modular) started');
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
OPNsense MCP Server v0.6.0 (Modular Edition)

Usage: opnsense-mcp-server --url <url> --api-key <key> --api-secret <secret> [options]

Required:
  -u, --url <url>           OPNsense API URL (e.g., https://192.168.1.1)
  -k, --api-key <key>       API Key for authentication
  -s, --api-secret <secret> API Secret for authentication

Options:
  --no-verify-ssl           Disable SSL certificate verification
  --plugins                 Include plugin tools (adds ${toolsData.pluginTools} plugin modules)
  -h, --help                Show this help message

Environment Variables:
  OPNSENSE_URL              OPNsense API URL
  OPNSENSE_API_KEY          API Key
  OPNSENSE_API_SECRET       API Secret
  OPNSENSE_VERIFY_SSL       Set to 'false' to disable SSL verification
  INCLUDE_PLUGINS           Set to 'true' to include plugin tools

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

// Write the single-file server to parent directory
fs.writeFileSync(path.join(__dirname, '..', 'index.js'), serverCode);
console.log('Built index.js successfully');
console.log(`Total tools: ${toolsData.totalTools} modules`);
console.log(`Core tools: ${toolsData.coreTools} modules`);
console.log(`Plugin tools: ${toolsData.pluginTools} modules`);