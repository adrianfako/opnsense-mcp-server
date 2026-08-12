#!/usr/bin/env node
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
const TOOLS = [
  {
    "name": "core_manage",
    "description": "Core system management - 46 available methods including: backupBackups, backupDeleteBackup, backupDiff, backupDownload, backupProviders...",
    "module": "core",
    "methods": [
      "backupBackups",
      "backupDeleteBackup",
      "backupDiff",
      "backupDownload",
      "backupProviders",
      "backupRevertBackup",
      "dashboardGetDashboard",
      "dashboardPicture",
      "dashboardProductInfoFeed",
      "dashboardRestoreDefaults",
      "dashboardSaveWidgets",
      "defaultsFactoryDefaults",
      "defaultsGet",
      "defaultsGetInstalledSections",
      "defaultsReset",
      "hasyncGet",
      "hasyncReconfigure",
      "hasyncSet",
      "hasyncStatusRemoteService",
      "hasyncStatusRestart",
      "hasyncStatusRestartAll",
      "hasyncStatusServices",
      "hasyncStatusStart",
      "hasyncStatusStop",
      "hasyncStatusVersion",
      "initialSetupAbort",
      "initialSetupConfigure",
      "menuSearch",
      "menuTree",
      "serviceRestart",
      "serviceSearch",
      "serviceStart",
      "serviceStop",
      "snapshotsActivate",
      "snapshotsAdd",
      "snapshotsDel",
      "snapshotsGet",
      "snapshotsIsSupported",
      "snapshotsSearch",
      "snapshotsSet",
      "systemDismissStatus",
      "systemHalt",
      "systemReboot",
      "systemStatus",
      "tunablesAddItem",
      "tunablesDelItem",
      "tunablesGet",
      "tunablesGetItem",
      "tunablesReconfigure",
      "tunablesReset",
      "tunablesSearchItem",
      "tunablesSet",
      "tunablesSetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "backupBackups",
            "backupDeleteBackup",
            "backupDiff",
            "backupDownload",
            "backupProviders",
            "backupRevertBackup",
            "dashboardGetDashboard",
            "dashboardPicture",
            "dashboardProductInfoFeed",
            "dashboardRestoreDefaults",
            "dashboardSaveWidgets",
            "defaultsFactoryDefaults",
            "defaultsGet",
            "defaultsGetInstalledSections",
            "defaultsReset",
            "hasyncGet",
            "hasyncReconfigure",
            "hasyncSet",
            "hasyncStatusRemoteService",
            "hasyncStatusRestart",
            "hasyncStatusRestartAll",
            "hasyncStatusServices",
            "hasyncStatusStart",
            "hasyncStatusStop",
            "hasyncStatusVersion",
            "initialSetupAbort",
            "initialSetupConfigure",
            "menuSearch",
            "menuTree",
            "serviceRestart",
            "serviceSearch",
            "serviceStart",
            "serviceStop",
            "snapshotsActivate",
            "snapshotsAdd",
            "snapshotsDel",
            "snapshotsGet",
            "snapshotsIsSupported",
            "snapshotsSearch",
            "snapshotsSet",
            "systemDismissStatus",
            "systemHalt",
            "systemReboot",
            "systemStatus",
            "tunablesAddItem",
            "tunablesDelItem",
            "tunablesGet",
            "tunablesGetItem",
            "tunablesReconfigure",
            "tunablesReset",
            "tunablesSearchItem",
            "tunablesSet",
            "tunablesSetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "firewall_manage",
    "description": "Firewall management - 89 available methods. WRITE-BODY SCHEMA (live-validated on OPNsense 26.x, 2026-06-11): add/set bodies MUST be the family's nested editable model — the shape its *GetRule/*GetItem returns (call with no uuid for an empty template). NEVER send the flat dotted keys that *SearchRule/*SearchItem return: OPNsense answers HTTP 200 'saved' but silently drops mis-shaped fields (e.g. a d_nat rule built from search-shaped keys saves with an EMPTY destination and matches everything). Wrappers: params.item = {rule:{...}} for dNat/filter/sourceNat/oneToOne/npt, {alias:{...}}, {group:{...}}, {category:{...}}. Field dialects: dNat is the outlier — NESTED source/destination objects {network,address,port,not}, flag 'disabled', text 'descr', lowercase protocol keys (tcp, udp, tcp/udp); filter/sourceNat/oneToOne/npt use FLAT source_net/source_not/source_port + destination_net/destination_not/destination_port, flag 'enabled', text 'description', UPPERCASE protocol (TCP, UDP, TCP/UDP). Family extras: sourceNat target/target_port/staticnatport/nonat; oneToOne external + type (binat|nat); npt trackif; filter action (pass|block|reject)/quick/direction (in|out|any)/gateway/statetype; alias name/type (host|network|port|url|urltable|geoip|networkgroup|mac|asn|...)/content (newline-separated entries)/proto; group ifname/members (comma-separated interfaces; uuid IS the ifname)/nogroup; category name/auto/color (hex, no #). 'categories' everywhere = comma-separated category UUIDs. Writes only STAGE config — follow with the family apply (dNatApply/sourceNatApply/oneToOneApply/nptApply/filterBaseApply) or aliasReconfigure/groupReconfigure. Worked dNat example: {item:{rule:{interface:'wan',ipprotocol:'inet',protocol:'tcp',source:{network:'',address:'',port:'',not:'0'},destination:{network:'wanip',address:'',port:'29998',not:'0'},target:'10.1.2.249','local-port':'22',descr:'x',nordr:'0',disabled:'0'}}}",
    "module": "firewall",
    "methods": [
      "aliasAddItem",
      "aliasDelItem",
      "aliasExport",
      "aliasGet",
      "aliasGetAliasUUID",
      "aliasGetGeoIP",
      "aliasGetItem",
      "aliasGetTableSize",
      "aliasImport",
      "aliasListCategories",
      "aliasListCountries",
      "aliasListNetworkAliases",
      "aliasListUserGroups",
      "aliasReconfigure",
      "aliasSearchItem",
      "aliasSet",
      "aliasSetItem",
      "aliasToggleItem",
      "aliasUpdate",
      "aliasUtilAdd",
      "aliasUtilAliases",
      "aliasUtilDelete",
      "aliasUtilFindReferences",
      "aliasUtilFlush",
      "aliasUtilList",
      "aliasUtilUpdateBogons",
      "categoryAddItem",
      "categoryDelItem",
      "categoryDownload",
      "categoryGet",
      "categoryGetItem",
      "categorySearchItem",
      "categorySet",
      "categorySetItem",
      "categoryUpload",
      "dNatAddRule",
      "dNatApply",
      "dNatDelRule",
      "dNatDownloadRules",
      "dNatGet",
      "dNatGetRule",
      "dNatListCategories",
      "dNatListNetworkSelectOptions",
      "dNatListPortSelectOptions",
      "dNatMoveRuleBefore",
      "dNatSearchRule",
      "dNatSet",
      "dNatSetRule",
      "dNatToggleRule",
      "dNatToggleRuleLog",
      "dNatUploadRules",
      "filterAddRule",
      "filterApply",
      "filterBaseApply",
      "filterBaseCancelRollback",
      "filterBaseGet",
      "filterBaseListCategories",
      "filterBaseListNetworkSelectOptions",
      "filterBaseListPortSelectOptions",
      "filterBaseRevert",
      "filterBaseSavepoint",
      "filterBaseSet",
      "filterDelRule",
      "filterDownloadRules",
      "filterFlushInspectCache",
      "filterGetInterfaceList",
      "filterGetRule",
      "filterListCategories",
      "filterListNetworkSelectOptions",
      "filterListPortSelectOptions",
      "filterMoveRuleBefore",
      "filterSearchRule",
      "filterSetRule",
      "filterToggleRule",
      "filterToggleRuleLog",
      "filterUploadRules",
      "filterUtilRuleStats",
      "groupAddItem",
      "groupDelItem",
      "groupGet",
      "groupGetItem",
      "groupReconfigure",
      "groupSearchItem",
      "groupSet",
      "groupSetItem",
      "migrationCountOutbound",
      "migrationCountRules",
      "migrationDownloadOutbound",
      "migrationDownloadRules",
      "migrationFlush",
      "migrationFlushOutbound",
      "nptAddRule",
      "nptApply",
      "nptDelRule",
      "nptDownloadRules",
      "nptGetRule",
      "nptListCategories",
      "nptListNetworkSelectOptions",
      "nptListPortSelectOptions",
      "nptMoveRuleBefore",
      "nptSearchRule",
      "nptSetRule",
      "nptToggleRule",
      "nptToggleRuleLog",
      "nptUploadRules",
      "oneToOneAddRule",
      "oneToOneApply",
      "oneToOneDelRule",
      "oneToOneDownloadRules",
      "oneToOneGetRule",
      "oneToOneListCategories",
      "oneToOneListNetworkSelectOptions",
      "oneToOneListPortSelectOptions",
      "oneToOneMoveRuleBefore",
      "oneToOneSearchRule",
      "oneToOneSetRule",
      "oneToOneToggleRule",
      "oneToOneToggleRuleLog",
      "oneToOneUploadRules",
      "sourceNatAddRule",
      "sourceNatApply",
      "sourceNatDelRule",
      "sourceNatDownloadRules",
      "sourceNatGet",
      "sourceNatGetRule",
      "sourceNatListCategories",
      "sourceNatListNetworkSelectOptions",
      "sourceNatListPortSelectOptions",
      "sourceNatMoveRuleBefore",
      "sourceNatSearchRule",
      "sourceNatSet",
      "sourceNatSetRule",
      "sourceNatToggleRule",
      "sourceNatToggleRuleLog",
      "sourceNatUploadRules"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "aliasAddItem",
            "aliasDelItem",
            "aliasExport",
            "aliasGet",
            "aliasGetAliasUUID",
            "aliasGetGeoIP",
            "aliasGetItem",
            "aliasGetTableSize",
            "aliasImport",
            "aliasListCategories",
            "aliasListCountries",
            "aliasListNetworkAliases",
            "aliasListUserGroups",
            "aliasReconfigure",
            "aliasSearchItem",
            "aliasSet",
            "aliasSetItem",
            "aliasToggleItem",
            "aliasUpdate",
            "aliasUtilAdd",
            "aliasUtilAliases",
            "aliasUtilDelete",
            "aliasUtilFindReferences",
            "aliasUtilFlush",
            "aliasUtilList",
            "aliasUtilUpdateBogons",
            "categoryAddItem",
            "categoryDelItem",
            "categoryDownload",
            "categoryGet",
            "categoryGetItem",
            "categorySearchItem",
            "categorySet",
            "categorySetItem",
            "categoryUpload",
            "dNatAddRule",
            "dNatApply",
            "dNatDelRule",
            "dNatDownloadRules",
            "dNatGet",
            "dNatGetRule",
            "dNatListCategories",
            "dNatListNetworkSelectOptions",
            "dNatListPortSelectOptions",
            "dNatMoveRuleBefore",
            "dNatSearchRule",
            "dNatSet",
            "dNatSetRule",
            "dNatToggleRule",
            "dNatToggleRuleLog",
            "dNatUploadRules",
            "filterAddRule",
            "filterApply",
            "filterBaseApply",
            "filterBaseCancelRollback",
            "filterBaseGet",
            "filterBaseListCategories",
            "filterBaseListNetworkSelectOptions",
            "filterBaseListPortSelectOptions",
            "filterBaseRevert",
            "filterBaseSavepoint",
            "filterBaseSet",
            "filterDelRule",
            "filterDownloadRules",
            "filterFlushInspectCache",
            "filterGetInterfaceList",
            "filterGetRule",
            "filterListCategories",
            "filterListNetworkSelectOptions",
            "filterListPortSelectOptions",
            "filterMoveRuleBefore",
            "filterSearchRule",
            "filterSetRule",
            "filterToggleRule",
            "filterToggleRuleLog",
            "filterUploadRules",
            "filterUtilRuleStats",
            "groupAddItem",
            "groupDelItem",
            "groupGet",
            "groupGetItem",
            "groupReconfigure",
            "groupSearchItem",
            "groupSet",
            "groupSetItem",
            "migrationCountOutbound",
            "migrationCountRules",
            "migrationDownloadOutbound",
            "migrationDownloadRules",
            "migrationFlush",
            "migrationFlushOutbound",
            "nptAddRule",
            "nptApply",
            "nptDelRule",
            "nptDownloadRules",
            "nptGetRule",
            "nptListCategories",
            "nptListNetworkSelectOptions",
            "nptListPortSelectOptions",
            "nptMoveRuleBefore",
            "nptSearchRule",
            "nptSetRule",
            "nptToggleRule",
            "nptToggleRuleLog",
            "nptUploadRules",
            "oneToOneAddRule",
            "oneToOneApply",
            "oneToOneDelRule",
            "oneToOneDownloadRules",
            "oneToOneGetRule",
            "oneToOneListCategories",
            "oneToOneListNetworkSelectOptions",
            "oneToOneListPortSelectOptions",
            "oneToOneMoveRuleBefore",
            "oneToOneSearchRule",
            "oneToOneSetRule",
            "oneToOneToggleRule",
            "oneToOneToggleRuleLog",
            "oneToOneUploadRules",
            "sourceNatAddRule",
            "sourceNatApply",
            "sourceNatDelRule",
            "sourceNatDownloadRules",
            "sourceNatGet",
            "sourceNatGetRule",
            "sourceNatListCategories",
            "sourceNatListNetworkSelectOptions",
            "sourceNatListPortSelectOptions",
            "sourceNatMoveRuleBefore",
            "sourceNatSearchRule",
            "sourceNatSet",
            "sourceNatSetRule",
            "sourceNatToggleRule",
            "sourceNatToggleRuleLog",
            "sourceNatUploadRules"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "auth_manage",
    "description": "Authentication management - 19 available methods including: groupAdd, groupDel, groupGet, groupSet, privGet...",
    "module": "auth",
    "methods": [
      "groupAdd",
      "groupDel",
      "groupGet",
      "groupSearch",
      "groupSet",
      "privGet",
      "privGetItem",
      "privSearch",
      "privSet",
      "privSetItem",
      "userAdd",
      "userAddApiKey",
      "userDel",
      "userDelApiKey",
      "userDownload",
      "userGet",
      "userNewOtpSeed",
      "userSearch",
      "userSearchApiKey",
      "userSet",
      "userUpload"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "groupAdd",
            "groupDel",
            "groupGet",
            "groupSearch",
            "groupSet",
            "privGet",
            "privGetItem",
            "privSearch",
            "privSet",
            "privSetItem",
            "userAdd",
            "userAddApiKey",
            "userDel",
            "userDelApiKey",
            "userDownload",
            "userGet",
            "userNewOtpSeed",
            "userSearch",
            "userSearchApiKey",
            "userSet",
            "userUpload"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "interfaces_manage",
    "description": "Network interfaces management - 63 available methods including: gifSettingsAddItem, gifSettingsDelItem, gifSettingsGet, gifSettingsGetIfOptions, gifSettingsGetItem...",
    "module": "interfaces",
    "methods": [
      "assignmentAddItem",
      "assignmentDelItem",
      "assignmentGetItem",
      "assignmentReconfigure",
      "assignmentSearchItem",
      "assignmentSetItem",
      "bridgeSettingsAddItem",
      "bridgeSettingsDelItem",
      "bridgeSettingsGetItem",
      "bridgeSettingsReconfigure",
      "bridgeSettingsSearchItem",
      "bridgeSettingsSetItem",
      "gifSettingsAddItem",
      "gifSettingsDelItem",
      "gifSettingsGet",
      "gifSettingsGetIfOptions",
      "gifSettingsGetItem",
      "gifSettingsReconfigure",
      "gifSettingsSearchItem",
      "gifSettingsSet",
      "gifSettingsSetItem",
      "greSettingsAddItem",
      "greSettingsDelItem",
      "greSettingsGet",
      "greSettingsGetIfOptions",
      "greSettingsGetItem",
      "greSettingsReconfigure",
      "greSettingsSearchItem",
      "greSettingsSet",
      "greSettingsSetItem",
      "laggSettingsAddItem",
      "laggSettingsDelItem",
      "laggSettingsGet",
      "laggSettingsGetItem",
      "laggSettingsReconfigure",
      "laggSettingsSearchItem",
      "laggSettingsSet",
      "laggSettingsSetItem",
      "loopbackSettingsAddItem",
      "loopbackSettingsDelItem",
      "loopbackSettingsGet",
      "loopbackSettingsGetItem",
      "loopbackSettingsReconfigure",
      "loopbackSettingsSearchItem",
      "loopbackSettingsSet",
      "loopbackSettingsSetItem",
      "neighborSettingsAddItem",
      "neighborSettingsDelItem",
      "neighborSettingsGet",
      "neighborSettingsGetItem",
      "neighborSettingsReconfigure",
      "neighborSettingsSearchItem",
      "neighborSettingsSet",
      "neighborSettingsSetItem",
      "overviewExport",
      "overviewGetInterface",
      "overviewInterfacesInfo",
      "overviewReloadInterface",
      "settingsGet",
      "settingsReconfigure",
      "vipSettingsAddItem",
      "vipSettingsDelItem",
      "vipSettingsGet",
      "vipSettingsGetItem",
      "vipSettingsGetUnusedVhid",
      "vipSettingsReconfigure",
      "vipSettingsSearchItem",
      "vipSettingsSet",
      "vipSettingsSetItem",
      "vlanSettingsAddItem",
      "vlanSettingsDelItem",
      "vlanSettingsGet",
      "vlanSettingsGetItem",
      "vlanSettingsReconfigure",
      "vlanSettingsSearchItem",
      "vlanSettingsSet",
      "vlanSettingsSetItem",
      "vxlanSettingsAddItem",
      "vxlanSettingsDelItem",
      "vxlanSettingsGet",
      "vxlanSettingsGetItem",
      "vxlanSettingsReconfigure",
      "vxlanSettingsSearchItem",
      "vxlanSettingsSet",
      "vxlanSettingsSetItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "assignmentAddItem",
            "assignmentDelItem",
            "assignmentGetItem",
            "assignmentReconfigure",
            "assignmentSearchItem",
            "assignmentSetItem",
            "bridgeSettingsAddItem",
            "bridgeSettingsDelItem",
            "bridgeSettingsGetItem",
            "bridgeSettingsReconfigure",
            "bridgeSettingsSearchItem",
            "bridgeSettingsSetItem",
            "gifSettingsAddItem",
            "gifSettingsDelItem",
            "gifSettingsGet",
            "gifSettingsGetIfOptions",
            "gifSettingsGetItem",
            "gifSettingsReconfigure",
            "gifSettingsSearchItem",
            "gifSettingsSet",
            "gifSettingsSetItem",
            "greSettingsAddItem",
            "greSettingsDelItem",
            "greSettingsGet",
            "greSettingsGetIfOptions",
            "greSettingsGetItem",
            "greSettingsReconfigure",
            "greSettingsSearchItem",
            "greSettingsSet",
            "greSettingsSetItem",
            "laggSettingsAddItem",
            "laggSettingsDelItem",
            "laggSettingsGet",
            "laggSettingsGetItem",
            "laggSettingsReconfigure",
            "laggSettingsSearchItem",
            "laggSettingsSet",
            "laggSettingsSetItem",
            "loopbackSettingsAddItem",
            "loopbackSettingsDelItem",
            "loopbackSettingsGet",
            "loopbackSettingsGetItem",
            "loopbackSettingsReconfigure",
            "loopbackSettingsSearchItem",
            "loopbackSettingsSet",
            "loopbackSettingsSetItem",
            "neighborSettingsAddItem",
            "neighborSettingsDelItem",
            "neighborSettingsGet",
            "neighborSettingsGetItem",
            "neighborSettingsReconfigure",
            "neighborSettingsSearchItem",
            "neighborSettingsSet",
            "neighborSettingsSetItem",
            "overviewExport",
            "overviewGetInterface",
            "overviewInterfacesInfo",
            "overviewReloadInterface",
            "settingsGet",
            "settingsReconfigure",
            "vipSettingsAddItem",
            "vipSettingsDelItem",
            "vipSettingsGet",
            "vipSettingsGetItem",
            "vipSettingsGetUnusedVhid",
            "vipSettingsReconfigure",
            "vipSettingsSearchItem",
            "vipSettingsSet",
            "vipSettingsSetItem",
            "vlanSettingsAddItem",
            "vlanSettingsDelItem",
            "vlanSettingsGet",
            "vlanSettingsGetItem",
            "vlanSettingsReconfigure",
            "vlanSettingsSearchItem",
            "vlanSettingsSet",
            "vlanSettingsSetItem",
            "vxlanSettingsAddItem",
            "vxlanSettingsDelItem",
            "vxlanSettingsGet",
            "vxlanSettingsGetItem",
            "vxlanSettingsReconfigure",
            "vxlanSettingsSearchItem",
            "vxlanSettingsSet",
            "vxlanSettingsSetItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "captiveportal_manage",
    "description": "Captiveportal management - 27 available methods including: accessApi, accessLogoff, accessLogon, serviceDelTemplate, serviceGetTemplate...",
    "module": "captiveportal",
    "methods": [
      "accessApi",
      "accessLogoff",
      "accessLogon",
      "accessStatus",
      "serviceDelTemplate",
      "serviceGetTemplate",
      "serviceReconfigure",
      "serviceSaveTemplate",
      "serviceSearchTemplates",
      "sessionConnect",
      "sessionDisconnect",
      "sessionList",
      "sessionSearch",
      "sessionZones",
      "settingsAddZone",
      "settingsDelZone",
      "settingsGet",
      "settingsGetZone",
      "settingsSearchZones",
      "settingsSet",
      "settingsSetZone",
      "settingsToggleZone",
      "templateDelTemplate",
      "templateGetTemplate",
      "templateSaveTemplate",
      "templateSearchTemplates",
      "voucherDropExpiredVouchers",
      "voucherDropVoucherGroup",
      "voucherExpireVoucher",
      "voucherGenerateVouchers",
      "voucherListProviders",
      "voucherListVoucherGroups",
      "voucherListVouchers"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "accessApi",
            "accessLogoff",
            "accessLogon",
            "accessStatus",
            "serviceDelTemplate",
            "serviceGetTemplate",
            "serviceReconfigure",
            "serviceSaveTemplate",
            "serviceSearchTemplates",
            "sessionConnect",
            "sessionDisconnect",
            "sessionList",
            "sessionSearch",
            "sessionZones",
            "settingsAddZone",
            "settingsDelZone",
            "settingsGet",
            "settingsGetZone",
            "settingsSearchZones",
            "settingsSet",
            "settingsSetZone",
            "settingsToggleZone",
            "templateDelTemplate",
            "templateGetTemplate",
            "templateSaveTemplate",
            "templateSearchTemplates",
            "voucherDropExpiredVouchers",
            "voucherDropVoucherGroup",
            "voucherExpireVoucher",
            "voucherGenerateVouchers",
            "voucherListProviders",
            "voucherListVoucherGroups",
            "voucherListVouchers"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "cron_manage",
    "description": "Cron management - 8 available methods including: serviceReconfigure, settingsAddJob, settingsDelJob, settingsGet, settingsGetJob...",
    "module": "cron",
    "methods": [
      "serviceReconfigure",
      "settingsAddJob",
      "settingsDelJob",
      "settingsGet",
      "settingsGetJob",
      "settingsSearchJobs",
      "settingsSet",
      "settingsSetJob",
      "settingsToggleJob"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "settingsAddJob",
            "settingsDelJob",
            "settingsGet",
            "settingsGetJob",
            "settingsSearchJobs",
            "settingsSet",
            "settingsSetJob",
            "settingsToggleJob"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcpv4_manage",
    "description": "Dhcpv4 management - 7 available methods including: leasesDelLease, leasesSearchLease, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "dhcpv4",
    "methods": [
      "leasesDelLease",
      "leasesSearchLease",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "leasesDelLease",
            "leasesSearchLease",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcpv6_manage",
    "description": "Dhcpv6 management - 8 available methods including: leasesDelLease, leasesSearchLease, leasesSearchPrefix, serviceReconfigure, serviceRestart...",
    "module": "dhcpv6",
    "methods": [
      "leasesDelLease",
      "leasesSearchLease",
      "leasesSearchPrefix",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "leasesDelLease",
            "leasesSearchLease",
            "leasesSearchPrefix",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dhcrelay_manage",
    "description": "Dhcrelay management - 12 available methods including: serviceReconfigure, settingsAddDest, settingsAddRelay, settingsDelDest, settingsDelRelay...",
    "module": "dhcrelay",
    "methods": [
      "serviceReconfigure",
      "settingsAddDest",
      "settingsAddRelay",
      "settingsDelDest",
      "settingsDelRelay",
      "settingsGet",
      "settingsGetDest",
      "settingsGetRelay",
      "settingsSearchDest",
      "settingsSearchRelay",
      "settingsSet",
      "settingsSetDest",
      "settingsSetRelay",
      "settingsToggleRelay"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "settingsAddDest",
            "settingsAddRelay",
            "settingsDelDest",
            "settingsDelRelay",
            "settingsGet",
            "settingsGetDest",
            "settingsGetRelay",
            "settingsSearchDest",
            "settingsSearchRelay",
            "settingsSet",
            "settingsSetDest",
            "settingsSetRelay",
            "settingsToggleRelay"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "diagnostics_manage",
    "description": "Diagnostics management - 90 available methods including: activityGetActivity, cpuUsageGetCPUType, cpuUsageStream, dnsReverseLookup, dnsDiagnosticsGet...",
    "module": "diagnostics",
    "methods": [
      "activityGetActivity",
      "cpuUsageGetCPUType",
      "cpuUsageStream",
      "dnsDiagnosticsGet",
      "dnsDiagnosticsSet",
      "dnsReverseLookup",
      "firewallDelState",
      "firewallFlushSources",
      "firewallFlushStates",
      "firewallKillStates",
      "firewallListRuleIds",
      "firewallLog",
      "firewallLogFilters",
      "firewallPfStates",
      "firewallPfStatistics",
      "firewallQueryPfTop",
      "firewallQueryStates",
      "firewallStats",
      "firewallStreamLog",
      "interfaceCarpStatus",
      "interfaceDelRoute",
      "interfaceFlushArp",
      "interfaceGetArp",
      "interfaceGetBpfStatistics",
      "interfaceGetInterfaceConfig",
      "interfaceGetInterfaceNames",
      "interfaceGetInterfaceStatistics",
      "interfaceGetMemoryStatistics",
      "interfaceGetNdp",
      "interfaceGetNetisrStatistics",
      "interfaceGetPfsyncNodes",
      "interfaceGetProtocolStatistics",
      "interfaceGetRoutes",
      "interfaceGetSocketStatistics",
      "interfaceGetVipStatus",
      "interfaceSearchArp",
      "interfaceSearchNdp",
      "lvtemplateAddItem",
      "lvtemplateDelItem",
      "lvtemplateGet",
      "lvtemplateGetItem",
      "lvtemplateSearchItem",
      "lvtemplateSet",
      "lvtemplateSetItem",
      "netflowCacheStats",
      "netflowGetconfig",
      "netflowIsEnabled",
      "netflowReconfigure",
      "netflowReset",
      "netflowSetconfig",
      "netflowStatus",
      "networkinsightExport",
      "networkinsightGetInterfaces",
      "networkinsightGetMetadata",
      "networkinsightGetProtocols",
      "networkinsightGetServices",
      "networkinsightTimeserie",
      "networkinsightTop",
      "packetCaptureDownload",
      "packetCaptureGet",
      "packetCaptureMacInfo",
      "packetCaptureRemove",
      "packetCaptureSearchJobs",
      "packetCaptureSet",
      "packetCaptureStart",
      "packetCaptureStop",
      "packetCaptureView",
      "pingGet",
      "pingRemove",
      "pingSearchJobs",
      "pingSet",
      "pingStart",
      "pingStop",
      "portprobeGet",
      "portprobeSet",
      "systemMemory",
      "systemSystemDisk",
      "systemSystemInformation",
      "systemSystemMbuf",
      "systemSystemResources",
      "systemSystemSwap",
      "systemSystemTemperature",
      "systemSystemTime",
      "systemhealthDelRRD",
      "systemhealthExportAsCSV",
      "systemhealthGetInterfaces",
      "systemhealthGetRRDlist",
      "systemhealthGetRrdList",
      "systemhealthGetSystemHealth",
      "systemhealthReconfigure",
      "tracerouteGet",
      "tracerouteSet",
      "trafficInterface",
      "trafficStream",
      "trafficTop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "activityGetActivity",
            "cpuUsageGetCPUType",
            "cpuUsageStream",
            "dnsDiagnosticsGet",
            "dnsDiagnosticsSet",
            "dnsReverseLookup",
            "firewallDelState",
            "firewallFlushSources",
            "firewallFlushStates",
            "firewallKillStates",
            "firewallListRuleIds",
            "firewallLog",
            "firewallLogFilters",
            "firewallPfStates",
            "firewallPfStatistics",
            "firewallQueryPfTop",
            "firewallQueryStates",
            "firewallStats",
            "firewallStreamLog",
            "interfaceCarpStatus",
            "interfaceDelRoute",
            "interfaceFlushArp",
            "interfaceGetArp",
            "interfaceGetBpfStatistics",
            "interfaceGetInterfaceConfig",
            "interfaceGetInterfaceNames",
            "interfaceGetInterfaceStatistics",
            "interfaceGetMemoryStatistics",
            "interfaceGetNdp",
            "interfaceGetNetisrStatistics",
            "interfaceGetPfsyncNodes",
            "interfaceGetProtocolStatistics",
            "interfaceGetRoutes",
            "interfaceGetSocketStatistics",
            "interfaceGetVipStatus",
            "interfaceSearchArp",
            "interfaceSearchNdp",
            "lvtemplateAddItem",
            "lvtemplateDelItem",
            "lvtemplateGet",
            "lvtemplateGetItem",
            "lvtemplateSearchItem",
            "lvtemplateSet",
            "lvtemplateSetItem",
            "netflowCacheStats",
            "netflowGetconfig",
            "netflowIsEnabled",
            "netflowReconfigure",
            "netflowReset",
            "netflowSetconfig",
            "netflowStatus",
            "networkinsightExport",
            "networkinsightGetInterfaces",
            "networkinsightGetMetadata",
            "networkinsightGetProtocols",
            "networkinsightGetServices",
            "networkinsightTimeserie",
            "networkinsightTop",
            "packetCaptureDownload",
            "packetCaptureGet",
            "packetCaptureMacInfo",
            "packetCaptureRemove",
            "packetCaptureSearchJobs",
            "packetCaptureSet",
            "packetCaptureStart",
            "packetCaptureStop",
            "packetCaptureView",
            "pingGet",
            "pingRemove",
            "pingSearchJobs",
            "pingSet",
            "pingStart",
            "pingStop",
            "portprobeGet",
            "portprobeSet",
            "systemMemory",
            "systemSystemDisk",
            "systemSystemInformation",
            "systemSystemMbuf",
            "systemSystemResources",
            "systemSystemSwap",
            "systemSystemTemperature",
            "systemSystemTime",
            "systemhealthDelRRD",
            "systemhealthExportAsCSV",
            "systemhealthGetInterfaces",
            "systemhealthGetRRDlist",
            "systemhealthGetRrdList",
            "systemhealthGetSystemHealth",
            "systemhealthReconfigure",
            "tracerouteGet",
            "tracerouteSet",
            "trafficInterface",
            "trafficStream",
            "trafficTop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "dnsmasq_manage",
    "description": "Dnsmasq management - 35 available methods including: leasesSearch, serviceReconfigure, serviceRestart, serviceStart, serviceStatus...",
    "module": "dnsmasq",
    "methods": [
      "leasesSearch",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddBoot",
      "settingsAddDomain",
      "settingsAddHost",
      "settingsAddOption",
      "settingsAddRange",
      "settingsAddTag",
      "settingsDelBoot",
      "settingsDelDomain",
      "settingsDelHost",
      "settingsDelOption",
      "settingsDelRange",
      "settingsDelTag",
      "settingsDownloadHosts",
      "settingsGet",
      "settingsGetBoot",
      "settingsGetDomain",
      "settingsGetHost",
      "settingsGetOption",
      "settingsGetRange",
      "settingsGetTag",
      "settingsGetTagList",
      "settingsSearchBoot",
      "settingsSearchDomain",
      "settingsSearchHost",
      "settingsSearchOption",
      "settingsSearchRange",
      "settingsSearchTag",
      "settingsSet",
      "settingsSetBoot",
      "settingsSetDomain",
      "settingsSetHost",
      "settingsSetOption",
      "settingsSetRange",
      "settingsSetTag",
      "settingsUploadHosts"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "leasesSearch",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddBoot",
            "settingsAddDomain",
            "settingsAddHost",
            "settingsAddOption",
            "settingsAddRange",
            "settingsAddTag",
            "settingsDelBoot",
            "settingsDelDomain",
            "settingsDelHost",
            "settingsDelOption",
            "settingsDelRange",
            "settingsDelTag",
            "settingsDownloadHosts",
            "settingsGet",
            "settingsGetBoot",
            "settingsGetDomain",
            "settingsGetHost",
            "settingsGetOption",
            "settingsGetRange",
            "settingsGetTag",
            "settingsGetTagList",
            "settingsSearchBoot",
            "settingsSearchDomain",
            "settingsSearchHost",
            "settingsSearchOption",
            "settingsSearchRange",
            "settingsSearchTag",
            "settingsSet",
            "settingsSetBoot",
            "settingsSetDomain",
            "settingsSetHost",
            "settingsSetOption",
            "settingsSetRange",
            "settingsSetTag",
            "settingsUploadHosts"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "firmware_manage",
    "description": "Firmware management - 26 available methods including: firmwareAudit, firmwareChangelog, firmwareCheck, firmwareConnection, firmwareGet...",
    "module": "firmware",
    "methods": [
      "firmwareAudit",
      "firmwareChangelog",
      "firmwareCheck",
      "firmwareCleanup",
      "firmwareConnection",
      "firmwareDetails",
      "firmwareGet",
      "firmwareGetOptions",
      "firmwareHealth",
      "firmwareInfo",
      "firmwareInstall",
      "firmwareLicense",
      "firmwareLock",
      "firmwareLog",
      "firmwarePoweroff",
      "firmwareReboot",
      "firmwareReinstall",
      "firmwareRemove",
      "firmwareResyncPlugins",
      "firmwareRunning",
      "firmwareSet",
      "firmwareStatus",
      "firmwareSyncPlugins",
      "firmwareUnlock",
      "firmwareUpdate",
      "firmwareUpgrade",
      "firmwareUpgradestatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "firmwareAudit",
            "firmwareChangelog",
            "firmwareCheck",
            "firmwareCleanup",
            "firmwareConnection",
            "firmwareDetails",
            "firmwareGet",
            "firmwareGetOptions",
            "firmwareHealth",
            "firmwareInfo",
            "firmwareInstall",
            "firmwareLicense",
            "firmwareLock",
            "firmwareLog",
            "firmwarePoweroff",
            "firmwareReboot",
            "firmwareReinstall",
            "firmwareRemove",
            "firmwareResyncPlugins",
            "firmwareRunning",
            "firmwareSet",
            "firmwareStatus",
            "firmwareSyncPlugins",
            "firmwareUnlock",
            "firmwareUpdate",
            "firmwareUpgrade",
            "firmwareUpgradestatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "ids_manage",
    "description": "Ids management - 40 available methods including: serviceDropAlertLog, serviceGetAlertInfo, serviceGetAlertLogs, serviceQueryAlerts, serviceReconfigure...",
    "module": "ids",
    "methods": [
      "serviceDropAlertLog",
      "serviceGetAlertInfo",
      "serviceGetAlertLogs",
      "serviceQueryAlerts",
      "serviceReconfigure",
      "serviceReloadRules",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceUpdateRules",
      "settingsAddPolicy",
      "settingsAddPolicyRule",
      "settingsAddUserRule",
      "settingsCheckPolicyRule",
      "settingsDelPolicy",
      "settingsDelPolicyRule",
      "settingsDelUserRule",
      "settingsGet",
      "settingsGetPolicy",
      "settingsGetPolicyRule",
      "settingsGetRuleInfo",
      "settingsGetRuleset",
      "settingsGetRulesetproperties",
      "settingsGetUserRule",
      "settingsListRuleMetadata",
      "settingsListRulesets",
      "settingsSearchInstalledRules",
      "settingsSearchPolicy",
      "settingsSearchPolicyRule",
      "settingsSearchUserRule",
      "settingsSet",
      "settingsSetPolicy",
      "settingsSetPolicyRule",
      "settingsSetRule",
      "settingsSetRuleset",
      "settingsSetRulesetproperties",
      "settingsSetUserRule",
      "settingsTogglePolicy",
      "settingsTogglePolicyRule",
      "settingsToggleRule",
      "settingsToggleRuleset",
      "settingsToggleUserRule"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceDropAlertLog",
            "serviceGetAlertInfo",
            "serviceGetAlertLogs",
            "serviceQueryAlerts",
            "serviceReconfigure",
            "serviceReloadRules",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "serviceUpdateRules",
            "settingsAddPolicy",
            "settingsAddPolicyRule",
            "settingsAddUserRule",
            "settingsCheckPolicyRule",
            "settingsDelPolicy",
            "settingsDelPolicyRule",
            "settingsDelUserRule",
            "settingsGet",
            "settingsGetPolicy",
            "settingsGetPolicyRule",
            "settingsGetRuleInfo",
            "settingsGetRuleset",
            "settingsGetRulesetproperties",
            "settingsGetUserRule",
            "settingsListRuleMetadata",
            "settingsListRulesets",
            "settingsSearchInstalledRules",
            "settingsSearchPolicy",
            "settingsSearchPolicyRule",
            "settingsSearchUserRule",
            "settingsSet",
            "settingsSetPolicy",
            "settingsSetPolicyRule",
            "settingsSetRule",
            "settingsSetRuleset",
            "settingsSetRulesetproperties",
            "settingsSetUserRule",
            "settingsTogglePolicy",
            "settingsTogglePolicyRule",
            "settingsToggleRule",
            "settingsToggleRuleset",
            "settingsToggleUserRule"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "ipsec_manage",
    "description": "Ipsec management - 80 available methods including: connectionsAddChild, connectionsAddConnection, connectionsAddLocal, connectionsAddRemote, connectionsConnectionExists...",
    "module": "ipsec",
    "methods": [
      "connectionsAddChild",
      "connectionsAddConnection",
      "connectionsAddLocal",
      "connectionsAddRemote",
      "connectionsConnectionExists",
      "connectionsDelChild",
      "connectionsDelConnection",
      "connectionsDelLocal",
      "connectionsDelRemote",
      "connectionsGet",
      "connectionsGetChild",
      "connectionsGetConnection",
      "connectionsGetLocal",
      "connectionsGetRemote",
      "connectionsIsEnabled",
      "connectionsSearchChild",
      "connectionsSearchConnection",
      "connectionsSearchLocal",
      "connectionsSearchRemote",
      "connectionsSet",
      "connectionsSetChild",
      "connectionsSetConnection",
      "connectionsSetLocal",
      "connectionsSetRemote",
      "connectionsSwanctl",
      "connectionsToggle",
      "connectionsToggleChild",
      "connectionsToggleConnection",
      "connectionsToggleLocal",
      "connectionsToggleRemote",
      "keyPairsAddItem",
      "keyPairsDelItem",
      "keyPairsGenKeyPair",
      "keyPairsGet",
      "keyPairsGetItem",
      "keyPairsSearchItem",
      "keyPairsSet",
      "keyPairsSetItem",
      "leasesPools",
      "leasesSearch",
      "legacySubsystemApplyConfig",
      "legacySubsystemStatus",
      "manualSpdAdd",
      "manualSpdDel",
      "manualSpdGet",
      "manualSpdSearch",
      "manualSpdSet",
      "manualSpdToggle",
      "poolsAdd",
      "poolsDel",
      "poolsGet",
      "poolsSearch",
      "poolsSet",
      "poolsToggle",
      "preSharedKeysAddItem",
      "preSharedKeysDelItem",
      "preSharedKeysGet",
      "preSharedKeysGetItem",
      "preSharedKeysSearchItem",
      "preSharedKeysSet",
      "preSharedKeysSetItem",
      "sadDelete",
      "sadSearch",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "sessionsConnect",
      "sessionsDisconnect",
      "sessionsSearchPhase1",
      "sessionsSearchPhase2",
      "settingsGet",
      "settingsSet",
      "spdDelete",
      "spdSearch",
      "tunnelDelPhase1",
      "tunnelDelPhase2",
      "tunnelSearchPhase1",
      "tunnelSearchPhase2",
      "tunnelToggle",
      "tunnelTogglePhase1",
      "tunnelTogglePhase2",
      "vtiAdd",
      "vtiDel",
      "vtiGet",
      "vtiSearch",
      "vtiSet",
      "vtiToggle"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "connectionsAddChild",
            "connectionsAddConnection",
            "connectionsAddLocal",
            "connectionsAddRemote",
            "connectionsConnectionExists",
            "connectionsDelChild",
            "connectionsDelConnection",
            "connectionsDelLocal",
            "connectionsDelRemote",
            "connectionsGet",
            "connectionsGetChild",
            "connectionsGetConnection",
            "connectionsGetLocal",
            "connectionsGetRemote",
            "connectionsIsEnabled",
            "connectionsSearchChild",
            "connectionsSearchConnection",
            "connectionsSearchLocal",
            "connectionsSearchRemote",
            "connectionsSet",
            "connectionsSetChild",
            "connectionsSetConnection",
            "connectionsSetLocal",
            "connectionsSetRemote",
            "connectionsSwanctl",
            "connectionsToggle",
            "connectionsToggleChild",
            "connectionsToggleConnection",
            "connectionsToggleLocal",
            "connectionsToggleRemote",
            "keyPairsAddItem",
            "keyPairsDelItem",
            "keyPairsGenKeyPair",
            "keyPairsGet",
            "keyPairsGetItem",
            "keyPairsSearchItem",
            "keyPairsSet",
            "keyPairsSetItem",
            "leasesPools",
            "leasesSearch",
            "legacySubsystemApplyConfig",
            "legacySubsystemStatus",
            "manualSpdAdd",
            "manualSpdDel",
            "manualSpdGet",
            "manualSpdSearch",
            "manualSpdSet",
            "manualSpdToggle",
            "poolsAdd",
            "poolsDel",
            "poolsGet",
            "poolsSearch",
            "poolsSet",
            "poolsToggle",
            "preSharedKeysAddItem",
            "preSharedKeysDelItem",
            "preSharedKeysGet",
            "preSharedKeysGetItem",
            "preSharedKeysSearchItem",
            "preSharedKeysSet",
            "preSharedKeysSetItem",
            "sadDelete",
            "sadSearch",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "sessionsConnect",
            "sessionsDisconnect",
            "sessionsSearchPhase1",
            "sessionsSearchPhase2",
            "settingsGet",
            "settingsSet",
            "spdDelete",
            "spdSearch",
            "tunnelDelPhase1",
            "tunnelDelPhase2",
            "tunnelSearchPhase1",
            "tunnelSearchPhase2",
            "tunnelToggle",
            "tunnelTogglePhase1",
            "tunnelTogglePhase2",
            "vtiAdd",
            "vtiDel",
            "vtiGet",
            "vtiSearch",
            "vtiSet",
            "vtiToggle"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "kea_manage",
    "description": "Kea management - 24 available methods including: ctrlAgentGet, ctrlAgentSet, dhcpv4AddPeer, dhcpv4AddReservation, dhcpv4AddSubnet...",
    "module": "kea",
    "methods": [
      "ctrlAgentGet",
      "ctrlAgentSet",
      "ddnsGet",
      "dhcpv4AddOption",
      "dhcpv4AddPeer",
      "dhcpv4AddReservation",
      "dhcpv4AddSubnet",
      "dhcpv4DelOption",
      "dhcpv4DelPeer",
      "dhcpv4DelReservation",
      "dhcpv4DelSubnet",
      "dhcpv4DownloadReservations",
      "dhcpv4Get",
      "dhcpv4GetOption",
      "dhcpv4GetPeer",
      "dhcpv4GetReservation",
      "dhcpv4GetSubnet",
      "dhcpv4SearchOption",
      "dhcpv4SearchPeer",
      "dhcpv4SearchReservation",
      "dhcpv4SearchSubnet",
      "dhcpv4Set",
      "dhcpv4SetOption",
      "dhcpv4SetPeer",
      "dhcpv4SetReservation",
      "dhcpv4SetSubnet",
      "dhcpv4UploadReservations",
      "dhcpv6AddOption",
      "dhcpv6AddPdPool",
      "dhcpv6AddPeer",
      "dhcpv6AddReservation",
      "dhcpv6AddSubnet",
      "dhcpv6DelOption",
      "dhcpv6DelPdPool",
      "dhcpv6DelPeer",
      "dhcpv6DelReservation",
      "dhcpv6DelSubnet",
      "dhcpv6DownloadReservations",
      "dhcpv6Get",
      "dhcpv6GetOption",
      "dhcpv6GetPdPool",
      "dhcpv6GetPeer",
      "dhcpv6GetReservation",
      "dhcpv6GetSubnet",
      "dhcpv6SearchOption",
      "dhcpv6SearchPdPool",
      "dhcpv6SearchPeer",
      "dhcpv6SearchReservation",
      "dhcpv6SearchSubnet",
      "dhcpv6SetOption",
      "dhcpv6SetPdPool",
      "dhcpv6SetPeer",
      "dhcpv6SetReservation",
      "dhcpv6SetSubnet",
      "dhcpv6UploadReservations",
      "leases4DelLease",
      "leases4Search",
      "leases6DelLease",
      "leases6Search",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "ctrlAgentGet",
            "ctrlAgentSet",
            "ddnsGet",
            "dhcpv4AddOption",
            "dhcpv4AddPeer",
            "dhcpv4AddReservation",
            "dhcpv4AddSubnet",
            "dhcpv4DelOption",
            "dhcpv4DelPeer",
            "dhcpv4DelReservation",
            "dhcpv4DelSubnet",
            "dhcpv4DownloadReservations",
            "dhcpv4Get",
            "dhcpv4GetOption",
            "dhcpv4GetPeer",
            "dhcpv4GetReservation",
            "dhcpv4GetSubnet",
            "dhcpv4SearchOption",
            "dhcpv4SearchPeer",
            "dhcpv4SearchReservation",
            "dhcpv4SearchSubnet",
            "dhcpv4Set",
            "dhcpv4SetOption",
            "dhcpv4SetPeer",
            "dhcpv4SetReservation",
            "dhcpv4SetSubnet",
            "dhcpv4UploadReservations",
            "dhcpv6AddOption",
            "dhcpv6AddPdPool",
            "dhcpv6AddPeer",
            "dhcpv6AddReservation",
            "dhcpv6AddSubnet",
            "dhcpv6DelOption",
            "dhcpv6DelPdPool",
            "dhcpv6DelPeer",
            "dhcpv6DelReservation",
            "dhcpv6DelSubnet",
            "dhcpv6DownloadReservations",
            "dhcpv6Get",
            "dhcpv6GetOption",
            "dhcpv6GetPdPool",
            "dhcpv6GetPeer",
            "dhcpv6GetReservation",
            "dhcpv6GetSubnet",
            "dhcpv6SearchOption",
            "dhcpv6SearchPdPool",
            "dhcpv6SearchPeer",
            "dhcpv6SearchReservation",
            "dhcpv6SearchSubnet",
            "dhcpv6SetOption",
            "dhcpv6SetPdPool",
            "dhcpv6SetPeer",
            "dhcpv6SetReservation",
            "dhcpv6SetSubnet",
            "dhcpv6UploadReservations",
            "leases4DelLease",
            "leases4Search",
            "leases6DelLease",
            "leases6Search",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "monit_manage",
    "description": "Monit management - 25 available methods including: serviceCheck, serviceReconfigure, serviceRestart, serviceStart, serviceStatus...",
    "module": "monit",
    "methods": [
      "serviceCheck",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddAlert",
      "settingsAddService",
      "settingsAddTest",
      "settingsDelAlert",
      "settingsDelService",
      "settingsDelTest",
      "settingsDirty",
      "settingsGet",
      "settingsGetAlert",
      "settingsGetGeneral",
      "settingsGetService",
      "settingsGetTest",
      "settingsSearchAlert",
      "settingsSearchService",
      "settingsSearchTest",
      "settingsSet",
      "settingsSetAlert",
      "settingsSetService",
      "settingsSetTest",
      "settingsToggleAlert",
      "settingsToggleService",
      "statusGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceCheck",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddAlert",
            "settingsAddService",
            "settingsAddTest",
            "settingsDelAlert",
            "settingsDelService",
            "settingsDelTest",
            "settingsDirty",
            "settingsGet",
            "settingsGetAlert",
            "settingsGetGeneral",
            "settingsGetService",
            "settingsGetTest",
            "settingsSearchAlert",
            "settingsSearchService",
            "settingsSearchTest",
            "settingsSet",
            "settingsSetAlert",
            "settingsSetService",
            "settingsSetTest",
            "settingsToggleAlert",
            "settingsToggleService",
            "statusGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "openvpn_manage",
    "description": "Openvpn management - 28 available methods including: clientOverwritesAdd, clientOverwritesDel, clientOverwritesGet, clientOverwritesSet, clientOverwritesToggle...",
    "module": "openvpn",
    "methods": [
      "clientOverwritesAdd",
      "clientOverwritesDel",
      "clientOverwritesGet",
      "clientOverwritesSearch",
      "clientOverwritesSet",
      "clientOverwritesToggle",
      "exportAccounts",
      "exportDownload",
      "exportProviders",
      "exportStorePresets",
      "exportTemplates",
      "exportValidatePresets",
      "instancesAdd",
      "instancesAddStaticKey",
      "instancesDel",
      "instancesDelStaticKey",
      "instancesGenKey",
      "instancesGet",
      "instancesGetStaticKey",
      "instancesSearch",
      "instancesSearchStaticKey",
      "instancesSet",
      "instancesSetStaticKey",
      "instancesToggle",
      "serviceKillSession",
      "serviceReconfigure",
      "serviceRestartService",
      "serviceSearchRoutes",
      "serviceSearchSessions",
      "serviceStartService",
      "serviceStopService"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "clientOverwritesAdd",
            "clientOverwritesDel",
            "clientOverwritesGet",
            "clientOverwritesSearch",
            "clientOverwritesSet",
            "clientOverwritesToggle",
            "exportAccounts",
            "exportDownload",
            "exportProviders",
            "exportStorePresets",
            "exportTemplates",
            "exportValidatePresets",
            "instancesAdd",
            "instancesAddStaticKey",
            "instancesDel",
            "instancesDelStaticKey",
            "instancesGenKey",
            "instancesGet",
            "instancesGetStaticKey",
            "instancesSearch",
            "instancesSearchStaticKey",
            "instancesSet",
            "instancesSetStaticKey",
            "instancesToggle",
            "serviceKillSession",
            "serviceReconfigure",
            "serviceRestartService",
            "serviceSearchRoutes",
            "serviceSearchSessions",
            "serviceStartService",
            "serviceStopService"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "routes_manage",
    "description": "Routes management - 9 available methods including: gatewayStatus, routesAddroute, routesDelroute, routesGet, routesGetroute...",
    "module": "routes",
    "methods": [
      "gatewayStatus",
      "routesAddroute",
      "routesDelroute",
      "routesGet",
      "routesGetroute",
      "routesReconfigure",
      "routesSearchroute",
      "routesSet",
      "routesSetroute",
      "routesToggleroute"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "gatewayStatus",
            "routesAddroute",
            "routesDelroute",
            "routesGet",
            "routesGetroute",
            "routesReconfigure",
            "routesSearchroute",
            "routesSet",
            "routesSetroute",
            "routesToggleroute"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "routing_manage",
    "description": "Routing management - 9 available methods including: settingsAddGateway, settingsDelGateway, settingsGet, settingsGetGateway, settingsReconfigure...",
    "module": "routing",
    "methods": [
      "groupSettingsAdd",
      "groupSettingsDel",
      "groupSettingsGet",
      "groupSettingsReconfigure",
      "groupSettingsSearch",
      "groupSettingsSet",
      "settingsAddGateway",
      "settingsDelGateway",
      "settingsGet",
      "settingsGetGateway",
      "settingsReconfigure",
      "settingsSearchGateway",
      "settingsSet",
      "settingsSetGateway",
      "settingsToggleGateway"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "groupSettingsAdd",
            "groupSettingsDel",
            "groupSettingsGet",
            "groupSettingsReconfigure",
            "groupSettingsSearch",
            "groupSettingsSet",
            "settingsAddGateway",
            "settingsDelGateway",
            "settingsGet",
            "settingsGetGateway",
            "settingsReconfigure",
            "settingsSearchGateway",
            "settingsSet",
            "settingsSetGateway",
            "settingsToggleGateway"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "syslog_manage",
    "description": "Syslog management - 14 available methods including: serviceReconfigure, serviceReset, serviceRestart, serviceStart, serviceStats...",
    "module": "syslog",
    "methods": [
      "serviceReconfigure",
      "serviceReset",
      "serviceRestart",
      "serviceStart",
      "serviceStats",
      "serviceStatus",
      "serviceStop",
      "settingsAddDestination",
      "settingsDelDestination",
      "settingsGet",
      "settingsGetDestination",
      "settingsSearchDestinations",
      "settingsSet",
      "settingsSetDestination",
      "settingsToggleDestination"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceReset",
            "serviceRestart",
            "serviceStart",
            "serviceStats",
            "serviceStatus",
            "serviceStop",
            "settingsAddDestination",
            "settingsDelDestination",
            "settingsGet",
            "settingsGetDestination",
            "settingsSearchDestinations",
            "settingsSet",
            "settingsSetDestination",
            "settingsToggleDestination"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "trafficshaper_manage",
    "description": "Trafficshaper management - 20 available methods including: serviceFlushreload, serviceReconfigure, serviceStatistics, settingsAddPipe, settingsAddQueue...",
    "module": "trafficshaper",
    "methods": [
      "serviceFlushreload",
      "serviceReconfigure",
      "serviceStatistics",
      "settingsAddPipe",
      "settingsAddQueue",
      "settingsAddRule",
      "settingsDelPipe",
      "settingsDelQueue",
      "settingsDelRule",
      "settingsDownloadPipes",
      "settingsDownloadQueues",
      "settingsGet",
      "settingsGetPipe",
      "settingsGetQueue",
      "settingsGetRule",
      "settingsSearchPipes",
      "settingsSearchQueues",
      "settingsSearchRules",
      "settingsSet",
      "settingsSetPipe",
      "settingsSetQueue",
      "settingsSetRule",
      "settingsTogglePipe",
      "settingsToggleQueue",
      "settingsToggleRule",
      "settingsUploadPipes",
      "settingsUploadQueues"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceFlushreload",
            "serviceReconfigure",
            "serviceStatistics",
            "settingsAddPipe",
            "settingsAddQueue",
            "settingsAddRule",
            "settingsDelPipe",
            "settingsDelQueue",
            "settingsDelRule",
            "settingsDownloadPipes",
            "settingsDownloadQueues",
            "settingsGet",
            "settingsGetPipe",
            "settingsGetQueue",
            "settingsGetRule",
            "settingsSearchPipes",
            "settingsSearchQueues",
            "settingsSearchRules",
            "settingsSet",
            "settingsSetPipe",
            "settingsSetQueue",
            "settingsSetRule",
            "settingsTogglePipe",
            "settingsToggleQueue",
            "settingsToggleRule",
            "settingsUploadPipes",
            "settingsUploadQueues"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "trust_manage",
    "description": "Trust management - 25 available methods including: caCaInfo, caCaList, caDel, caGenerateFile, caGet...",
    "module": "trust",
    "methods": [
      "caAdd",
      "caCaInfo",
      "caCaList",
      "caDel",
      "caGenerateFile",
      "caGet",
      "caRawDump",
      "caSearch",
      "caSet",
      "certAdd",
      "certCaInfo",
      "certCaList",
      "certDel",
      "certGenerateFile",
      "certGet",
      "certRawDump",
      "certSearch",
      "certSet",
      "certUserList",
      "crlDel",
      "crlGet",
      "crlGetOcspInfoData",
      "crlRawDump",
      "crlSearch",
      "crlSet",
      "settingsGet",
      "settingsReconfigure",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "caAdd",
            "caCaInfo",
            "caCaList",
            "caDel",
            "caGenerateFile",
            "caGet",
            "caRawDump",
            "caSearch",
            "caSet",
            "certAdd",
            "certCaInfo",
            "certCaList",
            "certDel",
            "certGenerateFile",
            "certGet",
            "certRawDump",
            "certSearch",
            "certSet",
            "certUserList",
            "crlDel",
            "crlGet",
            "crlGetOcspInfoData",
            "crlRawDump",
            "crlSearch",
            "crlSet",
            "settingsGet",
            "settingsReconfigure",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "unbound_manage",
    "description": "Unbound management - 42 available methods including: diagnosticsDumpcache, diagnosticsDumpinfra, diagnosticsListinsecure, diagnosticsListlocaldata, diagnosticsListlocalzones...",
    "module": "unbound",
    "methods": [
      "diagnosticsDumpcache",
      "diagnosticsDumpinfra",
      "diagnosticsListinsecure",
      "diagnosticsListlocaldata",
      "diagnosticsListlocalzones",
      "diagnosticsStats",
      "diagnosticsTestBlocklist",
      "overviewGetPolicies",
      "overviewIsBlockListEnabled",
      "overviewIsEnabled",
      "overviewReset",
      "overviewRolling",
      "overviewSearchQueries",
      "overviewTotals",
      "serviceDnsbl",
      "serviceReconfigure",
      "serviceReconfigureGeneral",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddAcl",
      "settingsAddDnsbl",
      "settingsAddForward",
      "settingsAddHostAlias",
      "settingsAddHostOverride",
      "settingsDelAcl",
      "settingsDelDnsbl",
      "settingsDelForward",
      "settingsDelHostAlias",
      "settingsDelHostOverride",
      "settingsGet",
      "settingsGetAcl",
      "settingsGetDnsbl",
      "settingsGetForward",
      "settingsGetHostAlias",
      "settingsGetHostOverride",
      "settingsGetNameservers",
      "settingsSearchAcl",
      "settingsSearchDnsbl",
      "settingsSearchForward",
      "settingsSearchHostAlias",
      "settingsSearchHostOverride",
      "settingsSet",
      "settingsSetAcl",
      "settingsSetDnsbl",
      "settingsSetForward",
      "settingsSetHostAlias",
      "settingsSetHostOverride",
      "settingsToggleAcl",
      "settingsToggleDnsbl",
      "settingsToggleForward",
      "settingsToggleHostAlias",
      "settingsToggleHostOverride",
      "settingsUpdateBlocklist"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "diagnosticsDumpcache",
            "diagnosticsDumpinfra",
            "diagnosticsListinsecure",
            "diagnosticsListlocaldata",
            "diagnosticsListlocalzones",
            "diagnosticsStats",
            "diagnosticsTestBlocklist",
            "overviewGetPolicies",
            "overviewIsBlockListEnabled",
            "overviewIsEnabled",
            "overviewReset",
            "overviewRolling",
            "overviewSearchQueries",
            "overviewTotals",
            "serviceDnsbl",
            "serviceReconfigure",
            "serviceReconfigureGeneral",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddAcl",
            "settingsAddDnsbl",
            "settingsAddForward",
            "settingsAddHostAlias",
            "settingsAddHostOverride",
            "settingsDelAcl",
            "settingsDelDnsbl",
            "settingsDelForward",
            "settingsDelHostAlias",
            "settingsDelHostOverride",
            "settingsGet",
            "settingsGetAcl",
            "settingsGetDnsbl",
            "settingsGetForward",
            "settingsGetHostAlias",
            "settingsGetHostOverride",
            "settingsGetNameservers",
            "settingsSearchAcl",
            "settingsSearchDnsbl",
            "settingsSearchForward",
            "settingsSearchHostAlias",
            "settingsSearchHostOverride",
            "settingsSet",
            "settingsSetAcl",
            "settingsSetDnsbl",
            "settingsSetForward",
            "settingsSetHostAlias",
            "settingsSetHostOverride",
            "settingsToggleAcl",
            "settingsToggleDnsbl",
            "settingsToggleForward",
            "settingsToggleHostAlias",
            "settingsToggleHostOverride",
            "settingsUpdateBlocklist"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "wireguard_manage",
    "description": "Wireguard management - 28 methods. WRITE-BODY SCHEMA (live-validated eu-2/homelab 2026-06-15): client add/set bodies MUST wrap params.item = {client:{...}}; server add/set MUST wrap params.item = {server:{...}}. Sending the fields FLAT (item.{...}, unwrapped) returns {result:failed} as a silent no-op — the single most common WG write mistake. Multi-value fields (tunneladdress, servers, peers, dns) are comma-separated STRINGS in the write body (the GET echoes them back as selected-maps); 'servers' on a client = the server UUID(s), 'peers' on a server = client UUID(s). psk:'' is safe to send on a no-PSK peer (no wipe). Client fields: enabled, name, pubkey, psk, tunneladdress, serveraddress, serverport, endpoint, keepalive, servers. Server fields: enabled, name, instance, pubkey, privkey, port, mtu, dns, tunneladdress, disableroutes, gateway, peers. Fetch the empty editable template via clientGetClient / serverGetServer with NO uuid (fork makes uuid optional). Writes only STAGE config — apply with serviceReconfigure (runs wg syncconf: non-disruptive delta, won't bounce live peers). Worked example: clientAddClient params.item={client:{enabled:'1',name:'peer1',pubkey:'<b64>',psk:'',tunneladdress:'10.10.10.5/32',serveraddress:'',serverport:'',keepalive:'25',servers:'<server-uuid>'}}.",
    "module": "wireguard",
    "methods": [
      "clientAddClient",
      "clientAddClientBuilder",
      "clientDelClient",
      "clientGet",
      "clientGetClient",
      "clientGetClientBuilder",
      "clientGetServerInfo",
      "clientListServers",
      "clientPsk",
      "clientSearchClient",
      "clientSet",
      "clientSetClient",
      "clientToggleClient",
      "generalGet",
      "generalSet",
      "serverAddServer",
      "serverDelServer",
      "serverGet",
      "serverGetServer",
      "serverKeyPair",
      "serverSearchServer",
      "serverSet",
      "serverSetServer",
      "serverToggleServer",
      "serviceReconfigure",
      "serviceRestart",
      "serviceShow",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "clientAddClient",
            "clientAddClientBuilder",
            "clientDelClient",
            "clientGet",
            "clientGetClient",
            "clientGetClientBuilder",
            "clientGetServerInfo",
            "clientListServers",
            "clientPsk",
            "clientSearchClient",
            "clientSet",
            "clientSetClient",
            "clientToggleClient",
            "generalGet",
            "generalSet",
            "serverAddServer",
            "serverDelServer",
            "serverGet",
            "serverGetServer",
            "serverKeyPair",
            "serverSearchServer",
            "serverSet",
            "serverSetServer",
            "serverToggleServer",
            "serviceReconfigure",
            "serviceRestart",
            "serviceShow",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_acmeclient_manage",
    "description": "Plugin acmeclient management - 48 available methods including: accountsAdd, accountsDel, accountsGet, accountsRegister, accountsSet...",
    "module": "plugins",
    "submodule": "acmeclient",
    "methods": [
      "accountsAdd",
      "accountsDel",
      "accountsGet",
      "accountsRegister",
      "accountsSet",
      "accountsToggle",
      "accountsUpdate",
      "actionsAdd",
      "actionsDel",
      "actionsGet",
      "actionsSet",
      "actionsSftpGetIdentity",
      "actionsSftpTestConnection",
      "actionsSshGetIdentity",
      "actionsSshTestConnection",
      "actionsToggle",
      "actionsUpdate",
      "certificatesAdd",
      "certificatesAutomation",
      "certificatesDel",
      "certificatesGet",
      "certificatesImport",
      "certificatesRemovekey",
      "certificatesRevoke",
      "certificatesSet",
      "certificatesSign",
      "certificatesToggle",
      "certificatesUpdate",
      "serviceConfigtest",
      "serviceReconfigure",
      "serviceReset",
      "serviceRestart",
      "serviceSignallcerts",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsFetchCronIntegration",
      "settingsFetchHAProxyIntegration",
      "settingsGet",
      "settingsGetBindPluginStatus",
      "settingsGetGcloudPluginStatus",
      "settingsSet",
      "validationsAdd",
      "validationsDel",
      "validationsGet",
      "validationsSet",
      "validationsToggle",
      "validationsUpdate"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "accountsAdd",
            "accountsDel",
            "accountsGet",
            "accountsRegister",
            "accountsSet",
            "accountsToggle",
            "accountsUpdate",
            "actionsAdd",
            "actionsDel",
            "actionsGet",
            "actionsSet",
            "actionsSftpGetIdentity",
            "actionsSftpTestConnection",
            "actionsSshGetIdentity",
            "actionsSshTestConnection",
            "actionsToggle",
            "actionsUpdate",
            "certificatesAdd",
            "certificatesAutomation",
            "certificatesDel",
            "certificatesGet",
            "certificatesImport",
            "certificatesRemovekey",
            "certificatesRevoke",
            "certificatesSet",
            "certificatesSign",
            "certificatesToggle",
            "certificatesUpdate",
            "serviceConfigtest",
            "serviceReconfigure",
            "serviceReset",
            "serviceRestart",
            "serviceSignallcerts",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsFetchCronIntegration",
            "settingsFetchHAProxyIntegration",
            "settingsGet",
            "settingsGetBindPluginStatus",
            "settingsGetGcloudPluginStatus",
            "settingsSet",
            "validationsAdd",
            "validationsDel",
            "validationsGet",
            "validationsSet",
            "validationsToggle",
            "validationsUpdate"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_apcupsd_manage",
    "description": "Plugin apcupsd management - 8 available methods including: serviceGetUpsStatus, serviceReconfigure, serviceRestart, serviceStart, serviceStatus...",
    "module": "plugins",
    "submodule": "apcupsd",
    "methods": [
      "serviceGetUpsStatus",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceGetUpsStatus",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_bind_manage",
    "description": "Plugin bind management - 36 available methods including: aclAddAcl, aclDelAcl, aclGet, aclGetAcl, aclSet...",
    "module": "plugins",
    "submodule": "bind",
    "methods": [
      "aclAddAcl",
      "aclDelAcl",
      "aclGet",
      "aclGetAcl",
      "aclSet",
      "aclSetAcl",
      "aclToggleAcl",
      "dnsblGet",
      "dnsblSet",
      "domainAddPrimaryDomain",
      "domainAddSecondaryDomain",
      "domainDelDomain",
      "domainGet",
      "domainGetDomain",
      "domainSearchMasterDomain",
      "domainSearchSlaveDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalGet",
      "generalSet",
      "generalZoneshow",
      "generalZonetest",
      "recordAddRecord",
      "recordDelRecord",
      "recordGet",
      "recordGetRecord",
      "recordSet",
      "recordSetRecord",
      "recordToggleRecord",
      "serviceDnsbl",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "aclAddAcl",
            "aclDelAcl",
            "aclGet",
            "aclGetAcl",
            "aclSet",
            "aclSetAcl",
            "aclToggleAcl",
            "dnsblGet",
            "dnsblSet",
            "domainAddPrimaryDomain",
            "domainAddSecondaryDomain",
            "domainDelDomain",
            "domainGet",
            "domainGetDomain",
            "domainSearchMasterDomain",
            "domainSearchSlaveDomain",
            "domainSet",
            "domainSetDomain",
            "domainToggleDomain",
            "generalGet",
            "generalSet",
            "generalZoneshow",
            "generalZonetest",
            "recordAddRecord",
            "recordDelRecord",
            "recordGet",
            "recordGetRecord",
            "recordSet",
            "recordSetRecord",
            "recordToggleRecord",
            "serviceDnsbl",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_caddy_manage",
    "description": "Plugin caddy management - 52 available methods including: diagnosticsCaddyfile, diagnosticsConfig, diagnosticsGet, diagnosticsSet, generalGet...",
    "module": "plugins",
    "submodule": "caddy",
    "methods": [
      "diagnosticsCaddyfile",
      "diagnosticsConfig",
      "diagnosticsGet",
      "diagnosticsSet",
      "generalGet",
      "generalSet",
      "reverseProxyAddAccessList",
      "reverseProxyAddBasicAuth",
      "reverseProxyAddHandle",
      "reverseProxyAddHeader",
      "reverseProxyAddLayer4",
      "reverseProxyAddLayer4Openvpn",
      "reverseProxyAddReverseProxy",
      "reverseProxyAddSubdomain",
      "reverseProxyDelAccessList",
      "reverseProxyDelBasicAuth",
      "reverseProxyDelHandle",
      "reverseProxyDelHeader",
      "reverseProxyDelLayer4",
      "reverseProxyDelLayer4Openvpn",
      "reverseProxyDelReverseProxy",
      "reverseProxyDelSubdomain",
      "reverseProxyGet",
      "reverseProxyGetAccessList",
      "reverseProxyGetAllReverseDomains",
      "reverseProxyGetBasicAuth",
      "reverseProxyGetHandle",
      "reverseProxyGetHeader",
      "reverseProxyGetLayer4",
      "reverseProxyGetLayer4Openvpn",
      "reverseProxyGetReverseProxy",
      "reverseProxyGetSubdomain",
      "reverseProxySet",
      "reverseProxySetAccessList",
      "reverseProxySetBasicAuth",
      "reverseProxySetHandle",
      "reverseProxySetHeader",
      "reverseProxySetLayer4",
      "reverseProxySetLayer4Openvpn",
      "reverseProxySetReverseProxy",
      "reverseProxySetSubdomain",
      "reverseProxyToggleHandle",
      "reverseProxyToggleLayer4",
      "reverseProxyToggleLayer4Openvpn",
      "reverseProxyToggleReverseProxy",
      "reverseProxyToggleSubdomain",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceValidate"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "diagnosticsCaddyfile",
            "diagnosticsConfig",
            "diagnosticsGet",
            "diagnosticsSet",
            "generalGet",
            "generalSet",
            "reverseProxyAddAccessList",
            "reverseProxyAddBasicAuth",
            "reverseProxyAddHandle",
            "reverseProxyAddHeader",
            "reverseProxyAddLayer4",
            "reverseProxyAddLayer4Openvpn",
            "reverseProxyAddReverseProxy",
            "reverseProxyAddSubdomain",
            "reverseProxyDelAccessList",
            "reverseProxyDelBasicAuth",
            "reverseProxyDelHandle",
            "reverseProxyDelHeader",
            "reverseProxyDelLayer4",
            "reverseProxyDelLayer4Openvpn",
            "reverseProxyDelReverseProxy",
            "reverseProxyDelSubdomain",
            "reverseProxyGet",
            "reverseProxyGetAccessList",
            "reverseProxyGetAllReverseDomains",
            "reverseProxyGetBasicAuth",
            "reverseProxyGetHandle",
            "reverseProxyGetHeader",
            "reverseProxyGetLayer4",
            "reverseProxyGetLayer4Openvpn",
            "reverseProxyGetReverseProxy",
            "reverseProxyGetSubdomain",
            "reverseProxySet",
            "reverseProxySetAccessList",
            "reverseProxySetBasicAuth",
            "reverseProxySetHandle",
            "reverseProxySetHeader",
            "reverseProxySetLayer4",
            "reverseProxySetLayer4Openvpn",
            "reverseProxySetReverseProxy",
            "reverseProxySetSubdomain",
            "reverseProxyToggleHandle",
            "reverseProxyToggleLayer4",
            "reverseProxyToggleLayer4Openvpn",
            "reverseProxyToggleReverseProxy",
            "reverseProxyToggleSubdomain",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "serviceValidate"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_chrony_manage",
    "description": "Plugin chrony management - 11 available methods including: generalGet, generalSet, serviceChronyauthdata, serviceChronysources, serviceChronysourcestats...",
    "module": "plugins",
    "submodule": "chrony",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceChronyauthdata",
      "serviceChronysources",
      "serviceChronysourcestats",
      "serviceChronytracking",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceChronyauthdata",
            "serviceChronysources",
            "serviceChronysourcestats",
            "serviceChronytracking",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_cicap_manage",
    "description": "Plugin cicap management - 10 available methods including: antivirusGet, antivirusSet, generalGet, generalSet, serviceCheckclamav...",
    "module": "plugins",
    "submodule": "cicap",
    "methods": [
      "antivirusGet",
      "antivirusSet",
      "generalGet",
      "generalSet",
      "serviceCheckclamav",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "antivirusGet",
            "antivirusSet",
            "generalGet",
            "generalSet",
            "serviceCheckclamav",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_clamav_manage",
    "description": "Plugin clamav management - 16 available methods including: generalGet, generalSet, serviceFreshclam, serviceReconfigure, serviceRestart...",
    "module": "plugins",
    "submodule": "clamav",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceFreshclam",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceVersion",
      "urlAddUrl",
      "urlDelUrl",
      "urlGet",
      "urlGetUrl",
      "urlSet",
      "urlSetUrl",
      "urlToggleUrl"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceFreshclam",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "serviceVersion",
            "urlAddUrl",
            "urlDelUrl",
            "urlGet",
            "urlGetUrl",
            "urlSet",
            "urlSetUrl",
            "urlToggleUrl"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_collectd_manage",
    "description": "Plugin collectd management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "collectd",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_crowdsec_manage",
    "description": "Plugin crowdsec management - 12 available methods including: alertsGet, bouncersGet, decisionsDelete, decisionsGet, generalGet...",
    "module": "plugins",
    "submodule": "crowdsec",
    "methods": [
      "alertsGet",
      "bouncersGet",
      "decisionsDelete",
      "decisionsGet",
      "generalGet",
      "generalSet",
      "hubGet",
      "machinesGet",
      "serviceDebug",
      "serviceReload",
      "serviceStatus",
      "versionGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "alertsGet",
            "bouncersGet",
            "decisionsDelete",
            "decisionsGet",
            "generalGet",
            "generalSet",
            "hubGet",
            "machinesGet",
            "serviceDebug",
            "serviceReload",
            "serviceStatus",
            "versionGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dechw_manage",
    "description": "Plugin dechw management - 1 available methods including: infoPowerStatus...",
    "module": "plugins",
    "submodule": "dechw",
    "methods": [
      "infoPowerStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "infoPowerStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_diagnostics_manage",
    "description": "Plugin diagnostics management - 1 available methods including: proofpointEtStatus...",
    "module": "plugins",
    "submodule": "diagnostics",
    "methods": [
      "proofpointEtStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "proofpointEtStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dmidecode_manage",
    "description": "Plugin dmidecode management - 1 available methods including: serviceGet...",
    "module": "plugins",
    "submodule": "dmidecode",
    "methods": [
      "serviceGet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceGet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dnscryptproxy_manage",
    "description": "Plugin dnscryptproxy management - 38 available methods including: cloakAddCloak, cloakDelCloak, cloakGet, cloakGetCloak, cloakSet...",
    "module": "plugins",
    "submodule": "dnscryptproxy",
    "methods": [
      "cloakAddCloak",
      "cloakDelCloak",
      "cloakGet",
      "cloakGetCloak",
      "cloakSet",
      "cloakSetCloak",
      "cloakToggleCloak",
      "dnsblGet",
      "dnsblSet",
      "forwardAddForward",
      "forwardDelForward",
      "forwardGet",
      "forwardGetForward",
      "forwardSet",
      "forwardSetForward",
      "forwardToggleForward",
      "generalGet",
      "generalSet",
      "serverAddServer",
      "serverDelServer",
      "serverGet",
      "serverGetServer",
      "serverSet",
      "serverSetServer",
      "serverToggleServer",
      "serviceDnsbl",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "whitelistAddWhitelist",
      "whitelistDelWhitelist",
      "whitelistGet",
      "whitelistGetWhitelist",
      "whitelistSet",
      "whitelistSetWhitelist",
      "whitelistToggleWhitelist"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "cloakAddCloak",
            "cloakDelCloak",
            "cloakGet",
            "cloakGetCloak",
            "cloakSet",
            "cloakSetCloak",
            "cloakToggleCloak",
            "dnsblGet",
            "dnsblSet",
            "forwardAddForward",
            "forwardDelForward",
            "forwardGet",
            "forwardGetForward",
            "forwardSet",
            "forwardSetForward",
            "forwardToggleForward",
            "generalGet",
            "generalSet",
            "serverAddServer",
            "serverDelServer",
            "serverGet",
            "serverGetServer",
            "serverSet",
            "serverSetServer",
            "serverToggleServer",
            "serviceDnsbl",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "whitelistAddWhitelist",
            "whitelistDelWhitelist",
            "whitelistGet",
            "whitelistGetWhitelist",
            "whitelistSet",
            "whitelistSetWhitelist",
            "whitelistToggleWhitelist"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_dyndns_manage",
    "description": "Plugin dyndns management - 14 available methods including: accountsAddItem, accountsDelItem, accountsGet, accountsGetItem, accountsSet...",
    "module": "plugins",
    "submodule": "dyndns",
    "methods": [
      "accountsAddItem",
      "accountsDelItem",
      "accountsGet",
      "accountsGetItem",
      "accountsSet",
      "accountsSetItem",
      "accountsToggleItem",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "accountsAddItem",
            "accountsDelItem",
            "accountsGet",
            "accountsGetItem",
            "accountsSet",
            "accountsSetItem",
            "accountsToggleItem",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_freeradius_manage",
    "description": "Plugin freeradius management - 68 available methods including: avpairAddAvpair, avpairDelAvpair, avpairGet, avpairGetAvpair, avpairSet...",
    "module": "plugins",
    "submodule": "freeradius",
    "methods": [
      "avpairAddAvpair",
      "avpairDelAvpair",
      "avpairGet",
      "avpairGetAvpair",
      "avpairSet",
      "avpairSetAvpair",
      "avpairToggleAvpair",
      "clientAddClient",
      "clientDelClient",
      "clientGet",
      "clientGetClient",
      "clientSearchClient",
      "clientSet",
      "clientSetClient",
      "clientToggleClient",
      "dhcpAddDhcp",
      "dhcpDelDhcp",
      "dhcpGet",
      "dhcpGetDhcp",
      "dhcpSet",
      "dhcpSetDhcp",
      "dhcpToggleDhcp",
      "eapGet",
      "eapSet",
      "generalGet",
      "generalSet",
      "ldapGet",
      "ldapSet",
      "leaseAddLease",
      "leaseDelLease",
      "leaseGet",
      "leaseGetLease",
      "leaseSet",
      "leaseSetLease",
      "leaseToggleLease",
      "proxyAddHomeserver",
      "proxyAddHomeserverpool",
      "proxyAddRealm",
      "proxyDelHomeserver",
      "proxyDelHomeserverpool",
      "proxyDelRealm",
      "proxyGet",
      "proxyGetHomeserver",
      "proxyGetHomeserverpool",
      "proxyGetRealm",
      "proxySearchHomeserver",
      "proxySearchHomeserverpool",
      "proxySearchRealm",
      "proxySet",
      "proxySetHomeserver",
      "proxySetHomeserverpool",
      "proxySetRealm",
      "proxyToggleHomeserver",
      "proxyToggleHomeserverpool",
      "proxyToggleRealm",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userGet",
      "userGetUser",
      "userSearchUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "avpairAddAvpair",
            "avpairDelAvpair",
            "avpairGet",
            "avpairGetAvpair",
            "avpairSet",
            "avpairSetAvpair",
            "avpairToggleAvpair",
            "clientAddClient",
            "clientDelClient",
            "clientGet",
            "clientGetClient",
            "clientSearchClient",
            "clientSet",
            "clientSetClient",
            "clientToggleClient",
            "dhcpAddDhcp",
            "dhcpDelDhcp",
            "dhcpGet",
            "dhcpGetDhcp",
            "dhcpSet",
            "dhcpSetDhcp",
            "dhcpToggleDhcp",
            "eapGet",
            "eapSet",
            "generalGet",
            "generalSet",
            "ldapGet",
            "ldapSet",
            "leaseAddLease",
            "leaseDelLease",
            "leaseGet",
            "leaseGetLease",
            "leaseSet",
            "leaseSetLease",
            "leaseToggleLease",
            "proxyAddHomeserver",
            "proxyAddHomeserverpool",
            "proxyAddRealm",
            "proxyDelHomeserver",
            "proxyDelHomeserverpool",
            "proxyDelRealm",
            "proxyGet",
            "proxyGetHomeserver",
            "proxyGetHomeserverpool",
            "proxyGetRealm",
            "proxySearchHomeserver",
            "proxySearchHomeserverpool",
            "proxySearchRealm",
            "proxySet",
            "proxySetHomeserver",
            "proxySetHomeserverpool",
            "proxySetRealm",
            "proxyToggleHomeserver",
            "proxyToggleHomeserverpool",
            "proxyToggleRealm",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "userAddUser",
            "userDelUser",
            "userGet",
            "userGetUser",
            "userSearchUser",
            "userSet",
            "userSetUser",
            "userToggleUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ftpproxy_manage",
    "description": "Plugin ftpproxy management - 12 available methods including: serviceConfig, serviceReload, serviceRestart, serviceStart, serviceStatus...",
    "module": "plugins",
    "submodule": "ftpproxy",
    "methods": [
      "serviceConfig",
      "serviceReload",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddProxy",
      "settingsDelProxy",
      "settingsGetProxy",
      "settingsSearchProxy",
      "settingsSetProxy",
      "settingsToggleProxy"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceConfig",
            "serviceReload",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddProxy",
            "settingsDelProxy",
            "settingsGetProxy",
            "settingsSearchProxy",
            "settingsSetProxy",
            "settingsToggleProxy"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_gridexample_manage",
    "description": "Plugin gridexample management - 7 available methods including: settingsAddItem, settingsDelItem, settingsGet, settingsGetItem, settingsSet...",
    "module": "plugins",
    "submodule": "gridexample",
    "methods": [
      "settingsAddItem",
      "settingsDelItem",
      "settingsGet",
      "settingsGetItem",
      "settingsSet",
      "settingsSetItem",
      "settingsToggleItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "settingsAddItem",
            "settingsDelItem",
            "settingsGet",
            "settingsGetItem",
            "settingsSet",
            "settingsSetItem",
            "settingsToggleItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_haproxy_manage",
    "description": "Plugin haproxy management - 96 available methods including: exportConfig, exportDiff, exportDownload, maintenanceCertActions, maintenanceCertDiff...",
    "module": "plugins",
    "submodule": "haproxy",
    "methods": [
      "exportConfig",
      "exportDiff",
      "exportDownload",
      "maintenanceCertActions",
      "maintenanceCertDiff",
      "maintenanceCertSync",
      "maintenanceCertSyncBulk",
      "maintenanceFetchCronIntegration",
      "maintenanceGet",
      "maintenanceSearchCertificateDiff",
      "maintenanceSearchServer",
      "maintenanceServerState",
      "maintenanceServerStateBulk",
      "maintenanceServerWeight",
      "maintenanceServerWeightBulk",
      "maintenanceSet",
      "serviceConfigtest",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddAcl",
      "settingsAddAction",
      "settingsAddBackend",
      "settingsAddCpu",
      "settingsAddErrorfile",
      "settingsAddFcgi",
      "settingsAddFrontend",
      "settingsAddGroup",
      "settingsAddHealthcheck",
      "settingsAddLua",
      "settingsAddMapfile",
      "settingsAddServer",
      "settingsAddUser",
      "settingsAddmailer",
      "settingsAddresolver",
      "settingsDelAcl",
      "settingsDelAction",
      "settingsDelBackend",
      "settingsDelCpu",
      "settingsDelErrorfile",
      "settingsDelFcgi",
      "settingsDelFrontend",
      "settingsDelGroup",
      "settingsDelHealthcheck",
      "settingsDelLua",
      "settingsDelMapfile",
      "settingsDelServer",
      "settingsDelUser",
      "settingsDelmailer",
      "settingsDelresolver",
      "settingsGet",
      "settingsGetAcl",
      "settingsGetAction",
      "settingsGetBackend",
      "settingsGetCpu",
      "settingsGetErrorfile",
      "settingsGetFcgi",
      "settingsGetFrontend",
      "settingsGetGroup",
      "settingsGetHealthcheck",
      "settingsGetLua",
      "settingsGetMapfile",
      "settingsGetServer",
      "settingsGetUser",
      "settingsGetmailer",
      "settingsGetresolver",
      "settingsSet",
      "settingsSetAcl",
      "settingsSetAction",
      "settingsSetBackend",
      "settingsSetCpu",
      "settingsSetErrorfile",
      "settingsSetFcgi",
      "settingsSetFrontend",
      "settingsSetGroup",
      "settingsSetHealthcheck",
      "settingsSetLua",
      "settingsSetMapfile",
      "settingsSetServer",
      "settingsSetUser",
      "settingsSetmailer",
      "settingsSetresolver",
      "settingsToggleBackend",
      "settingsToggleCpu",
      "settingsToggleFrontend",
      "settingsToggleGroup",
      "settingsToggleLua",
      "settingsToggleServer",
      "settingsToggleUser",
      "settingsTogglemailer",
      "settingsToggleresolver",
      "statisticsCounters",
      "statisticsInfo",
      "statisticsTables"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "exportConfig",
            "exportDiff",
            "exportDownload",
            "maintenanceCertActions",
            "maintenanceCertDiff",
            "maintenanceCertSync",
            "maintenanceCertSyncBulk",
            "maintenanceFetchCronIntegration",
            "maintenanceGet",
            "maintenanceSearchCertificateDiff",
            "maintenanceSearchServer",
            "maintenanceServerState",
            "maintenanceServerStateBulk",
            "maintenanceServerWeight",
            "maintenanceServerWeightBulk",
            "maintenanceSet",
            "serviceConfigtest",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddAcl",
            "settingsAddAction",
            "settingsAddBackend",
            "settingsAddCpu",
            "settingsAddErrorfile",
            "settingsAddFcgi",
            "settingsAddFrontend",
            "settingsAddGroup",
            "settingsAddHealthcheck",
            "settingsAddLua",
            "settingsAddMapfile",
            "settingsAddServer",
            "settingsAddUser",
            "settingsAddmailer",
            "settingsAddresolver",
            "settingsDelAcl",
            "settingsDelAction",
            "settingsDelBackend",
            "settingsDelCpu",
            "settingsDelErrorfile",
            "settingsDelFcgi",
            "settingsDelFrontend",
            "settingsDelGroup",
            "settingsDelHealthcheck",
            "settingsDelLua",
            "settingsDelMapfile",
            "settingsDelServer",
            "settingsDelUser",
            "settingsDelmailer",
            "settingsDelresolver",
            "settingsGet",
            "settingsGetAcl",
            "settingsGetAction",
            "settingsGetBackend",
            "settingsGetCpu",
            "settingsGetErrorfile",
            "settingsGetFcgi",
            "settingsGetFrontend",
            "settingsGetGroup",
            "settingsGetHealthcheck",
            "settingsGetLua",
            "settingsGetMapfile",
            "settingsGetServer",
            "settingsGetUser",
            "settingsGetmailer",
            "settingsGetresolver",
            "settingsSet",
            "settingsSetAcl",
            "settingsSetAction",
            "settingsSetBackend",
            "settingsSetCpu",
            "settingsSetErrorfile",
            "settingsSetFcgi",
            "settingsSetFrontend",
            "settingsSetGroup",
            "settingsSetHealthcheck",
            "settingsSetLua",
            "settingsSetMapfile",
            "settingsSetServer",
            "settingsSetUser",
            "settingsSetmailer",
            "settingsSetresolver",
            "settingsToggleBackend",
            "settingsToggleCpu",
            "settingsToggleFrontend",
            "settingsToggleGroup",
            "settingsToggleLua",
            "settingsToggleServer",
            "settingsToggleUser",
            "settingsTogglemailer",
            "settingsToggleresolver",
            "statisticsCounters",
            "statisticsInfo",
            "statisticsTables"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_helloworld_manage",
    "description": "Plugin helloworld management - 4 available methods including: serviceReload, serviceTest, settingsGet, settingsSet...",
    "module": "plugins",
    "submodule": "helloworld",
    "methods": [
      "serviceReload",
      "serviceTest",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReload",
            "serviceTest",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_hwprobe_manage",
    "description": "Plugin hwprobe management - 8 available methods including: generalGet, generalSet, serviceReconfigure, serviceReport, serviceRestart...",
    "module": "plugins",
    "submodule": "hwprobe",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceReport",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceReport",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_iperf_manage",
    "description": "Plugin iperf management - 7 available methods including: instanceGet, instanceQuery, instanceSet, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "iperf",
    "methods": [
      "instanceGet",
      "instanceQuery",
      "instanceSet",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "instanceGet",
            "instanceQuery",
            "instanceSet",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_lldpd_manage",
    "description": "Plugin lldpd management - 8 available methods including: generalGet, generalSet, serviceNeighbor, serviceReconfigure, serviceRestart...",
    "module": "plugins",
    "submodule": "lldpd",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceNeighbor",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceNeighbor",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_maltrail_manage",
    "description": "Plugin maltrail management - 16 available methods including: generalGet, generalSet, sensorGet, sensorSet, serverGet...",
    "module": "plugins",
    "submodule": "maltrail",
    "methods": [
      "generalGet",
      "generalSet",
      "sensorGet",
      "sensorSet",
      "serverGet",
      "serverSet",
      "serverserviceReconfigure",
      "serverserviceRestart",
      "serverserviceStart",
      "serverserviceStatus",
      "serverserviceStop",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "sensorGet",
            "sensorSet",
            "serverGet",
            "serverSet",
            "serverserviceReconfigure",
            "serverserviceRestart",
            "serverserviceStart",
            "serverserviceStatus",
            "serverserviceStop",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_mdnsrepeater_manage",
    "description": "Plugin mdnsrepeater management - 7 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "mdnsrepeater",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_muninnode_manage",
    "description": "Plugin muninnode management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "muninnode",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ndproxy_manage",
    "description": "Plugin ndproxy management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "ndproxy",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_netdata_manage",
    "description": "Plugin netdata management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "netdata",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_netsnmp_manage",
    "description": "Plugin netsnmp management - 14 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "netsnmp",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userGet",
      "userGetUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "userAddUser",
            "userDelUser",
            "userGet",
            "userGetUser",
            "userSet",
            "userSetUser",
            "userToggleUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nginx_manage",
    "description": "Plugin nginx management - 99 available methods including: bansDelban, bansGet, bansSet, logsAccesses, logsErrors...",
    "module": "plugins",
    "submodule": "nginx",
    "methods": [
      "bansDelban",
      "bansGet",
      "bansSet",
      "logsAccesses",
      "logsErrors",
      "logsStreamaccesses",
      "logsStreamerrors",
      "logsTlsHandshakes",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceVts",
      "settingsAddcachePath",
      "settingsAddcredential",
      "settingsAddcustompolicy",
      "settingsAdderrorpage",
      "settingsAddhttprewrite",
      "settingsAddhttpserver",
      "settingsAddipacl",
      "settingsAddlimitRequestConnection",
      "settingsAddlimitZone",
      "settingsAddlocation",
      "settingsAddnaxsirule",
      "settingsAddresolver",
      "settingsAddsecurityHeader",
      "settingsAddsnifwd",
      "settingsAddstreamserver",
      "settingsAddsyslogTarget",
      "settingsAddtlsFingerprint",
      "settingsAddupstream",
      "settingsAddupstreamserver",
      "settingsAdduserlist",
      "settingsDelcachePath",
      "settingsDelcredential",
      "settingsDelcustompolicy",
      "settingsDelerrorpage",
      "settingsDelhttprewrite",
      "settingsDelhttpserver",
      "settingsDelipacl",
      "settingsDellimitRequestConnection",
      "settingsDellimitZone",
      "settingsDellocation",
      "settingsDelnaxsirule",
      "settingsDelresolver",
      "settingsDelsecurityHeader",
      "settingsDelsnifwd",
      "settingsDelstreamserver",
      "settingsDelsyslogTarget",
      "settingsDeltlsFingerprint",
      "settingsDelupstream",
      "settingsDelupstreamserver",
      "settingsDeluserlist",
      "settingsDownloadrules",
      "settingsGet",
      "settingsGetcachePath",
      "settingsGetcredential",
      "settingsGetcustompolicy",
      "settingsGeterrorpage",
      "settingsGethttprewrite",
      "settingsGethttpserver",
      "settingsGetipacl",
      "settingsGetlimitRequestConnection",
      "settingsGetlimitZone",
      "settingsGetlocation",
      "settingsGetnaxsirule",
      "settingsGetresolver",
      "settingsGetsecurityHeader",
      "settingsGetsnifwd",
      "settingsGetstreamserver",
      "settingsGetsyslogTarget",
      "settingsGettlsFingerprint",
      "settingsGetupstream",
      "settingsGetupstreamserver",
      "settingsGetuserlist",
      "settingsSet",
      "settingsSetcachePath",
      "settingsSetcredential",
      "settingsSetcustompolicy",
      "settingsSeterrorpage",
      "settingsSethttprewrite",
      "settingsSethttpserver",
      "settingsSetipacl",
      "settingsSetlimitRequestConnection",
      "settingsSetlimitZone",
      "settingsSetlocation",
      "settingsSetnaxsirule",
      "settingsSetresolver",
      "settingsSetsecurityHeader",
      "settingsSetsnifwd",
      "settingsSetstreamserver",
      "settingsSetsyslogTarget",
      "settingsSettlsFingerprint",
      "settingsSetupstream",
      "settingsSetupstreamserver",
      "settingsSetuserlist",
      "settingsShowconfig",
      "settingsTestconfig"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "bansDelban",
            "bansGet",
            "bansSet",
            "logsAccesses",
            "logsErrors",
            "logsStreamaccesses",
            "logsStreamerrors",
            "logsTlsHandshakes",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "serviceVts",
            "settingsAddcachePath",
            "settingsAddcredential",
            "settingsAddcustompolicy",
            "settingsAdderrorpage",
            "settingsAddhttprewrite",
            "settingsAddhttpserver",
            "settingsAddipacl",
            "settingsAddlimitRequestConnection",
            "settingsAddlimitZone",
            "settingsAddlocation",
            "settingsAddnaxsirule",
            "settingsAddresolver",
            "settingsAddsecurityHeader",
            "settingsAddsnifwd",
            "settingsAddstreamserver",
            "settingsAddsyslogTarget",
            "settingsAddtlsFingerprint",
            "settingsAddupstream",
            "settingsAddupstreamserver",
            "settingsAdduserlist",
            "settingsDelcachePath",
            "settingsDelcredential",
            "settingsDelcustompolicy",
            "settingsDelerrorpage",
            "settingsDelhttprewrite",
            "settingsDelhttpserver",
            "settingsDelipacl",
            "settingsDellimitRequestConnection",
            "settingsDellimitZone",
            "settingsDellocation",
            "settingsDelnaxsirule",
            "settingsDelresolver",
            "settingsDelsecurityHeader",
            "settingsDelsnifwd",
            "settingsDelstreamserver",
            "settingsDelsyslogTarget",
            "settingsDeltlsFingerprint",
            "settingsDelupstream",
            "settingsDelupstreamserver",
            "settingsDeluserlist",
            "settingsDownloadrules",
            "settingsGet",
            "settingsGetcachePath",
            "settingsGetcredential",
            "settingsGetcustompolicy",
            "settingsGeterrorpage",
            "settingsGethttprewrite",
            "settingsGethttpserver",
            "settingsGetipacl",
            "settingsGetlimitRequestConnection",
            "settingsGetlimitZone",
            "settingsGetlocation",
            "settingsGetnaxsirule",
            "settingsGetresolver",
            "settingsGetsecurityHeader",
            "settingsGetsnifwd",
            "settingsGetstreamserver",
            "settingsGetsyslogTarget",
            "settingsGettlsFingerprint",
            "settingsGetupstream",
            "settingsGetupstreamserver",
            "settingsGetuserlist",
            "settingsSet",
            "settingsSetcachePath",
            "settingsSetcredential",
            "settingsSetcustompolicy",
            "settingsSeterrorpage",
            "settingsSethttprewrite",
            "settingsSethttpserver",
            "settingsSetipacl",
            "settingsSetlimitRequestConnection",
            "settingsSetlimitZone",
            "settingsSetlocation",
            "settingsSetnaxsirule",
            "settingsSetresolver",
            "settingsSetsecurityHeader",
            "settingsSetsnifwd",
            "settingsSetstreamserver",
            "settingsSetsyslogTarget",
            "settingsSettlsFingerprint",
            "settingsSetupstream",
            "settingsSetupstreamserver",
            "settingsSetuserlist",
            "settingsShowconfig",
            "settingsTestconfig"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nodeexporter_manage",
    "description": "Plugin nodeexporter management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "nodeexporter",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nrpe_manage",
    "description": "Plugin nrpe management - 14 available methods including: commandAddCommand, commandDelCommand, commandGet, commandGetCommand, commandSet...",
    "module": "plugins",
    "submodule": "nrpe",
    "methods": [
      "commandAddCommand",
      "commandDelCommand",
      "commandGet",
      "commandGetCommand",
      "commandSet",
      "commandSetCommand",
      "commandToggleCommand",
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "commandAddCommand",
            "commandDelCommand",
            "commandGet",
            "commandGetCommand",
            "commandSet",
            "commandSetCommand",
            "commandToggleCommand",
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_ntopng_manage",
    "description": "Plugin ntopng management - 8 available methods including: generalGet, generalSet, serviceCheckredis, serviceReconfigure, serviceRestart...",
    "module": "plugins",
    "submodule": "ntopng",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceCheckredis",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceCheckredis",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_nut_manage",
    "description": "Plugin nut management - 8 available methods including: diagnosticsUpsstatus, serviceReconfigure, serviceRestart, serviceStart, serviceStatus...",
    "module": "plugins",
    "submodule": "nut",
    "methods": [
      "diagnosticsUpsstatus",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "diagnosticsUpsstatus",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_openconnect_manage",
    "description": "Plugin openconnect management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "openconnect",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_postfix_manage",
    "description": "Plugin postfix management - 66 available methods including: addressAddAddress, addressDelAddress, addressGet, addressGetAddress, addressSet...",
    "module": "plugins",
    "submodule": "postfix",
    "methods": [
      "addressAddAddress",
      "addressDelAddress",
      "addressGet",
      "addressGetAddress",
      "addressSet",
      "addressSetAddress",
      "addressToggleAddress",
      "antispamGet",
      "antispamSet",
      "domainAddDomain",
      "domainDelDomain",
      "domainGet",
      "domainGetDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalGet",
      "generalSet",
      "headerchecksAddHeadercheck",
      "headerchecksDelHeadercheck",
      "headerchecksGet",
      "headerchecksGetHeadercheck",
      "headerchecksSet",
      "headerchecksSetHeadercheck",
      "headerchecksToggleHeadercheck",
      "recipientAddRecipient",
      "recipientDelRecipient",
      "recipientGet",
      "recipientGetRecipient",
      "recipientSet",
      "recipientSetRecipient",
      "recipientToggleRecipient",
      "recipientbccAddRecipientbcc",
      "recipientbccDelRecipientbcc",
      "recipientbccGet",
      "recipientbccGetRecipientbcc",
      "recipientbccSet",
      "recipientbccSetRecipientbcc",
      "recipientbccToggleRecipientbcc",
      "senderAddSender",
      "senderDelSender",
      "senderGet",
      "senderGetSender",
      "senderSet",
      "senderSetSender",
      "senderToggleSender",
      "senderbccAddSenderbcc",
      "senderbccDelSenderbcc",
      "senderbccGet",
      "senderbccGetSenderbcc",
      "senderbccSet",
      "senderbccSetSenderbcc",
      "senderbccToggleSenderbcc",
      "sendercanonicalAddSendercanonical",
      "sendercanonicalDelSendercanonical",
      "sendercanonicalGet",
      "sendercanonicalGetSendercanonical",
      "sendercanonicalSet",
      "sendercanonicalSetSendercanonical",
      "sendercanonicalToggleSendercanonical",
      "serviceCheckrspamd",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "addressAddAddress",
            "addressDelAddress",
            "addressGet",
            "addressGetAddress",
            "addressSet",
            "addressSetAddress",
            "addressToggleAddress",
            "antispamGet",
            "antispamSet",
            "domainAddDomain",
            "domainDelDomain",
            "domainGet",
            "domainGetDomain",
            "domainSet",
            "domainSetDomain",
            "domainToggleDomain",
            "generalGet",
            "generalSet",
            "headerchecksAddHeadercheck",
            "headerchecksDelHeadercheck",
            "headerchecksGet",
            "headerchecksGetHeadercheck",
            "headerchecksSet",
            "headerchecksSetHeadercheck",
            "headerchecksToggleHeadercheck",
            "recipientAddRecipient",
            "recipientDelRecipient",
            "recipientGet",
            "recipientGetRecipient",
            "recipientSet",
            "recipientSetRecipient",
            "recipientToggleRecipient",
            "recipientbccAddRecipientbcc",
            "recipientbccDelRecipientbcc",
            "recipientbccGet",
            "recipientbccGetRecipientbcc",
            "recipientbccSet",
            "recipientbccSetRecipientbcc",
            "recipientbccToggleRecipientbcc",
            "senderAddSender",
            "senderDelSender",
            "senderGet",
            "senderGetSender",
            "senderSet",
            "senderSetSender",
            "senderToggleSender",
            "senderbccAddSenderbcc",
            "senderbccDelSenderbcc",
            "senderbccGet",
            "senderbccGetSenderbcc",
            "senderbccSet",
            "senderbccSetSenderbcc",
            "senderbccToggleSenderbcc",
            "sendercanonicalAddSendercanonical",
            "sendercanonicalDelSendercanonical",
            "sendercanonicalGet",
            "sendercanonicalGetSendercanonical",
            "sendercanonicalSet",
            "sendercanonicalSetSendercanonical",
            "sendercanonicalToggleSendercanonical",
            "serviceCheckrspamd",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_proxy_manage",
    "description": "Plugin proxy management - 48 available methods including: serviceDownloadacls, serviceFetchacls, serviceReconfigure, serviceRefreshTemplate, serviceReset...",
    "module": "plugins",
    "submodule": "proxy",
    "methods": [
      "serviceDownloadacls",
      "serviceFetchacls",
      "serviceReconfigure",
      "serviceRefreshTemplate",
      "serviceReset",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddPACMatch",
      "settingsAddPACProxy",
      "settingsAddPACRule",
      "settingsAddRemoteBlacklist",
      "settingsDelPACMatch",
      "settingsDelPACProxy",
      "settingsDelPACRule",
      "settingsDelRemoteBlacklist",
      "settingsFetchRBCron",
      "settingsGet",
      "settingsGetPACMatch",
      "settingsGetPACProxy",
      "settingsGetPACRule",
      "settingsGetRemoteBlacklist",
      "settingsSearchRemoteBlacklists",
      "settingsSet",
      "settingsSetPACMatch",
      "settingsSetPACProxy",
      "settingsSetPACRule",
      "settingsSetRemoteBlacklist",
      "settingsTogglePACRule",
      "settingsToggleRemoteBlacklist",
      "templateGet",
      "templateReset",
      "templateSet",
      "aclAddCustomPolicy",
      "aclAddPolicy",
      "aclApply",
      "aclDelCustomPolicy",
      "aclDelPolicy",
      "aclGet",
      "aclGetCustomPolicy",
      "aclGetPolicy",
      "aclSet",
      "aclSetCustomPolicy",
      "aclSetPolicy",
      "aclTest",
      "aclToggleCustomPolicy",
      "aclTogglePolicy"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceDownloadacls",
            "serviceFetchacls",
            "serviceReconfigure",
            "serviceRefreshTemplate",
            "serviceReset",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddPACMatch",
            "settingsAddPACProxy",
            "settingsAddPACRule",
            "settingsAddRemoteBlacklist",
            "settingsDelPACMatch",
            "settingsDelPACProxy",
            "settingsDelPACRule",
            "settingsDelRemoteBlacklist",
            "settingsFetchRBCron",
            "settingsGet",
            "settingsGetPACMatch",
            "settingsGetPACProxy",
            "settingsGetPACRule",
            "settingsGetRemoteBlacklist",
            "settingsSearchRemoteBlacklists",
            "settingsSet",
            "settingsSetPACMatch",
            "settingsSetPACProxy",
            "settingsSetPACRule",
            "settingsSetRemoteBlacklist",
            "settingsTogglePACRule",
            "settingsToggleRemoteBlacklist",
            "templateGet",
            "templateReset",
            "templateSet",
            "aclAddCustomPolicy",
            "aclAddPolicy",
            "aclApply",
            "aclDelCustomPolicy",
            "aclDelPolicy",
            "aclGet",
            "aclGetCustomPolicy",
            "aclGetPolicy",
            "aclSet",
            "aclSetCustomPolicy",
            "aclSetPolicy",
            "aclTest",
            "aclToggleCustomPolicy",
            "aclTogglePolicy"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_proxysso_manage",
    "description": "Plugin proxysso management - 7 available methods including: serviceCreatekeytab, serviceDeletekeytab, serviceGetCheckList, serviceShowkeytab, serviceTestkerblogin...",
    "module": "plugins",
    "submodule": "proxysso",
    "methods": [
      "serviceCreatekeytab",
      "serviceDeletekeytab",
      "serviceGetCheckList",
      "serviceShowkeytab",
      "serviceTestkerblogin",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceCreatekeytab",
            "serviceDeletekeytab",
            "serviceGetCheckList",
            "serviceShowkeytab",
            "serviceTestkerblogin",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_puppetagent_manage",
    "description": "Plugin puppetagent management - 7 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "puppetagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_qemuguestagent_manage",
    "description": "Plugin qemuguestagent management - 7 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "qemuguestagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_quagga_manage",
    "description": "Plugin quagga management - 133 available methods including: bfdAddNeighbor, bfdDelNeighbor, bfdGet, bfdGetNeighbor, bfdSet...",
    "module": "plugins",
    "submodule": "quagga",
    "methods": [
      "bfdAddNeighbor",
      "bfdDelNeighbor",
      "bfdGet",
      "bfdGetNeighbor",
      "bfdSet",
      "bfdSetNeighbor",
      "bfdToggleNeighbor",
      "bgpAddAspath",
      "bgpAddCommunitylist",
      "bgpAddNeighbor",
      "bgpAddPeergroup",
      "bgpAddPrefixlist",
      "bgpAddRedistribution",
      "bgpAddRoutemap",
      "bgpDelAspath",
      "bgpDelCommunitylist",
      "bgpDelNeighbor",
      "bgpDelPeergroup",
      "bgpDelPrefixlist",
      "bgpDelRedistribution",
      "bgpDelRoutemap",
      "bgpGet",
      "bgpGetAspath",
      "bgpGetCommunitylist",
      "bgpGetNeighbor",
      "bgpGetPeergroup",
      "bgpGetPrefixlist",
      "bgpGetRedistribution",
      "bgpGetRoutemap",
      "bgpSet",
      "bgpSetAspath",
      "bgpSetCommunitylist",
      "bgpSetNeighbor",
      "bgpSetPeergroup",
      "bgpSetPrefixlist",
      "bgpSetRedistribution",
      "bgpSetRoutemap",
      "bgpToggleAspath",
      "bgpToggleCommunitylist",
      "bgpToggleNeighbor",
      "bgpTogglePeergroup",
      "bgpTogglePrefixlist",
      "bgpToggleRedistribution",
      "bgpToggleRoutemap",
      "diagnosticsBfdcounters",
      "diagnosticsBfdneighbors",
      "diagnosticsBfdsummary",
      "diagnosticsBgpneighbors",
      "diagnosticsBgpsummary",
      "diagnosticsGeneralrunningconfig",
      "diagnosticsOspfdatabase",
      "diagnosticsOspfinterface",
      "diagnosticsOspfoverview",
      "diagnosticsOspfv3interface",
      "diagnosticsOspfv3overview",
      "diagnosticsSearchBgproute4",
      "diagnosticsSearchBgproute6",
      "diagnosticsSearchGeneralroute4",
      "diagnosticsSearchGeneralroute6",
      "diagnosticsSearchOspfneighbor",
      "diagnosticsSearchOspfroute",
      "diagnosticsSearchOspfv3database",
      "diagnosticsSearchOspfv3route",
      "generalGet",
      "generalSet",
      "ospf6settingsAddInterface",
      "ospf6settingsAddNetwork",
      "ospf6settingsAddPrefixlist",
      "ospf6settingsAddRedistribution",
      "ospf6settingsAddRoutemap",
      "ospf6settingsDelInterface",
      "ospf6settingsDelNetwork",
      "ospf6settingsDelPrefixlist",
      "ospf6settingsDelRedistribution",
      "ospf6settingsDelRoutemap",
      "ospf6settingsGet",
      "ospf6settingsGetInterface",
      "ospf6settingsGetNetwork",
      "ospf6settingsGetPrefixlist",
      "ospf6settingsGetRedistribution",
      "ospf6settingsGetRoutemap",
      "ospf6settingsSet",
      "ospf6settingsSetInterface",
      "ospf6settingsSetNetwork",
      "ospf6settingsSetPrefixlist",
      "ospf6settingsSetRedistribution",
      "ospf6settingsSetRoutemap",
      "ospf6settingsToggleInterface",
      "ospf6settingsToggleNetwork",
      "ospf6settingsTogglePrefixlist",
      "ospf6settingsToggleRedistribution",
      "ospf6settingsToggleRoutemap",
      "ospfsettingsAddInterface",
      "ospfsettingsAddNetwork",
      "ospfsettingsAddPrefixlist",
      "ospfsettingsAddRedistribution",
      "ospfsettingsAddRoutemap",
      "ospfsettingsDelInterface",
      "ospfsettingsDelNetwork",
      "ospfsettingsDelPrefixlist",
      "ospfsettingsDelRedistribution",
      "ospfsettingsDelRoutemap",
      "ospfsettingsGet",
      "ospfsettingsGetInterface",
      "ospfsettingsGetNetwork",
      "ospfsettingsGetPrefixlist",
      "ospfsettingsGetRedistribution",
      "ospfsettingsGetRoutemap",
      "ospfsettingsSet",
      "ospfsettingsSetInterface",
      "ospfsettingsSetNetwork",
      "ospfsettingsSetPrefixlist",
      "ospfsettingsSetRedistribution",
      "ospfsettingsSetRoutemap",
      "ospfsettingsToggleInterface",
      "ospfsettingsToggleNetwork",
      "ospfsettingsTogglePrefixlist",
      "ospfsettingsToggleRedistribution",
      "ospfsettingsToggleRoutemap",
      "ripGet",
      "ripSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "staticAddRoute",
      "staticDelRoute",
      "staticGet",
      "staticGetRoute",
      "staticSet",
      "staticSetRoute",
      "staticToggleRoute"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "bfdAddNeighbor",
            "bfdDelNeighbor",
            "bfdGet",
            "bfdGetNeighbor",
            "bfdSet",
            "bfdSetNeighbor",
            "bfdToggleNeighbor",
            "bgpAddAspath",
            "bgpAddCommunitylist",
            "bgpAddNeighbor",
            "bgpAddPeergroup",
            "bgpAddPrefixlist",
            "bgpAddRedistribution",
            "bgpAddRoutemap",
            "bgpDelAspath",
            "bgpDelCommunitylist",
            "bgpDelNeighbor",
            "bgpDelPeergroup",
            "bgpDelPrefixlist",
            "bgpDelRedistribution",
            "bgpDelRoutemap",
            "bgpGet",
            "bgpGetAspath",
            "bgpGetCommunitylist",
            "bgpGetNeighbor",
            "bgpGetPeergroup",
            "bgpGetPrefixlist",
            "bgpGetRedistribution",
            "bgpGetRoutemap",
            "bgpSet",
            "bgpSetAspath",
            "bgpSetCommunitylist",
            "bgpSetNeighbor",
            "bgpSetPeergroup",
            "bgpSetPrefixlist",
            "bgpSetRedistribution",
            "bgpSetRoutemap",
            "bgpToggleAspath",
            "bgpToggleCommunitylist",
            "bgpToggleNeighbor",
            "bgpTogglePeergroup",
            "bgpTogglePrefixlist",
            "bgpToggleRedistribution",
            "bgpToggleRoutemap",
            "diagnosticsBfdcounters",
            "diagnosticsBfdneighbors",
            "diagnosticsBfdsummary",
            "diagnosticsBgpneighbors",
            "diagnosticsBgpsummary",
            "diagnosticsGeneralrunningconfig",
            "diagnosticsOspfdatabase",
            "diagnosticsOspfinterface",
            "diagnosticsOspfoverview",
            "diagnosticsOspfv3interface",
            "diagnosticsOspfv3overview",
            "diagnosticsSearchBgproute4",
            "diagnosticsSearchBgproute6",
            "diagnosticsSearchGeneralroute4",
            "diagnosticsSearchGeneralroute6",
            "diagnosticsSearchOspfneighbor",
            "diagnosticsSearchOspfroute",
            "diagnosticsSearchOspfv3database",
            "diagnosticsSearchOspfv3route",
            "generalGet",
            "generalSet",
            "ospf6settingsAddInterface",
            "ospf6settingsAddNetwork",
            "ospf6settingsAddPrefixlist",
            "ospf6settingsAddRedistribution",
            "ospf6settingsAddRoutemap",
            "ospf6settingsDelInterface",
            "ospf6settingsDelNetwork",
            "ospf6settingsDelPrefixlist",
            "ospf6settingsDelRedistribution",
            "ospf6settingsDelRoutemap",
            "ospf6settingsGet",
            "ospf6settingsGetInterface",
            "ospf6settingsGetNetwork",
            "ospf6settingsGetPrefixlist",
            "ospf6settingsGetRedistribution",
            "ospf6settingsGetRoutemap",
            "ospf6settingsSet",
            "ospf6settingsSetInterface",
            "ospf6settingsSetNetwork",
            "ospf6settingsSetPrefixlist",
            "ospf6settingsSetRedistribution",
            "ospf6settingsSetRoutemap",
            "ospf6settingsToggleInterface",
            "ospf6settingsToggleNetwork",
            "ospf6settingsTogglePrefixlist",
            "ospf6settingsToggleRedistribution",
            "ospf6settingsToggleRoutemap",
            "ospfsettingsAddInterface",
            "ospfsettingsAddNetwork",
            "ospfsettingsAddPrefixlist",
            "ospfsettingsAddRedistribution",
            "ospfsettingsAddRoutemap",
            "ospfsettingsDelInterface",
            "ospfsettingsDelNetwork",
            "ospfsettingsDelPrefixlist",
            "ospfsettingsDelRedistribution",
            "ospfsettingsDelRoutemap",
            "ospfsettingsGet",
            "ospfsettingsGetInterface",
            "ospfsettingsGetNetwork",
            "ospfsettingsGetPrefixlist",
            "ospfsettingsGetRedistribution",
            "ospfsettingsGetRoutemap",
            "ospfsettingsSet",
            "ospfsettingsSetInterface",
            "ospfsettingsSetNetwork",
            "ospfsettingsSetPrefixlist",
            "ospfsettingsSetRedistribution",
            "ospfsettingsSetRoutemap",
            "ospfsettingsToggleInterface",
            "ospfsettingsToggleNetwork",
            "ospfsettingsTogglePrefixlist",
            "ospfsettingsToggleRedistribution",
            "ospfsettingsToggleRoutemap",
            "ripGet",
            "ripSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "staticAddRoute",
            "staticDelRoute",
            "staticGet",
            "staticGetRoute",
            "staticSet",
            "staticSetRoute",
            "staticToggleRoute"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_radsecproxy_manage",
    "description": "Plugin radsecproxy management - 42 available methods including: clientsAddItem, clientsDelItem, clientsGet, clientsGetItem, clientsSet...",
    "module": "plugins",
    "submodule": "radsecproxy",
    "methods": [
      "clientsAddItem",
      "clientsDelItem",
      "clientsGet",
      "clientsGetItem",
      "clientsSet",
      "clientsSetItem",
      "clientsToggleItem",
      "generalGet",
      "generalSet",
      "realmsAddItem",
      "realmsDelItem",
      "realmsGet",
      "realmsGetItem",
      "realmsSet",
      "realmsSetItem",
      "realmsToggleItem",
      "rewritesAddItem",
      "rewritesDelItem",
      "rewritesGet",
      "rewritesGetItem",
      "rewritesSet",
      "rewritesSetItem",
      "rewritesToggleItem",
      "serversAddItem",
      "serversDelItem",
      "serversGet",
      "serversGetItem",
      "serversSet",
      "serversSetItem",
      "serversToggleItem",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "tlsAddItem",
      "tlsDelItem",
      "tlsGet",
      "tlsGetItem",
      "tlsSet",
      "tlsSetItem",
      "tlsToggleItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "clientsAddItem",
            "clientsDelItem",
            "clientsGet",
            "clientsGetItem",
            "clientsSet",
            "clientsSetItem",
            "clientsToggleItem",
            "generalGet",
            "generalSet",
            "realmsAddItem",
            "realmsDelItem",
            "realmsGet",
            "realmsGetItem",
            "realmsSet",
            "realmsSetItem",
            "realmsToggleItem",
            "rewritesAddItem",
            "rewritesDelItem",
            "rewritesGet",
            "rewritesGetItem",
            "rewritesSet",
            "rewritesSetItem",
            "rewritesToggleItem",
            "serversAddItem",
            "serversDelItem",
            "serversGet",
            "serversGetItem",
            "serversSet",
            "serversSetItem",
            "serversToggleItem",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "tlsAddItem",
            "tlsDelItem",
            "tlsGet",
            "tlsGetItem",
            "tlsSet",
            "tlsSetItem",
            "tlsToggleItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_redis_manage",
    "description": "Plugin redis management - 8 available methods including: serviceReconfigure, serviceResetdb, serviceRestart, serviceStart, serviceStatus...",
    "module": "plugins",
    "submodule": "redis",
    "methods": [
      "serviceReconfigure",
      "serviceResetdb",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceResetdb",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_relayd_manage",
    "description": "Plugin relayd management - 14 available methods including: serviceConfigtest, serviceReconfigure, serviceRestart, serviceStart, serviceStatus...",
    "module": "plugins",
    "submodule": "relayd",
    "methods": [
      "serviceConfigtest",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsDel",
      "settingsDirty",
      "settingsGet",
      "settingsSearch",
      "settingsSet",
      "settingsToggle",
      "statusSum",
      "statusToggle"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceConfigtest",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsDel",
            "settingsDirty",
            "settingsGet",
            "settingsSearch",
            "settingsSet",
            "settingsToggle",
            "statusSum",
            "statusToggle"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_rspamd_manage",
    "description": "Plugin rspamd management - 7 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "rspamd",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_shadowsocks_manage",
    "description": "Plugin shadowsocks management - 14 available methods including: generalGet, generalSet, localGet, localSet, localserviceReconfigure...",
    "module": "plugins",
    "submodule": "shadowsocks",
    "methods": [
      "generalGet",
      "generalSet",
      "localGet",
      "localSet",
      "localserviceReconfigure",
      "localserviceRestart",
      "localserviceStart",
      "localserviceStatus",
      "localserviceStop",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "localGet",
            "localSet",
            "localserviceReconfigure",
            "localserviceRestart",
            "localserviceStart",
            "localserviceStatus",
            "localserviceStop",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_siproxd_manage",
    "description": "Plugin siproxd management - 24 available methods including: domainAddDomain, domainDelDomain, domainGet, domainGetDomain, domainSearchDomain...",
    "module": "plugins",
    "submodule": "siproxd",
    "methods": [
      "domainAddDomain",
      "domainDelDomain",
      "domainGet",
      "domainGetDomain",
      "domainSearchDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceShowregistrations",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userGet",
      "userGetUser",
      "userSearchUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "domainAddDomain",
            "domainDelDomain",
            "domainGet",
            "domainGetDomain",
            "domainSearchDomain",
            "domainSet",
            "domainSetDomain",
            "domainToggleDomain",
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceShowregistrations",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "userAddUser",
            "userDelUser",
            "userGet",
            "userGetUser",
            "userSearchUser",
            "userSet",
            "userSetUser",
            "userToggleUser"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_smart_manage",
    "description": "Plugin smart management - 5 available methods including: serviceAbort, serviceInfo, serviceList, serviceLogs, serviceTest...",
    "module": "plugins",
    "submodule": "smart",
    "methods": [
      "serviceAbort",
      "serviceInfo",
      "serviceList",
      "serviceLogs",
      "serviceTest"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceAbort",
            "serviceInfo",
            "serviceList",
            "serviceLogs",
            "serviceTest"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_softether_manage",
    "description": "Plugin softether management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "softether",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_sslh_manage",
    "description": "Plugin sslh management - 8 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "sslh",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsIndex",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsIndex",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_stunnel_manage",
    "description": "Plugin stunnel management - 12 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "stunnel",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "servicesAddItem",
      "servicesDelItem",
      "servicesGet",
      "servicesGetItem",
      "servicesSet",
      "servicesSetItem",
      "servicesToggleItem"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "servicesAddItem",
            "servicesDelItem",
            "servicesGet",
            "servicesGetItem",
            "servicesSet",
            "servicesSetItem",
            "servicesToggleItem"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tailscale_manage",
    "description": "Plugin tailscale management - 19 available methods including: authenticationGet, authenticationSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "tailscale",
    "methods": [
      "authenticationGet",
      "authenticationSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddSubnet",
      "settingsDelSubnet",
      "settingsGet",
      "settingsGetSubnet",
      "settingsReload",
      "settingsSet",
      "settingsSetSubnet",
      "statusGet",
      "statusIp",
      "statusNet",
      "statusSet",
      "status"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "authenticationGet",
            "authenticationSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddSubnet",
            "settingsDelSubnet",
            "settingsGet",
            "settingsGetSubnet",
            "settingsReload",
            "settingsSet",
            "settingsSetSubnet",
            "statusGet",
            "statusIp",
            "statusNet",
            "statusSet",
            "status"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tayga_manage",
    "description": "Plugin tayga management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "tayga",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_telegraf_manage",
    "description": "Plugin telegraf management - 18 available methods including: generalGet, generalSet, inputGet, inputSet, keyAddKey...",
    "module": "plugins",
    "submodule": "telegraf",
    "methods": [
      "generalGet",
      "generalSet",
      "inputGet",
      "inputSet",
      "keyAddKey",
      "keyDelKey",
      "keyGet",
      "keyGetKey",
      "keySearchKey",
      "keySet",
      "keySetKey",
      "keyToggleKey",
      "outputGet",
      "outputSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "inputGet",
            "inputSet",
            "keyAddKey",
            "keyDelKey",
            "keyGet",
            "keyGetKey",
            "keySearchKey",
            "keySet",
            "keySetKey",
            "keyToggleKey",
            "outputGet",
            "outputSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tftp_manage",
    "description": "Plugin tftp management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "tftp",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tinc_manage",
    "description": "Plugin tinc management - 16 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStop, settingsDelHost...",
    "module": "plugins",
    "submodule": "tinc",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsDelHost",
      "settingsDelNetwork",
      "settingsGet",
      "settingsGetHost",
      "settingsGetNetwork",
      "settingsSearchHost",
      "settingsSearchNetwork",
      "settingsSet",
      "settingsSetHost",
      "settingsSetNetwork",
      "settingsToggleHost",
      "settingsToggleNetwork"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStop",
            "settingsDelHost",
            "settingsDelNetwork",
            "settingsGet",
            "settingsGetHost",
            "settingsGetNetwork",
            "settingsSearchHost",
            "settingsSearchNetwork",
            "settingsSet",
            "settingsSetHost",
            "settingsSetNetwork",
            "settingsToggleHost",
            "settingsToggleNetwork"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_tor_manage",
    "description": "Plugin tor management - 45 available methods including: exitaclAddacl, exitaclDelacl, exitaclGet, exitaclGetacl, exitaclSet...",
    "module": "plugins",
    "submodule": "tor",
    "methods": [
      "exitaclAddacl",
      "exitaclDelacl",
      "exitaclGet",
      "exitaclGetacl",
      "exitaclSet",
      "exitaclSetacl",
      "exitaclToggleacl",
      "generalAddhidservauth",
      "generalDelhidservauth",
      "generalGet",
      "generalGethidservauth",
      "generalSet",
      "generalSethidservauth",
      "generalTogglehidservauth",
      "hiddenserviceAddservice",
      "hiddenserviceDelservice",
      "hiddenserviceGet",
      "hiddenserviceGetservice",
      "hiddenserviceSet",
      "hiddenserviceSetservice",
      "hiddenserviceToggleservice",
      "hiddenserviceaclAddacl",
      "hiddenserviceaclDelacl",
      "hiddenserviceaclGet",
      "hiddenserviceaclGetacl",
      "hiddenserviceaclSet",
      "hiddenserviceaclSetacl",
      "hiddenserviceaclToggleacl",
      "relayGet",
      "relaySet",
      "serviceCircuits",
      "serviceGetHiddenServices",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceStreams",
      "socksaclAddacl",
      "socksaclDelacl",
      "socksaclGet",
      "socksaclGetacl",
      "socksaclSet",
      "socksaclSetacl",
      "socksaclToggleacl"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "exitaclAddacl",
            "exitaclDelacl",
            "exitaclGet",
            "exitaclGetacl",
            "exitaclSet",
            "exitaclSetacl",
            "exitaclToggleacl",
            "generalAddhidservauth",
            "generalDelhidservauth",
            "generalGet",
            "generalGethidservauth",
            "generalSet",
            "generalSethidservauth",
            "generalTogglehidservauth",
            "hiddenserviceAddservice",
            "hiddenserviceDelservice",
            "hiddenserviceGet",
            "hiddenserviceGetservice",
            "hiddenserviceSet",
            "hiddenserviceSetservice",
            "hiddenserviceToggleservice",
            "hiddenserviceaclAddacl",
            "hiddenserviceaclDelacl",
            "hiddenserviceaclGet",
            "hiddenserviceaclGetacl",
            "hiddenserviceaclSet",
            "hiddenserviceaclSetacl",
            "hiddenserviceaclToggleacl",
            "relayGet",
            "relaySet",
            "serviceCircuits",
            "serviceGetHiddenServices",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "serviceStreams",
            "socksaclAddacl",
            "socksaclDelacl",
            "socksaclGet",
            "socksaclGetacl",
            "socksaclSet",
            "socksaclSetacl",
            "socksaclToggleacl"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_turnserver_manage",
    "description": "Plugin turnserver management - 7 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "turnserver",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_udpbroadcastrelay_manage",
    "description": "Plugin udpbroadcastrelay management - 16 available methods including: serviceConfig, serviceGet, serviceReload, serviceRestart, serviceSet...",
    "module": "plugins",
    "submodule": "udpbroadcastrelay",
    "methods": [
      "serviceConfig",
      "serviceGet",
      "serviceReload",
      "serviceRestart",
      "serviceSet",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddRelay",
      "settingsDelRelay",
      "settingsGet",
      "settingsGetRelay",
      "settingsSearchRelay",
      "settingsSet",
      "settingsSetRelay",
      "settingsToggleRelay"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceConfig",
            "serviceGet",
            "serviceReload",
            "serviceRestart",
            "serviceSet",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddRelay",
            "settingsDelRelay",
            "settingsGet",
            "settingsGetRelay",
            "settingsSearchRelay",
            "settingsSet",
            "settingsSetRelay",
            "settingsToggleRelay"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_vnstat_manage",
    "description": "Plugin vnstat management - 12 available methods including: generalGet, generalSet, serviceDaily, serviceHourly, serviceMonthly...",
    "module": "plugins",
    "submodule": "vnstat",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceDaily",
      "serviceHourly",
      "serviceMonthly",
      "serviceReconfigure",
      "serviceResetdb",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceYearly"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceDaily",
            "serviceHourly",
            "serviceMonthly",
            "serviceReconfigure",
            "serviceResetdb",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "serviceYearly"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_wazuhagent_manage",
    "description": "Plugin wazuhagent management - 7 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "wazuhagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsGet",
            "settingsSet"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_wol_manage",
    "description": "Plugin wol management - 8 available methods including: wolAddHost, wolDelHost, wolGet, wolGetHost, wolGetwake...",
    "module": "plugins",
    "submodule": "wol",
    "methods": [
      "wolAddHost",
      "wolDelHost",
      "wolGet",
      "wolGetHost",
      "wolGetwake",
      "wolSet",
      "wolSetHost",
      "wolWakeall"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "wolAddHost",
            "wolDelHost",
            "wolGet",
            "wolGetHost",
            "wolGetwake",
            "wolSet",
            "wolSetHost",
            "wolWakeall"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zabbixagent_manage",
    "description": "Plugin zabbixagent management - 17 available methods including: serviceReconfigure, serviceRestart, serviceStart, serviceStatus, serviceStop...",
    "module": "plugins",
    "submodule": "zabbixagent",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddAlias",
      "settingsAddUserparameter",
      "settingsDelAlias",
      "settingsDelUserparameter",
      "settingsGet",
      "settingsGetAlias",
      "settingsGetUserparameter",
      "settingsSet",
      "settingsSetAlias",
      "settingsSetUserparameter",
      "settingsToggleAlias",
      "settingsToggleUserparameter"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop",
            "settingsAddAlias",
            "settingsAddUserparameter",
            "settingsDelAlias",
            "settingsDelUserparameter",
            "settingsGet",
            "settingsGetAlias",
            "settingsGetUserparameter",
            "settingsSet",
            "settingsSetAlias",
            "settingsSetUserparameter",
            "settingsToggleAlias",
            "settingsToggleUserparameter"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zabbixproxy_manage",
    "description": "Plugin zabbixproxy management - 7 available methods including: generalGet, generalSet, serviceReconfigure, serviceRestart, serviceStart...",
    "module": "plugins",
    "submodule": "zabbixproxy",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "generalGet",
            "generalSet",
            "serviceReconfigure",
            "serviceRestart",
            "serviceStart",
            "serviceStatus",
            "serviceStop"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "plugin_zerotier_manage",
    "description": "Plugin zerotier management - 10 available methods including: networkAdd, networkDel, networkGet, networkInfo, networkSearch...",
    "module": "plugins",
    "submodule": "zerotier",
    "methods": [
      "networkAdd",
      "networkDel",
      "networkGet",
      "networkInfo",
      "networkSearch",
      "networkSet",
      "networkToggle",
      "settingsGet",
      "settingsSet",
      "settingsStatus"
    ],
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "networkAdd",
            "networkDel",
            "networkGet",
            "networkInfo",
            "networkSearch",
            "networkSet",
            "networkToggle",
            "settingsGet",
            "settingsSet",
            "settingsStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    }
  },
  {
    "name": "backup_manage",
    "module": "backup",
    "description": "backup management - 1 available methods including: backupDownload...",
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "backupDownload"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    },
    "methods": [
      "backupDownload"
    ]
  },
  {
    "name": "hostdiscovery_manage",
    "module": "hostdiscovery",
    "description": "hostdiscovery management - 1 available methods including: serviceSearch...",
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceSearch"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    },
    "methods": [
      "serviceSearch"
    ]
  },
  {
    "name": "ntpd_manage",
    "module": "ntpd",
    "description": "ntpd management - 3 available methods including: serviceGps, serviceMeta, serviceStatus...",
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceGps",
            "serviceMeta",
            "serviceStatus"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    },
    "methods": [
      "serviceGps",
      "serviceMeta",
      "serviceStatus"
    ]
  },
  {
    "name": "radvd_manage",
    "module": "radvd",
    "description": "radvd management - 7 available methods including: serviceReconfigure, settingsAddEntry, settingsDelEntry, settingsGetEntry, settingsSearchEntry...",
    "inputSchema": {
      "type": "object",
      "properties": {
        "method": {
          "type": "string",
          "description": "The method to call on this module",
          "enum": [
            "serviceReconfigure",
            "settingsAddEntry",
            "settingsDelEntry",
            "settingsGetEntry",
            "settingsSearchEntry",
            "settingsSetEntry",
            "settingsToggleEntry"
          ]
        },
        "params": {
          "type": "object",
          "description": "Parameters for the method (varies by method)",
          "properties": {
            "uuid": {
              "type": "string",
              "description": "Item UUID (for get/set/del operations)"
            },
            "data": {
              "type": "object",
              "description": "Configuration data (for set operations)"
            },
            "item": {
              "type": "object",
              "description": "Item data (for add/set operations)"
            },
            "searchPhrase": {
              "type": "string",
              "description": "Search phrase (for search operations)"
            },
            "current": {
              "type": "integer",
              "description": "Current page (for search operations)",
              "default": 1
            },
            "rowCount": {
              "type": "integer",
              "description": "Rows per page (for search operations)",
              "default": 20
            },
            "args": {
              "type": "array",
              "description": "Explicit ordered positional arguments for the underlying client method (escape hatch for signatures not covered by uuid/item/data, e.g. backupDownload[host, backup]). When set, overrides the uuid/body mapping."
            }
          }
        }
      },
      "required": [
        "method"
      ]
    },
    "methods": [
      "serviceReconfigure",
      "settingsAddEntry",
      "settingsDelEntry",
      "settingsGetEntry",
      "settingsSearchEntry",
      "settingsSetEntry",
      "settingsToggleEntry"
    ]
  }
];

// Method documentation for help
const METHOD_DOCS = {
  "core": {
    "toolName": "core_manage",
    "methods": [
      "backupBackups",
      "backupDeleteBackup",
      "backupDiff",
      "backupDownload",
      "backupProviders",
      "backupRevertBackup",
      "dashboardGetDashboard",
      "dashboardPicture",
      "dashboardProductInfoFeed",
      "dashboardRestoreDefaults",
      "dashboardSaveWidgets",
      "hasyncGet",
      "hasyncReconfigure",
      "hasyncSet",
      "hasyncStatusRemoteService",
      "hasyncStatusRestart",
      "hasyncStatusRestartAll",
      "hasyncStatusServices",
      "hasyncStatusStart",
      "hasyncStatusStop",
      "hasyncStatusVersion",
      "menuSearch",
      "menuTree",
      "serviceRestart",
      "serviceSearch",
      "serviceStart",
      "serviceStop",
      "snapshotsActivate",
      "snapshotsAdd",
      "snapshotsDel",
      "snapshotsGet",
      "snapshotsIsSupported",
      "snapshotsSearch",
      "snapshotsSet",
      "systemDismissStatus",
      "systemHalt",
      "systemReboot",
      "systemStatus",
      "tunablesAddItem",
      "tunablesDelItem",
      "tunablesGet",
      "tunablesGetItem",
      "tunablesReconfigure",
      "tunablesReset",
      "tunablesSet",
      "tunablesSetItem"
    ]
  },
  "firewall": {
    "toolName": "firewall_manage",
    "methods": [
      "aliasAddItem",
      "aliasDelItem",
      "aliasGet",
      "aliasGetAliasUUID",
      "aliasGetGeoIP",
      "aliasGetItem",
      "aliasGetTableSize",
      "aliasImport",
      "aliasListCategories",
      "aliasListCountries",
      "aliasListNetworkAliases",
      "aliasListUserGroups",
      "aliasReconfigure",
      "aliasSearchItem",
      "aliasSet",
      "aliasSetItem",
      "aliasToggleItem",
      "aliasUtilAdd",
      "aliasUtilAliases",
      "aliasUtilDelete",
      "aliasUtilFindReferences",
      "aliasUtilFlush",
      "aliasUtilList",
      "aliasUtilUpdateBogons",
      "categoryAddItem",
      "categoryDelItem",
      "categoryGet",
      "categoryGetItem",
      "categorySearchItem",
      "categorySet",
      "categorySetItem",
      "dNatAddRule",
      "dNatApply",
      "dNatDelRule",
      "dNatGet",
      "dNatGetRule",
      "dNatSearchRule",
      "dNatSet",
      "dNatSetRule",
      "dNatToggleRule",
      "filterAddRule",
      "filterBaseApply",
      "filterBaseCancelRollback",
      "filterBaseGet",
      "filterBaseListCategories",
      "filterBaseListNetworkSelectOptions",
      "filterBaseListPortSelectOptions",
      "filterBaseRevert",
      "filterBaseSavepoint",
      "filterBaseSet",
      "filterDelRule",
      "filterFlushInspectCache",
      "filterGetInterfaceList",
      "filterGetRule",
      "filterMoveRuleBefore",
      "filterSearchRule",
      "filterSetRule",
      "filterToggleRule",
      "filterToggleRuleLog",
      "filterUtilRuleStats",
      "groupAddItem",
      "groupDelItem",
      "groupGet",
      "groupGetItem",
      "groupReconfigure",
      "groupSearchItem",
      "groupSet",
      "groupSetItem",
      "nptAddRule",
      "nptApply",
      "nptDelRule",
      "nptGetRule",
      "nptSearchRule",
      "nptSetRule",
      "nptToggleRule",
      "oneToOneAddRule",
      "oneToOneApply",
      "oneToOneDelRule",
      "oneToOneGetRule",
      "oneToOneSearchRule",
      "oneToOneSetRule",
      "oneToOneToggleRule",
      "sourceNatAddRule",
      "sourceNatApply",
      "sourceNatDelRule",
      "sourceNatGetRule",
      "sourceNatSearchRule",
      "sourceNatSetRule",
      "sourceNatToggleRule"
    ]
  },
  "auth": {
    "toolName": "auth_manage",
    "methods": [
      "groupAdd",
      "groupDel",
      "groupGet",
      "groupSet",
      "privGet",
      "privGetItem",
      "privSearch",
      "privSet",
      "privSetItem",
      "userAdd",
      "userAddApiKey",
      "userDel",
      "userDelApiKey",
      "userDownload",
      "userGet",
      "userNewOtpSeed",
      "userSearchApiKey",
      "userSet",
      "userUpload"
    ]
  },
  "interfaces": {
    "toolName": "interfaces_manage",
    "methods": [
      "gifSettingsAddItem",
      "gifSettingsDelItem",
      "gifSettingsGet",
      "gifSettingsGetIfOptions",
      "gifSettingsGetItem",
      "gifSettingsReconfigure",
      "gifSettingsSet",
      "gifSettingsSetItem",
      "greSettingsAddItem",
      "greSettingsDelItem",
      "greSettingsGet",
      "greSettingsGetIfOptions",
      "greSettingsGetItem",
      "greSettingsReconfigure",
      "greSettingsSet",
      "greSettingsSetItem",
      "laggSettingsAddItem",
      "laggSettingsDelItem",
      "laggSettingsGet",
      "laggSettingsGetItem",
      "laggSettingsReconfigure",
      "laggSettingsSet",
      "laggSettingsSetItem",
      "loopbackSettingsAddItem",
      "loopbackSettingsDelItem",
      "loopbackSettingsGet",
      "loopbackSettingsGetItem",
      "loopbackSettingsReconfigure",
      "loopbackSettingsSet",
      "loopbackSettingsSetItem",
      "neighborSettingsAddItem",
      "neighborSettingsDelItem",
      "neighborSettingsGet",
      "neighborSettingsGetItem",
      "neighborSettingsReconfigure",
      "neighborSettingsSet",
      "neighborSettingsSetItem",
      "overviewExport",
      "overviewGetInterface",
      "overviewInterfacesInfo",
      "overviewReloadInterface",
      "vipSettingsAddItem",
      "vipSettingsDelItem",
      "vipSettingsGet",
      "vipSettingsGetItem",
      "vipSettingsGetUnusedVhid",
      "vipSettingsReconfigure",
      "vipSettingsSet",
      "vipSettingsSetItem",
      "vlanSettingsAddItem",
      "vlanSettingsDelItem",
      "vlanSettingsGet",
      "vlanSettingsGetItem",
      "vlanSettingsReconfigure",
      "vlanSettingsSet",
      "vlanSettingsSetItem",
      "vxlanSettingsAddItem",
      "vxlanSettingsDelItem",
      "vxlanSettingsGet",
      "vxlanSettingsGetItem",
      "vxlanSettingsReconfigure",
      "vxlanSettingsSet",
      "vxlanSettingsSetItem"
    ]
  },
  "captiveportal": {
    "toolName": "captiveportal_manage",
    "methods": [
      "accessApi",
      "accessLogoff",
      "accessLogon",
      "serviceDelTemplate",
      "serviceGetTemplate",
      "serviceReconfigure",
      "serviceSaveTemplate",
      "serviceSearchTemplates",
      "sessionConnect",
      "sessionDisconnect",
      "sessionList",
      "sessionSearch",
      "sessionZones",
      "settingsAddZone",
      "settingsDelZone",
      "settingsGet",
      "settingsGetZone",
      "settingsSet",
      "settingsSetZone",
      "settingsToggleZone",
      "voucherDropExpiredVouchers",
      "voucherDropVoucherGroup",
      "voucherExpireVoucher",
      "voucherGenerateVouchers",
      "voucherListProviders",
      "voucherListVoucherGroups",
      "voucherListVouchers"
    ]
  },
  "cron": {
    "toolName": "cron_manage",
    "methods": [
      "serviceReconfigure",
      "settingsAddJob",
      "settingsDelJob",
      "settingsGet",
      "settingsGetJob",
      "settingsSet",
      "settingsSetJob",
      "settingsToggleJob"
    ]
  },
  "dhcpv4": {
    "toolName": "dhcpv4_manage",
    "methods": [
      "leasesDelLease",
      "leasesSearchLease",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "dhcpv6": {
    "toolName": "dhcpv6_manage",
    "methods": [
      "leasesDelLease",
      "leasesSearchLease",
      "leasesSearchPrefix",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "dhcrelay": {
    "toolName": "dhcrelay_manage",
    "methods": [
      "serviceReconfigure",
      "settingsAddDest",
      "settingsAddRelay",
      "settingsDelDest",
      "settingsDelRelay",
      "settingsGet",
      "settingsGetDest",
      "settingsGetRelay",
      "settingsSet",
      "settingsSetDest",
      "settingsSetRelay",
      "settingsToggleRelay"
    ]
  },
  "diagnostics": {
    "toolName": "diagnostics_manage",
    "methods": [
      "activityGetActivity",
      "cpuUsageGetCPUType",
      "cpuUsageStream",
      "dnsReverseLookup",
      "dnsDiagnosticsGet",
      "dnsDiagnosticsSet",
      "firewallDelState",
      "firewallFlushSources",
      "firewallFlushStates",
      "firewallKillStates",
      "firewallListRuleIds",
      "firewallLog",
      "firewallLogFilters",
      "firewallPfStates",
      "firewallPfStatistics",
      "firewallQueryPfTop",
      "firewallQueryStates",
      "firewallStats",
      "firewallStreamLog",
      "interfaceCarpStatus",
      "interfaceDelRoute",
      "interfaceFlushArp",
      "interfaceGetArp",
      "interfaceGetBpfStatistics",
      "interfaceGetInterfaceConfig",
      "interfaceGetInterfaceNames",
      "interfaceGetInterfaceStatistics",
      "interfaceGetMemoryStatistics",
      "interfaceGetNdp",
      "interfaceGetNetisrStatistics",
      "interfaceGetPfsyncNodes",
      "interfaceGetProtocolStatistics",
      "interfaceGetRoutes",
      "interfaceGetSocketStatistics",
      "interfaceGetVipStatus",
      "interfaceSearchArp",
      "interfaceSearchNdp",
      "lvtemplateAddItem",
      "lvtemplateDelItem",
      "lvtemplateGet",
      "lvtemplateGetItem",
      "lvtemplateSet",
      "lvtemplateSetItem",
      "netflowCacheStats",
      "netflowGetconfig",
      "netflowIsEnabled",
      "netflowReconfigure",
      "netflowSetconfig",
      "netflowStatus",
      "networkinsightExport",
      "networkinsightGetInterfaces",
      "networkinsightGetMetadata",
      "networkinsightGetProtocols",
      "networkinsightGetServices",
      "networkinsightTimeserie",
      "networkinsightTop",
      "packetCaptureDownload",
      "packetCaptureGet",
      "packetCaptureMacInfo",
      "packetCaptureRemove",
      "packetCaptureSearchJobs",
      "packetCaptureSet",
      "packetCaptureStart",
      "packetCaptureStop",
      "packetCaptureView",
      "pingGet",
      "pingRemove",
      "pingSearchJobs",
      "pingSet",
      "pingStart",
      "pingStop",
      "portprobeGet",
      "portprobeSet",
      "systemMemory",
      "systemSystemDisk",
      "systemSystemInformation",
      "systemSystemMbuf",
      "systemSystemResources",
      "systemSystemSwap",
      "systemSystemTemperature",
      "systemSystemTime",
      "systemhealthExportAsCSV",
      "systemhealthGetInterfaces",
      "systemhealthGetRRDlist",
      "systemhealthGetSystemHealth",
      "tracerouteGet",
      "tracerouteSet",
      "trafficInterface",
      "trafficTop",
      "trafficStream"
    ]
  },
  "dnsmasq": {
    "toolName": "dnsmasq_manage",
    "methods": [
      "leasesSearch",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddBoot",
      "settingsAddDomain",
      "settingsAddHost",
      "settingsAddOption",
      "settingsAddRange",
      "settingsAddTag",
      "settingsDelBoot",
      "settingsDelDomain",
      "settingsDelHost",
      "settingsDelOption",
      "settingsDelRange",
      "settingsDelTag",
      "settingsDownloadHosts",
      "settingsGet",
      "settingsGetBoot",
      "settingsGetDomain",
      "settingsGetHost",
      "settingsGetOption",
      "settingsGetRange",
      "settingsGetTag",
      "settingsGetTagList",
      "settingsSet",
      "settingsSetBoot",
      "settingsSetDomain",
      "settingsSetHost",
      "settingsSetOption",
      "settingsSetRange",
      "settingsSetTag",
      "settingsUploadHosts"
    ]
  },
  "firmware": {
    "toolName": "firmware_manage",
    "methods": [
      "firmwareAudit",
      "firmwareChangelog",
      "firmwareCheck",
      "firmwareConnection",
      "firmwareGet",
      "firmwareGetOptions",
      "firmwareHealth",
      "firmwareInfo",
      "firmwareLog",
      "firmwarePoweroff",
      "firmwareReboot",
      "firmwareResyncPlugins",
      "firmwareRunning",
      "firmwareSet",
      "firmwareStatus",
      "firmwareSyncPlugins",
      "firmwareUpdate",
      "firmwareUpgrade",
      "firmwareUpgradestatus",
      "firmwareDetails",
      "firmwareInstall",
      "firmwareLicense",
      "firmwareLock",
      "firmwareRemove",
      "firmwareReinstall",
      "firmwareUnlock"
    ]
  },
  "ids": {
    "toolName": "ids_manage",
    "methods": [
      "serviceDropAlertLog",
      "serviceGetAlertInfo",
      "serviceGetAlertLogs",
      "serviceQueryAlerts",
      "serviceReconfigure",
      "serviceReloadRules",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceUpdateRules",
      "settingsAddPolicy",
      "settingsAddPolicyRule",
      "settingsAddUserRule",
      "settingsCheckPolicyRule",
      "settingsDelPolicy",
      "settingsDelPolicyRule",
      "settingsDelUserRule",
      "settingsGet",
      "settingsGetPolicy",
      "settingsGetPolicyRule",
      "settingsGetRuleInfo",
      "settingsGetRuleset",
      "settingsGetRulesetproperties",
      "settingsGetUserRule",
      "settingsListRuleMetadata",
      "settingsListRulesets",
      "settingsSearchInstalledRules",
      "settingsSet",
      "settingsSetPolicy",
      "settingsSetPolicyRule",
      "settingsSetRule",
      "settingsSetRuleset",
      "settingsSetRulesetproperties",
      "settingsSetUserRule",
      "settingsTogglePolicy",
      "settingsTogglePolicyRule",
      "settingsToggleRule",
      "settingsToggleRuleset",
      "settingsToggleUserRule"
    ]
  },
  "ipsec": {
    "toolName": "ipsec_manage",
    "methods": [
      "connectionsAddChild",
      "connectionsAddConnection",
      "connectionsAddLocal",
      "connectionsAddRemote",
      "connectionsConnectionExists",
      "connectionsDelChild",
      "connectionsDelConnection",
      "connectionsDelLocal",
      "connectionsDelRemote",
      "connectionsGet",
      "connectionsGetChild",
      "connectionsGetConnection",
      "connectionsGetLocal",
      "connectionsGetRemote",
      "connectionsIsEnabled",
      "connectionsSet",
      "connectionsSetChild",
      "connectionsSetConnection",
      "connectionsSetLocal",
      "connectionsSetRemote",
      "connectionsSwanctl",
      "connectionsToggle",
      "connectionsToggleChild",
      "connectionsToggleConnection",
      "connectionsToggleLocal",
      "connectionsToggleRemote",
      "keyPairsAddItem",
      "keyPairsDelItem",
      "keyPairsGenKeyPair",
      "keyPairsGet",
      "keyPairsGetItem",
      "keyPairsSet",
      "keyPairsSetItem",
      "leasesPools",
      "leasesSearch",
      "legacySubsystemApplyConfig",
      "legacySubsystemStatus",
      "manualSpdAdd",
      "manualSpdDel",
      "manualSpdGet",
      "manualSpdSet",
      "manualSpdToggle",
      "poolsAdd",
      "poolsDel",
      "poolsGet",
      "poolsSet",
      "poolsToggle",
      "preSharedKeysAddItem",
      "preSharedKeysDelItem",
      "preSharedKeysGet",
      "preSharedKeysGetItem",
      "preSharedKeysSet",
      "preSharedKeysSetItem",
      "sadDelete",
      "sadSearch",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "sessionsConnect",
      "sessionsDisconnect",
      "sessionsSearchPhase1",
      "sessionsSearchPhase2",
      "settingsGet",
      "settingsSet",
      "spdDelete",
      "spdSearch",
      "tunnelDelPhase1",
      "tunnelDelPhase2",
      "tunnelSearchPhase1",
      "tunnelSearchPhase2",
      "tunnelToggle",
      "tunnelTogglePhase1",
      "tunnelTogglePhase2",
      "vtiAdd",
      "vtiDel",
      "vtiGet",
      "vtiSet",
      "vtiToggle"
    ]
  },
  "kea": {
    "toolName": "kea_manage",
    "methods": [
      "ctrlAgentGet",
      "ctrlAgentSet",
      "dhcpv4AddPeer",
      "dhcpv4AddReservation",
      "dhcpv4AddSubnet",
      "dhcpv4DelPeer",
      "dhcpv4DelReservation",
      "dhcpv4DelSubnet",
      "dhcpv4DownloadReservations",
      "dhcpv4Get",
      "dhcpv4GetPeer",
      "dhcpv4GetReservation",
      "dhcpv4GetSubnet",
      "dhcpv4Set",
      "dhcpv4SetPeer",
      "dhcpv4SetReservation",
      "dhcpv4SetSubnet",
      "dhcpv4UploadReservations",
      "leases4Search",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "monit": {
    "toolName": "monit_manage",
    "methods": [
      "serviceCheck",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddAlert",
      "settingsAddService",
      "settingsAddTest",
      "settingsDelAlert",
      "settingsDelService",
      "settingsDelTest",
      "settingsDirty",
      "settingsGet",
      "settingsGetAlert",
      "settingsGetGeneral",
      "settingsGetService",
      "settingsGetTest",
      "settingsSet",
      "settingsSetAlert",
      "settingsSetService",
      "settingsSetTest",
      "settingsToggleAlert",
      "settingsToggleService",
      "statusGet"
    ]
  },
  "openvpn": {
    "toolName": "openvpn_manage",
    "methods": [
      "clientOverwritesAdd",
      "clientOverwritesDel",
      "clientOverwritesGet",
      "clientOverwritesSet",
      "clientOverwritesToggle",
      "exportAccounts",
      "exportDownload",
      "exportProviders",
      "exportStorePresets",
      "exportTemplates",
      "exportValidatePresets",
      "instancesAdd",
      "instancesAddStaticKey",
      "instancesDel",
      "instancesDelStaticKey",
      "instancesGenKey",
      "instancesGet",
      "instancesGetStaticKey",
      "instancesSet",
      "instancesSetStaticKey",
      "instancesToggle",
      "serviceKillSession",
      "serviceReconfigure",
      "serviceRestartService",
      "serviceSearchRoutes",
      "serviceSearchSessions",
      "serviceStartService",
      "serviceStopService"
    ]
  },
  "routes": {
    "toolName": "routes_manage",
    "methods": [
      "gatewayStatus",
      "routesAddroute",
      "routesDelroute",
      "routesGet",
      "routesGetroute",
      "routesReconfigure",
      "routesSet",
      "routesSetroute",
      "routesToggleroute"
    ]
  },
  "routing": {
    "toolName": "routing_manage",
    "methods": [
      "settingsAddGateway",
      "settingsDelGateway",
      "settingsGet",
      "settingsGetGateway",
      "settingsReconfigure",
      "settingsSearchGateway",
      "settingsSet",
      "settingsSetGateway",
      "settingsToggleGateway"
    ]
  },
  "syslog": {
    "toolName": "syslog_manage",
    "methods": [
      "serviceReconfigure",
      "serviceReset",
      "serviceRestart",
      "serviceStart",
      "serviceStats",
      "serviceStatus",
      "serviceStop",
      "settingsAddDestination",
      "settingsDelDestination",
      "settingsGet",
      "settingsGetDestination",
      "settingsSet",
      "settingsSetDestination",
      "settingsToggleDestination"
    ]
  },
  "trafficshaper": {
    "toolName": "trafficshaper_manage",
    "methods": [
      "serviceFlushreload",
      "serviceReconfigure",
      "serviceStatistics",
      "settingsAddPipe",
      "settingsAddQueue",
      "settingsAddRule",
      "settingsDelPipe",
      "settingsDelQueue",
      "settingsDelRule",
      "settingsGet",
      "settingsGetPipe",
      "settingsGetQueue",
      "settingsGetRule",
      "settingsSet",
      "settingsSetPipe",
      "settingsSetQueue",
      "settingsSetRule",
      "settingsTogglePipe",
      "settingsToggleQueue",
      "settingsToggleRule"
    ]
  },
  "trust": {
    "toolName": "trust_manage",
    "methods": [
      "caCaInfo",
      "caCaList",
      "caDel",
      "caGenerateFile",
      "caGet",
      "caRawDump",
      "caSet",
      "certAdd",
      "certCaInfo",
      "certCaList",
      "certDel",
      "certGenerateFile",
      "certGet",
      "certRawDump",
      "certSet",
      "certUserList",
      "crlDel",
      "crlGet",
      "crlGetOcspInfoData",
      "crlRawDump",
      "crlSearch",
      "crlSet",
      "settingsGet",
      "settingsReconfigure",
      "settingsSet"
    ]
  },
  "unbound": {
    "toolName": "unbound_manage",
    "methods": [
      "diagnosticsDumpcache",
      "diagnosticsDumpinfra",
      "diagnosticsListinsecure",
      "diagnosticsListlocaldata",
      "diagnosticsListlocalzones",
      "diagnosticsStats",
      "overviewRolling",
      "overviewIsBlockListEnabled",
      "overviewIsEnabled",
      "overviewSearchQueries",
      "overviewTotals",
      "serviceDnsbl",
      "serviceReconfigure",
      "serviceReconfigureGeneral",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddAcl",
      "settingsAddForward",
      "settingsAddHostAlias",
      "settingsAddHostOverride",
      "settingsDelAcl",
      "settingsDelForward",
      "settingsDelHostAlias",
      "settingsDelHostOverride",
      "settingsGet",
      "settingsGetAcl",
      "settingsGetForward",
      "settingsGetHostAlias",
      "settingsGetHostOverride",
      "settingsGetNameservers",
      "settingsSet",
      "settingsSetAcl",
      "settingsSetForward",
      "settingsSetHostAlias",
      "settingsSetHostOverride",
      "settingsToggleAcl",
      "settingsToggleForward",
      "settingsToggleHostAlias",
      "settingsToggleHostOverride",
      "settingsUpdateBlocklist"
    ]
  },
  "wireguard": {
    "toolName": "wireguard_manage",
    "methods": [
      "clientAddClient",
      "clientAddClientBuilder",
      "clientDelClient",
      "clientGet",
      "clientGetClient",
      "clientGetClientBuilder",
      "clientGetServerInfo",
      "clientListServers",
      "clientPsk",
      "clientSet",
      "clientSetClient",
      "clientToggleClient",
      "generalGet",
      "generalSet",
      "serverAddServer",
      "serverDelServer",
      "serverGet",
      "serverGetServer",
      "serverKeyPair",
      "serverSet",
      "serverSetServer",
      "serverToggleServer",
      "serviceReconfigure",
      "serviceRestart",
      "serviceShow",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.acmeclient": {
    "toolName": "plugin_acmeclient_manage",
    "methods": [
      "accountsAdd",
      "accountsDel",
      "accountsGet",
      "accountsRegister",
      "accountsSet",
      "accountsToggle",
      "accountsUpdate",
      "actionsAdd",
      "actionsDel",
      "actionsGet",
      "actionsSet",
      "actionsSftpGetIdentity",
      "actionsSftpTestConnection",
      "actionsSshGetIdentity",
      "actionsSshTestConnection",
      "actionsToggle",
      "actionsUpdate",
      "certificatesAdd",
      "certificatesAutomation",
      "certificatesDel",
      "certificatesGet",
      "certificatesImport",
      "certificatesRemovekey",
      "certificatesRevoke",
      "certificatesSet",
      "certificatesSign",
      "certificatesToggle",
      "certificatesUpdate",
      "serviceConfigtest",
      "serviceReconfigure",
      "serviceReset",
      "serviceRestart",
      "serviceSignallcerts",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsFetchCronIntegration",
      "settingsFetchHAProxyIntegration",
      "settingsGet",
      "settingsGetBindPluginStatus",
      "settingsGetGcloudPluginStatus",
      "settingsSet",
      "validationsAdd",
      "validationsDel",
      "validationsGet",
      "validationsSet",
      "validationsToggle",
      "validationsUpdate"
    ]
  },
  "plugins.apcupsd": {
    "toolName": "plugin_apcupsd_manage",
    "methods": [
      "serviceGetUpsStatus",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.bind": {
    "toolName": "plugin_bind_manage",
    "methods": [
      "aclAddAcl",
      "aclDelAcl",
      "aclGet",
      "aclGetAcl",
      "aclSet",
      "aclSetAcl",
      "aclToggleAcl",
      "dnsblGet",
      "dnsblSet",
      "domainAddPrimaryDomain",
      "domainAddSecondaryDomain",
      "domainDelDomain",
      "domainGet",
      "domainGetDomain",
      "domainSearchMasterDomain",
      "domainSearchSlaveDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalGet",
      "generalSet",
      "generalZoneshow",
      "generalZonetest",
      "recordAddRecord",
      "recordDelRecord",
      "recordGet",
      "recordGetRecord",
      "recordSet",
      "recordSetRecord",
      "recordToggleRecord",
      "serviceDnsbl",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.caddy": {
    "toolName": "plugin_caddy_manage",
    "methods": [
      "diagnosticsCaddyfile",
      "diagnosticsConfig",
      "diagnosticsGet",
      "diagnosticsSet",
      "generalGet",
      "generalSet",
      "reverseProxyAddAccessList",
      "reverseProxyAddBasicAuth",
      "reverseProxyAddHandle",
      "reverseProxyAddHeader",
      "reverseProxyAddLayer4",
      "reverseProxyAddLayer4Openvpn",
      "reverseProxyAddReverseProxy",
      "reverseProxyAddSubdomain",
      "reverseProxyDelAccessList",
      "reverseProxyDelBasicAuth",
      "reverseProxyDelHandle",
      "reverseProxyDelHeader",
      "reverseProxyDelLayer4",
      "reverseProxyDelLayer4Openvpn",
      "reverseProxyDelReverseProxy",
      "reverseProxyDelSubdomain",
      "reverseProxyGet",
      "reverseProxyGetAccessList",
      "reverseProxyGetAllReverseDomains",
      "reverseProxyGetBasicAuth",
      "reverseProxyGetHandle",
      "reverseProxyGetHeader",
      "reverseProxyGetLayer4",
      "reverseProxyGetLayer4Openvpn",
      "reverseProxyGetReverseProxy",
      "reverseProxyGetSubdomain",
      "reverseProxySet",
      "reverseProxySetAccessList",
      "reverseProxySetBasicAuth",
      "reverseProxySetHandle",
      "reverseProxySetHeader",
      "reverseProxySetLayer4",
      "reverseProxySetLayer4Openvpn",
      "reverseProxySetReverseProxy",
      "reverseProxySetSubdomain",
      "reverseProxyToggleHandle",
      "reverseProxyToggleLayer4",
      "reverseProxyToggleLayer4Openvpn",
      "reverseProxyToggleReverseProxy",
      "reverseProxyToggleSubdomain",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceValidate"
    ]
  },
  "plugins.chrony": {
    "toolName": "plugin_chrony_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceChronyauthdata",
      "serviceChronysources",
      "serviceChronysourcestats",
      "serviceChronytracking",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.cicap": {
    "toolName": "plugin_cicap_manage",
    "methods": [
      "antivirusGet",
      "antivirusSet",
      "generalGet",
      "generalSet",
      "serviceCheckclamav",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.clamav": {
    "toolName": "plugin_clamav_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceFreshclam",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceVersion",
      "urlAddUrl",
      "urlDelUrl",
      "urlGet",
      "urlGetUrl",
      "urlSet",
      "urlSetUrl",
      "urlToggleUrl"
    ]
  },
  "plugins.collectd": {
    "toolName": "plugin_collectd_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.crowdsec": {
    "toolName": "plugin_crowdsec_manage",
    "methods": [
      "alertsGet",
      "bouncersGet",
      "decisionsDelete",
      "decisionsGet",
      "generalGet",
      "generalSet",
      "hubGet",
      "machinesGet",
      "serviceDebug",
      "serviceReload",
      "serviceStatus",
      "versionGet"
    ]
  },
  "plugins.dechw": {
    "toolName": "plugin_dechw_manage",
    "methods": [
      "infoPowerStatus"
    ]
  },
  "plugins.diagnostics": {
    "toolName": "plugin_diagnostics_manage",
    "methods": [
      "proofpointEtStatus"
    ]
  },
  "plugins.dmidecode": {
    "toolName": "plugin_dmidecode_manage",
    "methods": [
      "serviceGet"
    ]
  },
  "plugins.dnscryptproxy": {
    "toolName": "plugin_dnscryptproxy_manage",
    "methods": [
      "cloakAddCloak",
      "cloakDelCloak",
      "cloakGet",
      "cloakGetCloak",
      "cloakSet",
      "cloakSetCloak",
      "cloakToggleCloak",
      "dnsblGet",
      "dnsblSet",
      "forwardAddForward",
      "forwardDelForward",
      "forwardGet",
      "forwardGetForward",
      "forwardSet",
      "forwardSetForward",
      "forwardToggleForward",
      "generalGet",
      "generalSet",
      "serverAddServer",
      "serverDelServer",
      "serverGet",
      "serverGetServer",
      "serverSet",
      "serverSetServer",
      "serverToggleServer",
      "serviceDnsbl",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "whitelistAddWhitelist",
      "whitelistDelWhitelist",
      "whitelistGet",
      "whitelistGetWhitelist",
      "whitelistSet",
      "whitelistSetWhitelist",
      "whitelistToggleWhitelist"
    ]
  },
  "plugins.dyndns": {
    "toolName": "plugin_dyndns_manage",
    "methods": [
      "accountsAddItem",
      "accountsDelItem",
      "accountsGet",
      "accountsGetItem",
      "accountsSet",
      "accountsSetItem",
      "accountsToggleItem",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.freeradius": {
    "toolName": "plugin_freeradius_manage",
    "methods": [
      "avpairAddAvpair",
      "avpairDelAvpair",
      "avpairGet",
      "avpairGetAvpair",
      "avpairSet",
      "avpairSetAvpair",
      "avpairToggleAvpair",
      "clientAddClient",
      "clientDelClient",
      "clientGet",
      "clientGetClient",
      "clientSearchClient",
      "clientSet",
      "clientSetClient",
      "clientToggleClient",
      "dhcpAddDhcp",
      "dhcpDelDhcp",
      "dhcpGet",
      "dhcpGetDhcp",
      "dhcpSet",
      "dhcpSetDhcp",
      "dhcpToggleDhcp",
      "eapGet",
      "eapSet",
      "generalGet",
      "generalSet",
      "ldapGet",
      "ldapSet",
      "leaseAddLease",
      "leaseDelLease",
      "leaseGet",
      "leaseGetLease",
      "leaseSet",
      "leaseSetLease",
      "leaseToggleLease",
      "proxyAddHomeserver",
      "proxyAddHomeserverpool",
      "proxyAddRealm",
      "proxyDelHomeserver",
      "proxyDelHomeserverpool",
      "proxyDelRealm",
      "proxyGet",
      "proxyGetHomeserver",
      "proxyGetHomeserverpool",
      "proxyGetRealm",
      "proxySearchHomeserver",
      "proxySearchHomeserverpool",
      "proxySearchRealm",
      "proxySet",
      "proxySetHomeserver",
      "proxySetHomeserverpool",
      "proxySetRealm",
      "proxyToggleHomeserver",
      "proxyToggleHomeserverpool",
      "proxyToggleRealm",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userGet",
      "userGetUser",
      "userSearchUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ]
  },
  "plugins.ftpproxy": {
    "toolName": "plugin_ftpproxy_manage",
    "methods": [
      "serviceConfig",
      "serviceReload",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddProxy",
      "settingsDelProxy",
      "settingsGetProxy",
      "settingsSearchProxy",
      "settingsSetProxy",
      "settingsToggleProxy"
    ]
  },
  "plugins.gridexample": {
    "toolName": "plugin_gridexample_manage",
    "methods": [
      "settingsAddItem",
      "settingsDelItem",
      "settingsGet",
      "settingsGetItem",
      "settingsSet",
      "settingsSetItem",
      "settingsToggleItem"
    ]
  },
  "plugins.haproxy": {
    "toolName": "plugin_haproxy_manage",
    "methods": [
      "exportConfig",
      "exportDiff",
      "exportDownload",
      "maintenanceCertActions",
      "maintenanceCertDiff",
      "maintenanceCertSync",
      "maintenanceCertSyncBulk",
      "maintenanceFetchCronIntegration",
      "maintenanceGet",
      "maintenanceSearchCertificateDiff",
      "maintenanceSearchServer",
      "maintenanceServerState",
      "maintenanceServerStateBulk",
      "maintenanceServerWeight",
      "maintenanceServerWeightBulk",
      "maintenanceSet",
      "serviceConfigtest",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddAcl",
      "settingsAddAction",
      "settingsAddBackend",
      "settingsAddCpu",
      "settingsAddErrorfile",
      "settingsAddFcgi",
      "settingsAddFrontend",
      "settingsAddGroup",
      "settingsAddHealthcheck",
      "settingsAddLua",
      "settingsAddMapfile",
      "settingsAddServer",
      "settingsAddUser",
      "settingsAddmailer",
      "settingsAddresolver",
      "settingsDelAcl",
      "settingsDelAction",
      "settingsDelBackend",
      "settingsDelCpu",
      "settingsDelErrorfile",
      "settingsDelFcgi",
      "settingsDelFrontend",
      "settingsDelGroup",
      "settingsDelHealthcheck",
      "settingsDelLua",
      "settingsDelMapfile",
      "settingsDelServer",
      "settingsDelUser",
      "settingsDelmailer",
      "settingsDelresolver",
      "settingsGet",
      "settingsGetAcl",
      "settingsGetAction",
      "settingsGetBackend",
      "settingsGetCpu",
      "settingsGetErrorfile",
      "settingsGetFcgi",
      "settingsGetFrontend",
      "settingsGetGroup",
      "settingsGetHealthcheck",
      "settingsGetLua",
      "settingsGetMapfile",
      "settingsGetServer",
      "settingsGetUser",
      "settingsGetmailer",
      "settingsGetresolver",
      "settingsSet",
      "settingsSetAcl",
      "settingsSetAction",
      "settingsSetBackend",
      "settingsSetCpu",
      "settingsSetErrorfile",
      "settingsSetFcgi",
      "settingsSetFrontend",
      "settingsSetGroup",
      "settingsSetHealthcheck",
      "settingsSetLua",
      "settingsSetMapfile",
      "settingsSetServer",
      "settingsSetUser",
      "settingsSetmailer",
      "settingsSetresolver",
      "settingsToggleBackend",
      "settingsToggleCpu",
      "settingsToggleFrontend",
      "settingsToggleGroup",
      "settingsToggleLua",
      "settingsToggleServer",
      "settingsToggleUser",
      "settingsTogglemailer",
      "settingsToggleresolver",
      "statisticsCounters",
      "statisticsInfo",
      "statisticsTables"
    ]
  },
  "plugins.helloworld": {
    "toolName": "plugin_helloworld_manage",
    "methods": [
      "serviceReload",
      "serviceTest",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.hwprobe": {
    "toolName": "plugin_hwprobe_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceReport",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.iperf": {
    "toolName": "plugin_iperf_manage",
    "methods": [
      "instanceGet",
      "instanceQuery",
      "instanceSet",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.lldpd": {
    "toolName": "plugin_lldpd_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceNeighbor",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.maltrail": {
    "toolName": "plugin_maltrail_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "sensorGet",
      "sensorSet",
      "serverGet",
      "serverSet",
      "serverserviceReconfigure",
      "serverserviceRestart",
      "serverserviceStart",
      "serverserviceStatus",
      "serverserviceStop",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.mdnsrepeater": {
    "toolName": "plugin_mdnsrepeater_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.muninnode": {
    "toolName": "plugin_muninnode_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.ndproxy": {
    "toolName": "plugin_ndproxy_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.netdata": {
    "toolName": "plugin_netdata_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.netsnmp": {
    "toolName": "plugin_netsnmp_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userGet",
      "userGetUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ]
  },
  "plugins.nginx": {
    "toolName": "plugin_nginx_manage",
    "methods": [
      "bansDelban",
      "bansGet",
      "bansSet",
      "logsAccesses",
      "logsErrors",
      "logsStreamaccesses",
      "logsStreamerrors",
      "logsTlsHandshakes",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceVts",
      "settingsAddcachePath",
      "settingsAddcredential",
      "settingsAddcustompolicy",
      "settingsAdderrorpage",
      "settingsAddhttprewrite",
      "settingsAddhttpserver",
      "settingsAddipacl",
      "settingsAddlimitRequestConnection",
      "settingsAddlimitZone",
      "settingsAddlocation",
      "settingsAddnaxsirule",
      "settingsAddresolver",
      "settingsAddsecurityHeader",
      "settingsAddsnifwd",
      "settingsAddstreamserver",
      "settingsAddsyslogTarget",
      "settingsAddtlsFingerprint",
      "settingsAddupstream",
      "settingsAddupstreamserver",
      "settingsAdduserlist",
      "settingsDelcachePath",
      "settingsDelcredential",
      "settingsDelcustompolicy",
      "settingsDelerrorpage",
      "settingsDelhttprewrite",
      "settingsDelhttpserver",
      "settingsDelipacl",
      "settingsDellimitRequestConnection",
      "settingsDellimitZone",
      "settingsDellocation",
      "settingsDelnaxsirule",
      "settingsDelresolver",
      "settingsDelsecurityHeader",
      "settingsDelsnifwd",
      "settingsDelstreamserver",
      "settingsDelsyslogTarget",
      "settingsDeltlsFingerprint",
      "settingsDelupstream",
      "settingsDelupstreamserver",
      "settingsDeluserlist",
      "settingsDownloadrules",
      "settingsGet",
      "settingsGetcachePath",
      "settingsGetcredential",
      "settingsGetcustompolicy",
      "settingsGeterrorpage",
      "settingsGethttprewrite",
      "settingsGethttpserver",
      "settingsGetipacl",
      "settingsGetlimitRequestConnection",
      "settingsGetlimitZone",
      "settingsGetlocation",
      "settingsGetnaxsirule",
      "settingsGetresolver",
      "settingsGetsecurityHeader",
      "settingsGetsnifwd",
      "settingsGetstreamserver",
      "settingsGetsyslogTarget",
      "settingsGettlsFingerprint",
      "settingsGetupstream",
      "settingsGetupstreamserver",
      "settingsGetuserlist",
      "settingsSet",
      "settingsSetcachePath",
      "settingsSetcredential",
      "settingsSetcustompolicy",
      "settingsSeterrorpage",
      "settingsSethttprewrite",
      "settingsSethttpserver",
      "settingsSetipacl",
      "settingsSetlimitRequestConnection",
      "settingsSetlimitZone",
      "settingsSetlocation",
      "settingsSetnaxsirule",
      "settingsSetresolver",
      "settingsSetsecurityHeader",
      "settingsSetsnifwd",
      "settingsSetstreamserver",
      "settingsSetsyslogTarget",
      "settingsSettlsFingerprint",
      "settingsSetupstream",
      "settingsSetupstreamserver",
      "settingsSetuserlist",
      "settingsShowconfig",
      "settingsTestconfig"
    ]
  },
  "plugins.nodeexporter": {
    "toolName": "plugin_nodeexporter_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.nrpe": {
    "toolName": "plugin_nrpe_manage",
    "methods": [
      "commandAddCommand",
      "commandDelCommand",
      "commandGet",
      "commandGetCommand",
      "commandSet",
      "commandSetCommand",
      "commandToggleCommand",
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.ntopng": {
    "toolName": "plugin_ntopng_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceCheckredis",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.nut": {
    "toolName": "plugin_nut_manage",
    "methods": [
      "diagnosticsUpsstatus",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.openconnect": {
    "toolName": "plugin_openconnect_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.postfix": {
    "toolName": "plugin_postfix_manage",
    "methods": [
      "addressAddAddress",
      "addressDelAddress",
      "addressGet",
      "addressGetAddress",
      "addressSet",
      "addressSetAddress",
      "addressToggleAddress",
      "antispamGet",
      "antispamSet",
      "domainAddDomain",
      "domainDelDomain",
      "domainGet",
      "domainGetDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalGet",
      "generalSet",
      "headerchecksAddHeadercheck",
      "headerchecksDelHeadercheck",
      "headerchecksGet",
      "headerchecksGetHeadercheck",
      "headerchecksSet",
      "headerchecksSetHeadercheck",
      "headerchecksToggleHeadercheck",
      "recipientAddRecipient",
      "recipientDelRecipient",
      "recipientGet",
      "recipientGetRecipient",
      "recipientSet",
      "recipientSetRecipient",
      "recipientToggleRecipient",
      "recipientbccAddRecipientbcc",
      "recipientbccDelRecipientbcc",
      "recipientbccGet",
      "recipientbccGetRecipientbcc",
      "recipientbccSet",
      "recipientbccSetRecipientbcc",
      "recipientbccToggleRecipientbcc",
      "senderAddSender",
      "senderDelSender",
      "senderGet",
      "senderGetSender",
      "senderSet",
      "senderSetSender",
      "senderToggleSender",
      "senderbccAddSenderbcc",
      "senderbccDelSenderbcc",
      "senderbccGet",
      "senderbccGetSenderbcc",
      "senderbccSet",
      "senderbccSetSenderbcc",
      "senderbccToggleSenderbcc",
      "sendercanonicalAddSendercanonical",
      "sendercanonicalDelSendercanonical",
      "sendercanonicalGet",
      "sendercanonicalGetSendercanonical",
      "sendercanonicalSet",
      "sendercanonicalSetSendercanonical",
      "sendercanonicalToggleSendercanonical",
      "serviceCheckrspamd",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.proxy": {
    "toolName": "plugin_proxy_manage",
    "methods": [
      "serviceDownloadacls",
      "serviceFetchacls",
      "serviceReconfigure",
      "serviceRefreshTemplate",
      "serviceReset",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddPACMatch",
      "settingsAddPACProxy",
      "settingsAddPACRule",
      "settingsAddRemoteBlacklist",
      "settingsDelPACMatch",
      "settingsDelPACProxy",
      "settingsDelPACRule",
      "settingsDelRemoteBlacklist",
      "settingsFetchRBCron",
      "settingsGet",
      "settingsGetPACMatch",
      "settingsGetPACProxy",
      "settingsGetPACRule",
      "settingsGetRemoteBlacklist",
      "settingsSearchRemoteBlacklists",
      "settingsSet",
      "settingsSetPACMatch",
      "settingsSetPACProxy",
      "settingsSetPACRule",
      "settingsSetRemoteBlacklist",
      "settingsTogglePACRule",
      "settingsToggleRemoteBlacklist",
      "templateGet",
      "templateReset",
      "templateSet",
      "aclAddCustomPolicy",
      "aclAddPolicy",
      "aclApply",
      "aclDelCustomPolicy",
      "aclDelPolicy",
      "aclGet",
      "aclGetCustomPolicy",
      "aclGetPolicy",
      "aclSet",
      "aclSetCustomPolicy",
      "aclSetPolicy",
      "aclTest",
      "aclToggleCustomPolicy",
      "aclTogglePolicy"
    ]
  },
  "plugins.proxysso": {
    "toolName": "plugin_proxysso_manage",
    "methods": [
      "serviceCreatekeytab",
      "serviceDeletekeytab",
      "serviceGetCheckList",
      "serviceShowkeytab",
      "serviceTestkerblogin",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.puppetagent": {
    "toolName": "plugin_puppetagent_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.qemuguestagent": {
    "toolName": "plugin_qemuguestagent_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.quagga": {
    "toolName": "plugin_quagga_manage",
    "methods": [
      "bfdAddNeighbor",
      "bfdDelNeighbor",
      "bfdGet",
      "bfdGetNeighbor",
      "bfdSet",
      "bfdSetNeighbor",
      "bfdToggleNeighbor",
      "bgpAddAspath",
      "bgpAddCommunitylist",
      "bgpAddNeighbor",
      "bgpAddPeergroup",
      "bgpAddPrefixlist",
      "bgpAddRedistribution",
      "bgpAddRoutemap",
      "bgpDelAspath",
      "bgpDelCommunitylist",
      "bgpDelNeighbor",
      "bgpDelPeergroup",
      "bgpDelPrefixlist",
      "bgpDelRedistribution",
      "bgpDelRoutemap",
      "bgpGet",
      "bgpGetAspath",
      "bgpGetCommunitylist",
      "bgpGetNeighbor",
      "bgpGetPeergroup",
      "bgpGetPrefixlist",
      "bgpGetRedistribution",
      "bgpGetRoutemap",
      "bgpSet",
      "bgpSetAspath",
      "bgpSetCommunitylist",
      "bgpSetNeighbor",
      "bgpSetPeergroup",
      "bgpSetPrefixlist",
      "bgpSetRedistribution",
      "bgpSetRoutemap",
      "bgpToggleAspath",
      "bgpToggleCommunitylist",
      "bgpToggleNeighbor",
      "bgpTogglePeergroup",
      "bgpTogglePrefixlist",
      "bgpToggleRedistribution",
      "bgpToggleRoutemap",
      "diagnosticsBfdcounters",
      "diagnosticsBfdneighbors",
      "diagnosticsBfdsummary",
      "diagnosticsBgpneighbors",
      "diagnosticsBgpsummary",
      "diagnosticsGeneralrunningconfig",
      "diagnosticsOspfdatabase",
      "diagnosticsOspfinterface",
      "diagnosticsOspfoverview",
      "diagnosticsOspfv3interface",
      "diagnosticsOspfv3overview",
      "diagnosticsSearchBgproute4",
      "diagnosticsSearchBgproute6",
      "diagnosticsSearchGeneralroute4",
      "diagnosticsSearchGeneralroute6",
      "diagnosticsSearchOspfneighbor",
      "diagnosticsSearchOspfroute",
      "diagnosticsSearchOspfv3database",
      "diagnosticsSearchOspfv3route",
      "generalGet",
      "generalSet",
      "ospf6settingsAddInterface",
      "ospf6settingsAddNetwork",
      "ospf6settingsAddPrefixlist",
      "ospf6settingsAddRedistribution",
      "ospf6settingsAddRoutemap",
      "ospf6settingsDelInterface",
      "ospf6settingsDelNetwork",
      "ospf6settingsDelPrefixlist",
      "ospf6settingsDelRedistribution",
      "ospf6settingsDelRoutemap",
      "ospf6settingsGet",
      "ospf6settingsGetInterface",
      "ospf6settingsGetNetwork",
      "ospf6settingsGetPrefixlist",
      "ospf6settingsGetRedistribution",
      "ospf6settingsGetRoutemap",
      "ospf6settingsSet",
      "ospf6settingsSetInterface",
      "ospf6settingsSetNetwork",
      "ospf6settingsSetPrefixlist",
      "ospf6settingsSetRedistribution",
      "ospf6settingsSetRoutemap",
      "ospf6settingsToggleInterface",
      "ospf6settingsToggleNetwork",
      "ospf6settingsTogglePrefixlist",
      "ospf6settingsToggleRedistribution",
      "ospf6settingsToggleRoutemap",
      "ospfsettingsAddInterface",
      "ospfsettingsAddNetwork",
      "ospfsettingsAddPrefixlist",
      "ospfsettingsAddRedistribution",
      "ospfsettingsAddRoutemap",
      "ospfsettingsDelInterface",
      "ospfsettingsDelNetwork",
      "ospfsettingsDelPrefixlist",
      "ospfsettingsDelRedistribution",
      "ospfsettingsDelRoutemap",
      "ospfsettingsGet",
      "ospfsettingsGetInterface",
      "ospfsettingsGetNetwork",
      "ospfsettingsGetPrefixlist",
      "ospfsettingsGetRedistribution",
      "ospfsettingsGetRoutemap",
      "ospfsettingsSet",
      "ospfsettingsSetInterface",
      "ospfsettingsSetNetwork",
      "ospfsettingsSetPrefixlist",
      "ospfsettingsSetRedistribution",
      "ospfsettingsSetRoutemap",
      "ospfsettingsToggleInterface",
      "ospfsettingsToggleNetwork",
      "ospfsettingsTogglePrefixlist",
      "ospfsettingsToggleRedistribution",
      "ospfsettingsToggleRoutemap",
      "ripGet",
      "ripSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "staticAddRoute",
      "staticDelRoute",
      "staticGet",
      "staticGetRoute",
      "staticSet",
      "staticSetRoute",
      "staticToggleRoute"
    ]
  },
  "plugins.radsecproxy": {
    "toolName": "plugin_radsecproxy_manage",
    "methods": [
      "clientsAddItem",
      "clientsDelItem",
      "clientsGet",
      "clientsGetItem",
      "clientsSet",
      "clientsSetItem",
      "clientsToggleItem",
      "generalGet",
      "generalSet",
      "realmsAddItem",
      "realmsDelItem",
      "realmsGet",
      "realmsGetItem",
      "realmsSet",
      "realmsSetItem",
      "realmsToggleItem",
      "rewritesAddItem",
      "rewritesDelItem",
      "rewritesGet",
      "rewritesGetItem",
      "rewritesSet",
      "rewritesSetItem",
      "rewritesToggleItem",
      "serversAddItem",
      "serversDelItem",
      "serversGet",
      "serversGetItem",
      "serversSet",
      "serversSetItem",
      "serversToggleItem",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "tlsAddItem",
      "tlsDelItem",
      "tlsGet",
      "tlsGetItem",
      "tlsSet",
      "tlsSetItem",
      "tlsToggleItem"
    ]
  },
  "plugins.redis": {
    "toolName": "plugin_redis_manage",
    "methods": [
      "serviceReconfigure",
      "serviceResetdb",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.relayd": {
    "toolName": "plugin_relayd_manage",
    "methods": [
      "serviceConfigtest",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsDel",
      "settingsDirty",
      "settingsGet",
      "settingsSearch",
      "settingsSet",
      "settingsToggle",
      "statusSum",
      "statusToggle"
    ]
  },
  "plugins.rspamd": {
    "toolName": "plugin_rspamd_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.shadowsocks": {
    "toolName": "plugin_shadowsocks_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "localGet",
      "localSet",
      "localserviceReconfigure",
      "localserviceRestart",
      "localserviceStart",
      "localserviceStatus",
      "localserviceStop",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.siproxd": {
    "toolName": "plugin_siproxd_manage",
    "methods": [
      "domainAddDomain",
      "domainDelDomain",
      "domainGet",
      "domainGetDomain",
      "domainSearchDomain",
      "domainSet",
      "domainSetDomain",
      "domainToggleDomain",
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceShowregistrations",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "userAddUser",
      "userDelUser",
      "userGet",
      "userGetUser",
      "userSearchUser",
      "userSet",
      "userSetUser",
      "userToggleUser"
    ]
  },
  "plugins.smart": {
    "toolName": "plugin_smart_manage",
    "methods": [
      "serviceAbort",
      "serviceInfo",
      "serviceList",
      "serviceLogs",
      "serviceTest"
    ]
  },
  "plugins.softether": {
    "toolName": "plugin_softether_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.sslh": {
    "toolName": "plugin_sslh_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsIndex",
      "settingsSet"
    ]
  },
  "plugins.stunnel": {
    "toolName": "plugin_stunnel_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "servicesAddItem",
      "servicesDelItem",
      "servicesGet",
      "servicesGetItem",
      "servicesSet",
      "servicesSetItem",
      "servicesToggleItem"
    ]
  },
  "plugins.tailscale": {
    "toolName": "plugin_tailscale_manage",
    "methods": [
      "authenticationGet",
      "authenticationSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddSubnet",
      "settingsDelSubnet",
      "settingsGet",
      "settingsGetSubnet",
      "settingsReload",
      "settingsSet",
      "settingsSetSubnet",
      "statusGet",
      "statusIp",
      "statusNet",
      "statusSet",
      "status"
    ]
  },
  "plugins.tayga": {
    "toolName": "plugin_tayga_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.telegraf": {
    "toolName": "plugin_telegraf_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "inputGet",
      "inputSet",
      "keyAddKey",
      "keyDelKey",
      "keyGet",
      "keyGetKey",
      "keySet",
      "keySetKey",
      "keyToggleKey",
      "outputGet",
      "outputSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.tftp": {
    "toolName": "plugin_tftp_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.tinc": {
    "toolName": "plugin_tinc_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStop",
      "settingsDelHost",
      "settingsDelNetwork",
      "settingsGet",
      "settingsGetHost",
      "settingsGetNetwork",
      "settingsSearchHost",
      "settingsSearchNetwork",
      "settingsSet",
      "settingsSetHost",
      "settingsSetNetwork",
      "settingsToggleHost",
      "settingsToggleNetwork"
    ]
  },
  "plugins.tor": {
    "toolName": "plugin_tor_manage",
    "methods": [
      "exitaclAddacl",
      "exitaclDelacl",
      "exitaclGet",
      "exitaclGetacl",
      "exitaclSet",
      "exitaclSetacl",
      "exitaclToggleacl",
      "generalAddhidservauth",
      "generalDelhidservauth",
      "generalGet",
      "generalGethidservauth",
      "generalSet",
      "generalSethidservauth",
      "generalTogglehidservauth",
      "hiddenserviceAddservice",
      "hiddenserviceDelservice",
      "hiddenserviceGet",
      "hiddenserviceGetservice",
      "hiddenserviceSet",
      "hiddenserviceSetservice",
      "hiddenserviceToggleservice",
      "hiddenserviceaclAddacl",
      "hiddenserviceaclDelacl",
      "hiddenserviceaclGet",
      "hiddenserviceaclGetacl",
      "hiddenserviceaclSet",
      "hiddenserviceaclSetacl",
      "hiddenserviceaclToggleacl",
      "relayGet",
      "relaySet",
      "serviceCircuits",
      "serviceGetHiddenServices",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceStreams",
      "socksaclAddacl",
      "socksaclDelacl",
      "socksaclGet",
      "socksaclGetacl",
      "socksaclSet",
      "socksaclSetacl",
      "socksaclToggleacl"
    ]
  },
  "plugins.turnserver": {
    "toolName": "plugin_turnserver_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.udpbroadcastrelay": {
    "toolName": "plugin_udpbroadcastrelay_manage",
    "methods": [
      "serviceConfig",
      "serviceGet",
      "serviceReload",
      "serviceRestart",
      "serviceSet",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddRelay",
      "settingsDelRelay",
      "settingsGet",
      "settingsGetRelay",
      "settingsSearchRelay",
      "settingsSet",
      "settingsSetRelay",
      "settingsToggleRelay"
    ]
  },
  "plugins.vnstat": {
    "toolName": "plugin_vnstat_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceDaily",
      "serviceHourly",
      "serviceMonthly",
      "serviceReconfigure",
      "serviceResetdb",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "serviceYearly"
    ]
  },
  "plugins.wazuhagent": {
    "toolName": "plugin_wazuhagent_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsGet",
      "settingsSet"
    ]
  },
  "plugins.wol": {
    "toolName": "plugin_wol_manage",
    "methods": [
      "wolAddHost",
      "wolDelHost",
      "wolGet",
      "wolGetHost",
      "wolGetwake",
      "wolSet",
      "wolSetHost",
      "wolWakeall"
    ]
  },
  "plugins.zabbixagent": {
    "toolName": "plugin_zabbixagent_manage",
    "methods": [
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop",
      "settingsAddAlias",
      "settingsAddUserparameter",
      "settingsDelAlias",
      "settingsDelUserparameter",
      "settingsGet",
      "settingsGetAlias",
      "settingsGetUserparameter",
      "settingsSet",
      "settingsSetAlias",
      "settingsSetUserparameter",
      "settingsToggleAlias",
      "settingsToggleUserparameter"
    ]
  },
  "plugins.zabbixproxy": {
    "toolName": "plugin_zabbixproxy_manage",
    "methods": [
      "generalGet",
      "generalSet",
      "serviceReconfigure",
      "serviceRestart",
      "serviceStart",
      "serviceStatus",
      "serviceStop"
    ]
  },
  "plugins.zerotier": {
    "toolName": "plugin_zerotier_manage",
    "methods": [
      "networkAdd",
      "networkDel",
      "networkGet",
      "networkInfo",
      "networkSearch",
      "networkSet",
      "networkToggle",
      "settingsGet",
      "settingsSet",
      "settingsStatus"
    ]
  }
};

// Discovered MVC API surface — see src/api-routes.json and the note in build.ts.
const API_ROUTES = {"auth":{"groupAdd":{"mutating":true,"params":0,"path":"/api/auth/group/add","post":true,"search":false},"groupDel":{"mutating":true,"params":1,"path":"/api/auth/group/del","post":true,"search":false},"groupGet":{"mutating":false,"params":1,"path":"/api/auth/group/get","post":false,"search":false},"groupSearch":{"mutating":false,"params":0,"path":"/api/auth/group/search","post":false,"search":true},"groupSet":{"mutating":true,"params":1,"path":"/api/auth/group/set","post":true,"search":false},"privGetItem":{"mutating":false,"params":1,"path":"/api/auth/priv/getItem","post":false,"search":false},"privSearch":{"mutating":false,"params":0,"path":"/api/auth/priv/search","post":false,"search":true},"privSetItem":{"mutating":true,"params":1,"path":"/api/auth/priv/setItem","post":true,"search":false},"userAdd":{"mutating":true,"params":0,"path":"/api/auth/user/add","post":true,"search":false},"userAddApiKey":{"mutating":true,"params":1,"path":"/api/auth/user/addApiKey","post":true,"search":false},"userDel":{"mutating":true,"params":1,"path":"/api/auth/user/del","post":true,"search":false},"userDelApiKey":{"mutating":true,"params":1,"path":"/api/auth/user/delApiKey","post":true,"search":false},"userDownload":{"mutating":false,"params":0,"path":"/api/auth/user/download","post":false,"search":false},"userGet":{"mutating":false,"params":1,"path":"/api/auth/user/get","post":false,"search":false},"userNewOtpSeed":{"mutating":true,"params":0,"path":"/api/auth/user/newOtpSeed","post":false,"search":false},"userSearch":{"mutating":false,"params":0,"path":"/api/auth/user/search","post":false,"search":true},"userSearchApiKey":{"mutating":false,"params":0,"path":"/api/auth/user/searchApiKey","post":false,"search":true},"userSet":{"mutating":true,"params":1,"path":"/api/auth/user/set","post":true,"search":false},"userUpload":{"mutating":true,"params":0,"path":"/api/auth/user/upload","post":true,"search":false}},"backup":{"backupDownload":{"mutating":false,"params":1,"path":"/api/backup/backup/download","post":false,"search":false}},"captiveportal":{"accessApi":{"mutating":false,"params":0,"path":"/api/captiveportal/access/api","post":false,"search":false},"accessLogoff":{"mutating":false,"params":1,"path":"/api/captiveportal/access/logoff","post":true,"search":false},"accessLogon":{"mutating":false,"params":1,"path":"/api/captiveportal/access/logon","post":true,"search":false},"accessStatus":{"mutating":false,"params":1,"path":"/api/captiveportal/access/status","post":true,"search":false},"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/captiveportal/service/reconfigure","post":true,"search":false},"sessionConnect":{"mutating":true,"params":1,"path":"/api/captiveportal/session/connect","post":true,"search":false},"sessionDisconnect":{"mutating":true,"params":1,"path":"/api/captiveportal/session/disconnect","post":true,"search":false},"sessionList":{"mutating":false,"params":1,"path":"/api/captiveportal/session/list","post":false,"search":false},"sessionSearch":{"mutating":false,"params":0,"path":"/api/captiveportal/session/search","post":false,"search":true},"sessionZones":{"mutating":false,"params":0,"path":"/api/captiveportal/session/zones","post":false,"search":false},"settingsAddZone":{"mutating":true,"params":0,"path":"/api/captiveportal/settings/addZone","post":true,"search":false},"settingsDelZone":{"mutating":true,"params":1,"path":"/api/captiveportal/settings/delZone","post":true,"search":false},"settingsGetZone":{"mutating":false,"params":1,"path":"/api/captiveportal/settings/getZone","post":false,"search":false},"settingsSearchZones":{"mutating":false,"params":0,"path":"/api/captiveportal/settings/searchZones","post":false,"search":true},"settingsSetZone":{"mutating":true,"params":1,"path":"/api/captiveportal/settings/setZone","post":true,"search":false},"settingsToggleZone":{"mutating":true,"params":2,"path":"/api/captiveportal/settings/toggleZone","post":true,"search":false},"templateDelTemplate":{"mutating":true,"params":1,"path":"/api/captiveportal/template/delTemplate","post":true,"search":false},"templateGetTemplate":{"mutating":false,"params":1,"path":"/api/captiveportal/template/getTemplate","post":false,"search":false},"templateSaveTemplate":{"mutating":true,"params":0,"path":"/api/captiveportal/template/saveTemplate","post":true,"search":false},"templateSearchTemplates":{"mutating":false,"params":0,"path":"/api/captiveportal/template/searchTemplates","post":false,"search":true},"voucherDropExpiredVouchers":{"mutating":false,"params":2,"path":"/api/captiveportal/voucher/dropExpiredVouchers","post":true,"search":false},"voucherDropVoucherGroup":{"mutating":false,"params":2,"path":"/api/captiveportal/voucher/dropVoucherGroup","post":true,"search":false},"voucherExpireVoucher":{"mutating":false,"params":1,"path":"/api/captiveportal/voucher/expireVoucher","post":true,"search":false},"voucherGenerateVouchers":{"mutating":true,"params":1,"path":"/api/captiveportal/voucher/generateVouchers","post":true,"search":false},"voucherListProviders":{"mutating":false,"params":0,"path":"/api/captiveportal/voucher/listProviders","post":false,"search":false},"voucherListVoucherGroups":{"mutating":false,"params":1,"path":"/api/captiveportal/voucher/listVoucherGroups","post":false,"search":false},"voucherListVouchers":{"mutating":false,"params":2,"path":"/api/captiveportal/voucher/listVouchers","post":false,"search":false}},"core":{"backupBackups":{"mutating":false,"params":1,"path":"/api/core/backup/backups","post":false,"search":false},"backupDeleteBackup":{"mutating":true,"params":1,"path":"/api/core/backup/deleteBackup","post":true,"search":false},"backupDiff":{"mutating":false,"params":3,"path":"/api/core/backup/diff","post":false,"search":false},"backupDownload":{"mutating":false,"params":2,"path":"/api/core/backup/download","post":false,"search":false},"backupProviders":{"mutating":false,"params":0,"path":"/api/core/backup/providers","post":false,"search":false},"backupRevertBackup":{"mutating":false,"params":1,"path":"/api/core/backup/revertBackup","post":true,"search":false},"dashboardGetDashboard":{"mutating":false,"params":0,"path":"/api/core/dashboard/getDashboard","post":false,"search":false},"dashboardPicture":{"mutating":true,"params":0,"path":"/api/core/dashboard/picture","post":true,"search":false},"dashboardProductInfoFeed":{"mutating":false,"params":0,"path":"/api/core/dashboard/productInfoFeed","post":false,"search":false},"dashboardRestoreDefaults":{"mutating":true,"params":0,"path":"/api/core/dashboard/restoreDefaults","post":true,"search":false},"dashboardSaveWidgets":{"mutating":true,"params":0,"path":"/api/core/dashboard/saveWidgets","post":true,"search":false},"defaultsFactoryDefaults":{"mutating":true,"params":0,"path":"/api/core/defaults/factoryDefaults","post":true,"search":false},"defaultsGet":{"mutating":false,"params":0,"path":"/api/core/defaults/get","post":false,"search":false},"defaultsGetInstalledSections":{"mutating":false,"params":0,"path":"/api/core/defaults/getInstalledSections","post":false,"search":false},"defaultsReset":{"mutating":true,"params":0,"path":"/api/core/defaults/reset","post":true,"search":false},"hasyncReconfigure":{"mutating":true,"params":0,"path":"/api/core/hasync/reconfigure","post":true,"search":false},"hasyncStatusRemoteService":{"mutating":false,"params":3,"path":"/api/core/hasync_status/remoteService","post":false,"search":false},"hasyncStatusRestart":{"mutating":true,"params":2,"path":"/api/core/hasync_status/restart","post":true,"search":false},"hasyncStatusRestartAll":{"mutating":true,"params":2,"path":"/api/core/hasync_status/restartAll","post":true,"search":false},"hasyncStatusServices":{"mutating":false,"params":0,"path":"/api/core/hasync_status/services","post":false,"search":false},"hasyncStatusStart":{"mutating":true,"params":2,"path":"/api/core/hasync_status/start","post":true,"search":false},"hasyncStatusStop":{"mutating":true,"params":2,"path":"/api/core/hasync_status/stop","post":true,"search":false},"hasyncStatusVersion":{"mutating":false,"params":0,"path":"/api/core/hasync_status/version","post":false,"search":false},"initialSetupAbort":{"mutating":true,"params":0,"path":"/api/core/initial_setup/abort","post":true,"search":false},"initialSetupConfigure":{"mutating":true,"params":0,"path":"/api/core/initial_setup/configure","post":true,"search":false},"menuSearch":{"mutating":false,"params":0,"path":"/api/core/menu/search","post":false,"search":true},"menuTree":{"mutating":false,"params":0,"path":"/api/core/menu/tree","post":false,"search":false},"serviceRestart":{"mutating":true,"params":2,"path":"/api/core/service/restart","post":true,"search":false},"serviceSearch":{"mutating":false,"params":0,"path":"/api/core/service/search","post":false,"search":true},"serviceStart":{"mutating":true,"params":2,"path":"/api/core/service/start","post":true,"search":false},"serviceStop":{"mutating":true,"params":2,"path":"/api/core/service/stop","post":true,"search":false},"snapshotsActivate":{"mutating":false,"params":1,"path":"/api/core/snapshots/activate","post":true,"search":false},"snapshotsAdd":{"mutating":true,"params":0,"path":"/api/core/snapshots/add","post":true,"search":false},"snapshotsDel":{"mutating":true,"params":1,"path":"/api/core/snapshots/del","post":true,"search":false},"snapshotsGet":{"mutating":false,"params":1,"path":"/api/core/snapshots/get","post":false,"search":false},"snapshotsIsSupported":{"mutating":false,"params":0,"path":"/api/core/snapshots/isSupported","post":false,"search":false},"snapshotsSearch":{"mutating":false,"params":0,"path":"/api/core/snapshots/search","post":false,"search":true},"snapshotsSet":{"mutating":true,"params":1,"path":"/api/core/snapshots/set","post":true,"search":false},"systemDismissStatus":{"mutating":true,"params":0,"path":"/api/core/system/dismissStatus","post":true,"search":false},"systemHalt":{"mutating":true,"params":0,"path":"/api/core/system/halt","post":true,"search":false},"systemReboot":{"mutating":true,"params":0,"path":"/api/core/system/reboot","post":true,"search":false},"systemStatus":{"mutating":false,"params":0,"path":"/api/core/system/status","post":false,"search":false},"tunablesAddItem":{"mutating":true,"params":0,"path":"/api/core/tunables/addItem","post":true,"search":false},"tunablesDelItem":{"mutating":true,"params":1,"path":"/api/core/tunables/delItem","post":true,"search":false},"tunablesGetItem":{"mutating":false,"params":1,"path":"/api/core/tunables/getItem","post":false,"search":false},"tunablesReconfigure":{"mutating":true,"params":0,"path":"/api/core/tunables/reconfigure","post":true,"search":false},"tunablesReset":{"mutating":true,"params":0,"path":"/api/core/tunables/reset","post":true,"search":false},"tunablesSearchItem":{"mutating":false,"params":0,"path":"/api/core/tunables/searchItem","post":false,"search":true},"tunablesSetItem":{"mutating":true,"params":1,"path":"/api/core/tunables/setItem","post":true,"search":false}},"cron":{"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/cron/service/reconfigure","post":true,"search":false},"settingsAddJob":{"mutating":true,"params":0,"path":"/api/cron/settings/addJob","post":true,"search":false},"settingsDelJob":{"mutating":true,"params":1,"path":"/api/cron/settings/delJob","post":true,"search":false},"settingsGetJob":{"mutating":false,"params":1,"path":"/api/cron/settings/getJob","post":false,"search":false},"settingsSearchJobs":{"mutating":false,"params":0,"path":"/api/cron/settings/searchJobs","post":false,"search":true},"settingsSetJob":{"mutating":true,"params":1,"path":"/api/cron/settings/setJob","post":true,"search":false},"settingsToggleJob":{"mutating":true,"params":2,"path":"/api/cron/settings/toggleJob","post":true,"search":false}},"dhcrelay":{"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/dhcrelay/service/reconfigure","post":true,"search":false},"settingsAddDest":{"mutating":true,"params":0,"path":"/api/dhcrelay/settings/addDest","post":true,"search":false},"settingsAddRelay":{"mutating":true,"params":0,"path":"/api/dhcrelay/settings/addRelay","post":true,"search":false},"settingsDelDest":{"mutating":true,"params":1,"path":"/api/dhcrelay/settings/delDest","post":true,"search":false},"settingsDelRelay":{"mutating":true,"params":1,"path":"/api/dhcrelay/settings/delRelay","post":true,"search":false},"settingsGetDest":{"mutating":false,"params":1,"path":"/api/dhcrelay/settings/getDest","post":false,"search":false},"settingsGetRelay":{"mutating":false,"params":1,"path":"/api/dhcrelay/settings/getRelay","post":false,"search":false},"settingsSearchDest":{"mutating":false,"params":0,"path":"/api/dhcrelay/settings/searchDest","post":false,"search":true},"settingsSearchRelay":{"mutating":false,"params":0,"path":"/api/dhcrelay/settings/searchRelay","post":false,"search":true},"settingsSetDest":{"mutating":true,"params":1,"path":"/api/dhcrelay/settings/setDest","post":true,"search":false},"settingsSetRelay":{"mutating":true,"params":1,"path":"/api/dhcrelay/settings/setRelay","post":true,"search":false},"settingsToggleRelay":{"mutating":true,"params":2,"path":"/api/dhcrelay/settings/toggleRelay","post":true,"search":false}},"diagnostics":{"activityGetActivity":{"mutating":false,"params":0,"path":"/api/diagnostics/activity/getActivity","post":false,"search":false},"cpuUsageGetCPUType":{"mutating":false,"params":0,"path":"/api/diagnostics/cpu_usage/getCPUType","post":false,"search":false},"cpuUsageStream":{"mutating":false,"params":0,"path":"/api/diagnostics/cpu_usage/stream","post":false,"search":false},"dnsDiagnosticsSet":{"mutating":true,"params":0,"path":"/api/diagnostics/dns_diagnostics/set","post":true,"search":false},"dnsReverseLookup":{"mutating":false,"params":0,"path":"/api/diagnostics/dns/reverseLookup","post":false,"search":false},"firewallDelState":{"mutating":true,"params":2,"path":"/api/diagnostics/firewall/delState","post":true,"search":false},"firewallFlushSources":{"mutating":true,"params":0,"path":"/api/diagnostics/firewall/flushSources","post":true,"search":false},"firewallFlushStates":{"mutating":true,"params":0,"path":"/api/diagnostics/firewall/flushStates","post":true,"search":false},"firewallKillStates":{"mutating":true,"params":0,"path":"/api/diagnostics/firewall/killStates","post":true,"search":false},"firewallListRuleIds":{"mutating":false,"params":0,"path":"/api/diagnostics/firewall/listRuleIds","post":false,"search":false},"firewallLog":{"mutating":false,"params":0,"path":"/api/diagnostics/firewall/log","post":false,"search":false},"firewallLogFilters":{"mutating":false,"params":0,"path":"/api/diagnostics/firewall/logFilters","post":false,"search":false},"firewallPfStates":{"mutating":false,"params":0,"path":"/api/diagnostics/firewall/pfStates","post":false,"search":false},"firewallPfStatistics":{"mutating":false,"params":1,"path":"/api/diagnostics/firewall/pfStatistics","post":false,"search":false},"firewallQueryPfTop":{"mutating":false,"params":0,"path":"/api/diagnostics/firewall/queryPfTop","post":false,"search":false},"firewallQueryStates":{"mutating":false,"params":0,"path":"/api/diagnostics/firewall/queryStates","post":false,"search":false},"firewallStats":{"mutating":false,"params":0,"path":"/api/diagnostics/firewall/stats","post":false,"search":false},"firewallStreamLog":{"mutating":false,"params":0,"path":"/api/diagnostics/firewall/streamLog","post":false,"search":false},"interfaceCarpStatus":{"mutating":false,"params":1,"path":"/api/diagnostics/interface/carpStatus","post":true,"search":false},"interfaceDelRoute":{"mutating":true,"params":0,"path":"/api/diagnostics/interface/delRoute","post":true,"search":false},"interfaceFlushArp":{"mutating":true,"params":0,"path":"/api/diagnostics/interface/flushArp","post":true,"search":false},"interfaceGetArp":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getArp","post":false,"search":false},"interfaceGetBpfStatistics":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getBpfStatistics","post":false,"search":false},"interfaceGetInterfaceConfig":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getInterfaceConfig","post":false,"search":false},"interfaceGetInterfaceNames":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getInterfaceNames","post":false,"search":false},"interfaceGetInterfaceStatistics":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getInterfaceStatistics","post":false,"search":false},"interfaceGetMemoryStatistics":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getMemoryStatistics","post":false,"search":false},"interfaceGetNdp":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getNdp","post":false,"search":false},"interfaceGetNetisrStatistics":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getNetisrStatistics","post":false,"search":false},"interfaceGetPfsyncNodes":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getPfsyncNodes","post":false,"search":false},"interfaceGetProtocolStatistics":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getProtocolStatistics","post":false,"search":false},"interfaceGetRoutes":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getRoutes","post":false,"search":false},"interfaceGetSocketStatistics":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getSocketStatistics","post":false,"search":false},"interfaceGetVipStatus":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/getVipStatus","post":false,"search":false},"interfaceSearchArp":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/searchArp","post":false,"search":true},"interfaceSearchNdp":{"mutating":false,"params":0,"path":"/api/diagnostics/interface/searchNdp","post":false,"search":true},"lvtemplateAddItem":{"mutating":true,"params":0,"path":"/api/diagnostics/lvtemplate/addItem","post":true,"search":false},"lvtemplateDelItem":{"mutating":true,"params":1,"path":"/api/diagnostics/lvtemplate/delItem","post":true,"search":false},"lvtemplateGetItem":{"mutating":false,"params":1,"path":"/api/diagnostics/lvtemplate/getItem","post":false,"search":false},"lvtemplateSearchItem":{"mutating":false,"params":0,"path":"/api/diagnostics/lvtemplate/searchItem","post":false,"search":true},"lvtemplateSetItem":{"mutating":true,"params":1,"path":"/api/diagnostics/lvtemplate/setItem","post":true,"search":false},"netflowCacheStats":{"mutating":false,"params":0,"path":"/api/diagnostics/netflow/cacheStats","post":false,"search":false},"netflowGetconfig":{"mutating":false,"params":0,"path":"/api/diagnostics/netflow/getconfig","post":false,"search":false},"netflowIsEnabled":{"mutating":false,"params":0,"path":"/api/diagnostics/netflow/isEnabled","post":false,"search":false},"netflowReconfigure":{"mutating":true,"params":0,"path":"/api/diagnostics/netflow/reconfigure","post":true,"search":false},"netflowReset":{"mutating":true,"params":0,"path":"/api/diagnostics/netflow/reset","post":true,"search":false},"netflowSetconfig":{"mutating":true,"params":0,"path":"/api/diagnostics/netflow/setconfig","post":true,"search":false},"netflowStatus":{"mutating":false,"params":0,"path":"/api/diagnostics/netflow/status","post":false,"search":false},"networkinsightExport":{"mutating":false,"params":4,"path":"/api/diagnostics/networkinsight/export","post":false,"search":false},"networkinsightGetInterfaces":{"mutating":false,"params":0,"path":"/api/diagnostics/networkinsight/getInterfaces","post":false,"search":false},"networkinsightGetMetadata":{"mutating":false,"params":0,"path":"/api/diagnostics/networkinsight/getMetadata","post":false,"search":false},"networkinsightGetProtocols":{"mutating":false,"params":0,"path":"/api/diagnostics/networkinsight/getProtocols","post":false,"search":false},"networkinsightGetServices":{"mutating":false,"params":0,"path":"/api/diagnostics/networkinsight/getServices","post":false,"search":false},"networkinsightTimeserie":{"mutating":false,"params":7,"path":"/api/diagnostics/networkinsight/timeserie","post":false,"search":false},"networkinsightTop":{"mutating":false,"params":6,"path":"/api/diagnostics/networkinsight/top","post":false,"search":false},"packetCaptureDownload":{"mutating":false,"params":1,"path":"/api/diagnostics/packet_capture/download","post":false,"search":false},"packetCaptureMacInfo":{"mutating":false,"params":1,"path":"/api/diagnostics/packet_capture/macInfo","post":false,"search":false},"packetCaptureRemove":{"mutating":true,"params":1,"path":"/api/diagnostics/packet_capture/remove","post":true,"search":false},"packetCaptureSearchJobs":{"mutating":false,"params":0,"path":"/api/diagnostics/packet_capture/searchJobs","post":false,"search":true},"packetCaptureSet":{"mutating":true,"params":0,"path":"/api/diagnostics/packet_capture/set","post":true,"search":false},"packetCaptureStart":{"mutating":true,"params":1,"path":"/api/diagnostics/packet_capture/start","post":true,"search":false},"packetCaptureStop":{"mutating":true,"params":1,"path":"/api/diagnostics/packet_capture/stop","post":true,"search":false},"packetCaptureView":{"mutating":false,"params":2,"path":"/api/diagnostics/packet_capture/view","post":false,"search":false},"pingRemove":{"mutating":true,"params":1,"path":"/api/diagnostics/ping/remove","post":true,"search":false},"pingSearchJobs":{"mutating":false,"params":0,"path":"/api/diagnostics/ping/searchJobs","post":false,"search":true},"pingSet":{"mutating":true,"params":0,"path":"/api/diagnostics/ping/set","post":true,"search":false},"pingStart":{"mutating":true,"params":1,"path":"/api/diagnostics/ping/start","post":true,"search":false},"pingStop":{"mutating":true,"params":1,"path":"/api/diagnostics/ping/stop","post":true,"search":false},"portprobeSet":{"mutating":true,"params":0,"path":"/api/diagnostics/portprobe/set","post":true,"search":false},"systemMemory":{"mutating":false,"params":0,"path":"/api/diagnostics/system/memory","post":false,"search":false},"systemSystemDisk":{"mutating":false,"params":0,"path":"/api/diagnostics/system/systemDisk","post":false,"search":false},"systemSystemInformation":{"mutating":false,"params":0,"path":"/api/diagnostics/system/systemInformation","post":false,"search":false},"systemSystemMbuf":{"mutating":false,"params":0,"path":"/api/diagnostics/system/systemMbuf","post":false,"search":false},"systemSystemResources":{"mutating":false,"params":0,"path":"/api/diagnostics/system/systemResources","post":false,"search":false},"systemSystemSwap":{"mutating":false,"params":0,"path":"/api/diagnostics/system/systemSwap","post":false,"search":false},"systemSystemTemperature":{"mutating":false,"params":0,"path":"/api/diagnostics/system/systemTemperature","post":false,"search":false},"systemSystemTime":{"mutating":false,"params":0,"path":"/api/diagnostics/system/systemTime","post":false,"search":false},"systemhealthDelRRD":{"mutating":true,"params":1,"path":"/api/diagnostics/systemhealth/delRRD","post":true,"search":false},"systemhealthExportAsCSV":{"mutating":false,"params":2,"path":"/api/diagnostics/systemhealth/exportAsCSV","post":false,"search":false},"systemhealthGetInterfaces":{"mutating":false,"params":0,"path":"/api/diagnostics/systemhealth/getInterfaces","post":false,"search":false},"systemhealthGetRrdList":{"mutating":false,"params":0,"path":"/api/diagnostics/systemhealth/getRrdList","post":false,"search":false},"systemhealthGetSystemHealth":{"mutating":false,"params":2,"path":"/api/diagnostics/systemhealth/getSystemHealth","post":false,"search":false},"systemhealthReconfigure":{"mutating":true,"params":0,"path":"/api/diagnostics/systemhealth/reconfigure","post":true,"search":false},"tracerouteSet":{"mutating":true,"params":0,"path":"/api/diagnostics/traceroute/set","post":true,"search":false},"trafficInterface":{"mutating":false,"params":0,"path":"/api/diagnostics/traffic/Interface","post":false,"search":false},"trafficStream":{"mutating":false,"params":1,"path":"/api/diagnostics/traffic/stream","post":false,"search":false},"trafficTop":{"mutating":false,"params":1,"path":"/api/diagnostics/traffic/Top","post":false,"search":false}},"dmidecode":{"serviceGet":{"mutating":false,"params":0,"path":"/api/dmidecode/service/get","post":false,"search":false}},"dnsmasq":{"leasesSearch":{"mutating":false,"params":0,"path":"/api/dnsmasq/leases/search","post":false,"search":true},"settingsAddBoot":{"mutating":true,"params":0,"path":"/api/dnsmasq/settings/addBoot","post":true,"search":false},"settingsAddDomain":{"mutating":true,"params":0,"path":"/api/dnsmasq/settings/addDomain","post":true,"search":false},"settingsAddHost":{"mutating":true,"params":0,"path":"/api/dnsmasq/settings/addHost","post":true,"search":false},"settingsAddOption":{"mutating":true,"params":0,"path":"/api/dnsmasq/settings/addOption","post":true,"search":false},"settingsAddRange":{"mutating":true,"params":0,"path":"/api/dnsmasq/settings/addRange","post":true,"search":false},"settingsAddTag":{"mutating":true,"params":0,"path":"/api/dnsmasq/settings/addTag","post":true,"search":false},"settingsDelBoot":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/delBoot","post":true,"search":false},"settingsDelDomain":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/delDomain","post":true,"search":false},"settingsDelHost":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/delHost","post":true,"search":false},"settingsDelOption":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/delOption","post":true,"search":false},"settingsDelRange":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/delRange","post":true,"search":false},"settingsDelTag":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/delTag","post":true,"search":false},"settingsDownloadHosts":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/downloadHosts","post":false,"search":false},"settingsGet":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/get","post":false,"search":false},"settingsGetBoot":{"mutating":false,"params":1,"path":"/api/dnsmasq/settings/getBoot","post":false,"search":false},"settingsGetDomain":{"mutating":false,"params":1,"path":"/api/dnsmasq/settings/getDomain","post":false,"search":false},"settingsGetHost":{"mutating":false,"params":1,"path":"/api/dnsmasq/settings/getHost","post":false,"search":false},"settingsGetOption":{"mutating":false,"params":1,"path":"/api/dnsmasq/settings/getOption","post":false,"search":false},"settingsGetRange":{"mutating":false,"params":1,"path":"/api/dnsmasq/settings/getRange","post":false,"search":false},"settingsGetTag":{"mutating":false,"params":1,"path":"/api/dnsmasq/settings/getTag","post":false,"search":false},"settingsGetTagList":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/getTagList","post":false,"search":false},"settingsSearchBoot":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/searchBoot","post":false,"search":true},"settingsSearchDomain":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/searchDomain","post":false,"search":true},"settingsSearchHost":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/searchHost","post":false,"search":true},"settingsSearchOption":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/searchOption","post":false,"search":true},"settingsSearchRange":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/searchRange","post":false,"search":true},"settingsSearchTag":{"mutating":false,"params":0,"path":"/api/dnsmasq/settings/searchTag","post":false,"search":true},"settingsSetBoot":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/setBoot","post":true,"search":false},"settingsSetDomain":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/setDomain","post":true,"search":false},"settingsSetHost":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/setHost","post":true,"search":false},"settingsSetOption":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/setOption","post":true,"search":false},"settingsSetRange":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/setRange","post":true,"search":false},"settingsSetTag":{"mutating":true,"params":1,"path":"/api/dnsmasq/settings/setTag","post":true,"search":false},"settingsUploadHosts":{"mutating":true,"params":0,"path":"/api/dnsmasq/settings/uploadHosts","post":true,"search":false}},"firewall":{"aliasAddItem":{"mutating":true,"params":0,"path":"/api/firewall/alias/addItem","post":true,"search":false},"aliasDelItem":{"mutating":true,"params":1,"path":"/api/firewall/alias/delItem","post":true,"search":false},"aliasExport":{"mutating":false,"params":0,"path":"/api/firewall/alias/export","post":false,"search":false},"aliasGetAliasUUID":{"mutating":false,"params":1,"path":"/api/firewall/alias/getAliasUUID","post":false,"search":false},"aliasGetGeoIP":{"mutating":false,"params":0,"path":"/api/firewall/alias/getGeoIP","post":false,"search":false},"aliasGetItem":{"mutating":false,"params":1,"path":"/api/firewall/alias/getItem","post":false,"search":false},"aliasGetTableSize":{"mutating":false,"params":0,"path":"/api/firewall/alias/getTableSize","post":false,"search":false},"aliasImport":{"mutating":true,"params":0,"path":"/api/firewall/alias/import","post":true,"search":false},"aliasListCategories":{"mutating":false,"params":0,"path":"/api/firewall/alias/listCategories","post":false,"search":false},"aliasListCountries":{"mutating":false,"params":0,"path":"/api/firewall/alias/listCountries","post":false,"search":false},"aliasListNetworkAliases":{"mutating":false,"params":0,"path":"/api/firewall/alias/listNetworkAliases","post":false,"search":false},"aliasListUserGroups":{"mutating":false,"params":0,"path":"/api/firewall/alias/listUserGroups","post":false,"search":false},"aliasReconfigure":{"mutating":true,"params":0,"path":"/api/firewall/alias/reconfigure","post":true,"search":false},"aliasSearchItem":{"mutating":false,"params":0,"path":"/api/firewall/alias/searchItem","post":false,"search":true},"aliasSetItem":{"mutating":true,"params":1,"path":"/api/firewall/alias/setItem","post":true,"search":false},"aliasToggleItem":{"mutating":true,"params":2,"path":"/api/firewall/alias/toggleItem","post":true,"search":false},"aliasUpdate":{"mutating":true,"params":1,"path":"/api/firewall/alias/update","post":true,"search":false},"aliasUtilAdd":{"mutating":true,"params":1,"path":"/api/firewall/alias_util/add","post":true,"search":false},"aliasUtilAliases":{"mutating":false,"params":0,"path":"/api/firewall/alias_util/aliases","post":false,"search":false},"aliasUtilDelete":{"mutating":true,"params":1,"path":"/api/firewall/alias_util/delete","post":true,"search":false},"aliasUtilFindReferences":{"mutating":false,"params":0,"path":"/api/firewall/alias_util/findReferences","post":false,"search":false},"aliasUtilFlush":{"mutating":true,"params":1,"path":"/api/firewall/alias_util/flush","post":true,"search":false},"aliasUtilList":{"mutating":false,"params":1,"path":"/api/firewall/alias_util/list","post":false,"search":false},"categoryAddItem":{"mutating":true,"params":0,"path":"/api/firewall/category/addItem","post":true,"search":false},"categoryDelItem":{"mutating":true,"params":1,"path":"/api/firewall/category/delItem","post":true,"search":false},"categoryDownload":{"mutating":false,"params":0,"path":"/api/firewall/category/download","post":false,"search":false},"categoryGetItem":{"mutating":false,"params":1,"path":"/api/firewall/category/getItem","post":false,"search":false},"categorySearchItem":{"mutating":false,"params":1,"path":"/api/firewall/category/searchItem","post":true,"search":true},"categorySetItem":{"mutating":true,"params":1,"path":"/api/firewall/category/setItem","post":true,"search":false},"categoryUpload":{"mutating":true,"params":0,"path":"/api/firewall/category/upload","post":true,"search":false},"dNatAddRule":{"mutating":true,"params":0,"path":"/api/firewall/d_nat/addRule","post":true,"search":false},"dNatApply":{"mutating":true,"params":0,"path":"/api/firewall/d_nat/apply","post":true,"search":false},"dNatDelRule":{"mutating":true,"params":1,"path":"/api/firewall/d_nat/delRule","post":true,"search":false},"dNatDownloadRules":{"mutating":false,"params":0,"path":"/api/firewall/d_nat/downloadRules","post":false,"search":false},"dNatGetRule":{"mutating":false,"params":1,"path":"/api/firewall/d_nat/getRule","post":false,"search":false},"dNatListCategories":{"mutating":false,"params":0,"path":"/api/firewall/d_nat/listCategories","post":false,"search":false},"dNatListNetworkSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/d_nat/listNetworkSelectOptions","post":false,"search":false},"dNatListPortSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/d_nat/listPortSelectOptions","post":false,"search":false},"dNatMoveRuleBefore":{"mutating":true,"params":2,"path":"/api/firewall/d_nat/moveRuleBefore","post":true,"search":false},"dNatSearchRule":{"mutating":false,"params":0,"path":"/api/firewall/d_nat/searchRule","post":false,"search":true},"dNatSetRule":{"mutating":true,"params":1,"path":"/api/firewall/d_nat/setRule","post":true,"search":false},"dNatToggleRule":{"mutating":true,"params":2,"path":"/api/firewall/d_nat/toggleRule","post":true,"search":false},"dNatToggleRuleLog":{"mutating":true,"params":2,"path":"/api/firewall/d_nat/toggleRuleLog","post":true,"search":false},"dNatUploadRules":{"mutating":true,"params":0,"path":"/api/firewall/d_nat/uploadRules","post":true,"search":false},"filterAddRule":{"mutating":true,"params":0,"path":"/api/firewall/filter/addRule","post":true,"search":false},"filterApply":{"mutating":true,"params":0,"path":"/api/firewall/filter/apply","post":true,"search":false},"filterDelRule":{"mutating":true,"params":1,"path":"/api/firewall/filter/delRule","post":true,"search":false},"filterDownloadRules":{"mutating":false,"params":0,"path":"/api/firewall/filter/downloadRules","post":false,"search":false},"filterFlushInspectCache":{"mutating":true,"params":0,"path":"/api/firewall/filter/flushInspectCache","post":true,"search":false},"filterGetInterfaceList":{"mutating":false,"params":0,"path":"/api/firewall/filter/getInterfaceList","post":false,"search":false},"filterGetRule":{"mutating":false,"params":1,"path":"/api/firewall/filter/getRule","post":false,"search":false},"filterListCategories":{"mutating":false,"params":0,"path":"/api/firewall/filter/listCategories","post":false,"search":false},"filterListNetworkSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/filter/listNetworkSelectOptions","post":false,"search":false},"filterListPortSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/filter/listPortSelectOptions","post":false,"search":false},"filterMoveRuleBefore":{"mutating":true,"params":2,"path":"/api/firewall/filter/moveRuleBefore","post":true,"search":false},"filterSearchRule":{"mutating":false,"params":0,"path":"/api/firewall/filter/searchRule","post":false,"search":true},"filterSetRule":{"mutating":true,"params":1,"path":"/api/firewall/filter/setRule","post":true,"search":false},"filterToggleRule":{"mutating":true,"params":2,"path":"/api/firewall/filter/toggleRule","post":true,"search":false},"filterToggleRuleLog":{"mutating":true,"params":2,"path":"/api/firewall/filter/toggleRuleLog","post":true,"search":false},"filterUploadRules":{"mutating":true,"params":0,"path":"/api/firewall/filter/uploadRules","post":true,"search":false},"filterUtilRuleStats":{"mutating":false,"params":0,"path":"/api/firewall/filter_util/ruleStats","post":false,"search":false},"groupAddItem":{"mutating":true,"params":0,"path":"/api/firewall/group/addItem","post":true,"search":false},"groupDelItem":{"mutating":true,"params":1,"path":"/api/firewall/group/delItem","post":true,"search":false},"groupGetItem":{"mutating":false,"params":1,"path":"/api/firewall/group/getItem","post":false,"search":false},"groupReconfigure":{"mutating":true,"params":0,"path":"/api/firewall/group/reconfigure","post":true,"search":false},"groupSearchItem":{"mutating":false,"params":0,"path":"/api/firewall/group/searchItem","post":false,"search":true},"groupSetItem":{"mutating":true,"params":1,"path":"/api/firewall/group/setItem","post":true,"search":false},"migrationCountOutbound":{"mutating":false,"params":0,"path":"/api/firewall/migration/countOutbound","post":false,"search":false},"migrationCountRules":{"mutating":false,"params":0,"path":"/api/firewall/migration/countRules","post":false,"search":false},"migrationDownloadOutbound":{"mutating":false,"params":0,"path":"/api/firewall/migration/downloadOutbound","post":false,"search":false},"migrationDownloadRules":{"mutating":false,"params":0,"path":"/api/firewall/migration/downloadRules","post":false,"search":false},"migrationFlush":{"mutating":true,"params":0,"path":"/api/firewall/migration/flush","post":true,"search":false},"migrationFlushOutbound":{"mutating":true,"params":0,"path":"/api/firewall/migration/flushOutbound","post":true,"search":false},"nptAddRule":{"mutating":true,"params":0,"path":"/api/firewall/npt/addRule","post":true,"search":false},"nptApply":{"mutating":true,"params":0,"path":"/api/firewall/npt/apply","post":true,"search":false},"nptDelRule":{"mutating":true,"params":1,"path":"/api/firewall/npt/delRule","post":true,"search":false},"nptDownloadRules":{"mutating":false,"params":0,"path":"/api/firewall/npt/downloadRules","post":false,"search":false},"nptGetRule":{"mutating":false,"params":1,"path":"/api/firewall/npt/getRule","post":false,"search":false},"nptListCategories":{"mutating":false,"params":0,"path":"/api/firewall/npt/listCategories","post":false,"search":false},"nptListNetworkSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/npt/listNetworkSelectOptions","post":false,"search":false},"nptListPortSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/npt/listPortSelectOptions","post":false,"search":false},"nptMoveRuleBefore":{"mutating":true,"params":2,"path":"/api/firewall/npt/moveRuleBefore","post":true,"search":false},"nptSearchRule":{"mutating":false,"params":0,"path":"/api/firewall/npt/searchRule","post":false,"search":true},"nptSetRule":{"mutating":true,"params":1,"path":"/api/firewall/npt/setRule","post":true,"search":false},"nptToggleRule":{"mutating":true,"params":2,"path":"/api/firewall/npt/toggleRule","post":true,"search":false},"nptToggleRuleLog":{"mutating":true,"params":2,"path":"/api/firewall/npt/toggleRuleLog","post":true,"search":false},"nptUploadRules":{"mutating":true,"params":0,"path":"/api/firewall/npt/uploadRules","post":true,"search":false},"oneToOneAddRule":{"mutating":true,"params":0,"path":"/api/firewall/one_to_one/addRule","post":true,"search":false},"oneToOneApply":{"mutating":true,"params":0,"path":"/api/firewall/one_to_one/apply","post":true,"search":false},"oneToOneDelRule":{"mutating":true,"params":1,"path":"/api/firewall/one_to_one/delRule","post":true,"search":false},"oneToOneDownloadRules":{"mutating":false,"params":0,"path":"/api/firewall/one_to_one/downloadRules","post":false,"search":false},"oneToOneGetRule":{"mutating":false,"params":1,"path":"/api/firewall/one_to_one/getRule","post":false,"search":false},"oneToOneListCategories":{"mutating":false,"params":0,"path":"/api/firewall/one_to_one/listCategories","post":false,"search":false},"oneToOneListNetworkSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/one_to_one/listNetworkSelectOptions","post":false,"search":false},"oneToOneListPortSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/one_to_one/listPortSelectOptions","post":false,"search":false},"oneToOneMoveRuleBefore":{"mutating":true,"params":2,"path":"/api/firewall/one_to_one/moveRuleBefore","post":true,"search":false},"oneToOneSearchRule":{"mutating":false,"params":0,"path":"/api/firewall/one_to_one/searchRule","post":false,"search":true},"oneToOneSetRule":{"mutating":true,"params":1,"path":"/api/firewall/one_to_one/setRule","post":true,"search":false},"oneToOneToggleRule":{"mutating":true,"params":2,"path":"/api/firewall/one_to_one/toggleRule","post":true,"search":false},"oneToOneToggleRuleLog":{"mutating":true,"params":2,"path":"/api/firewall/one_to_one/toggleRuleLog","post":true,"search":false},"oneToOneUploadRules":{"mutating":true,"params":0,"path":"/api/firewall/one_to_one/uploadRules","post":true,"search":false},"sourceNatAddRule":{"mutating":true,"params":0,"path":"/api/firewall/source_nat/addRule","post":true,"search":false},"sourceNatApply":{"mutating":true,"params":0,"path":"/api/firewall/source_nat/apply","post":true,"search":false},"sourceNatDelRule":{"mutating":true,"params":1,"path":"/api/firewall/source_nat/delRule","post":true,"search":false},"sourceNatDownloadRules":{"mutating":false,"params":0,"path":"/api/firewall/source_nat/downloadRules","post":false,"search":false},"sourceNatGet":{"mutating":false,"params":0,"path":"/api/firewall/source_nat/get","post":false,"search":false},"sourceNatGetRule":{"mutating":false,"params":1,"path":"/api/firewall/source_nat/getRule","post":false,"search":false},"sourceNatListCategories":{"mutating":false,"params":0,"path":"/api/firewall/source_nat/listCategories","post":false,"search":false},"sourceNatListNetworkSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/source_nat/listNetworkSelectOptions","post":false,"search":false},"sourceNatListPortSelectOptions":{"mutating":false,"params":0,"path":"/api/firewall/source_nat/listPortSelectOptions","post":false,"search":false},"sourceNatMoveRuleBefore":{"mutating":true,"params":2,"path":"/api/firewall/source_nat/moveRuleBefore","post":true,"search":false},"sourceNatSearchRule":{"mutating":false,"params":0,"path":"/api/firewall/source_nat/searchRule","post":false,"search":true},"sourceNatSet":{"mutating":true,"params":0,"path":"/api/firewall/source_nat/set","post":true,"search":false},"sourceNatSetRule":{"mutating":true,"params":1,"path":"/api/firewall/source_nat/setRule","post":true,"search":false},"sourceNatToggleRule":{"mutating":true,"params":2,"path":"/api/firewall/source_nat/toggleRule","post":true,"search":false},"sourceNatToggleRuleLog":{"mutating":true,"params":2,"path":"/api/firewall/source_nat/toggleRuleLog","post":true,"search":false},"sourceNatUploadRules":{"mutating":true,"params":0,"path":"/api/firewall/source_nat/uploadRules","post":true,"search":false}},"firmware":{"firmwareAudit":{"mutating":true,"params":0,"path":"/api/core/firmware/audit","post":true,"search":false},"firmwareChangelog":{"mutating":false,"params":1,"path":"/api/core/firmware/changelog","post":true,"search":false},"firmwareCheck":{"mutating":true,"params":0,"path":"/api/core/firmware/check","post":true,"search":false},"firmwareCleanup":{"mutating":true,"params":0,"path":"/api/core/firmware/cleanup","post":true,"search":false},"firmwareConnection":{"mutating":false,"params":0,"path":"/api/core/firmware/connection","post":false,"search":false},"firmwareDetails":{"mutating":false,"params":1,"path":"/api/core/firmware/details","post":true,"search":false},"firmwareGetOptions":{"mutating":false,"params":0,"path":"/api/core/firmware/getOptions","post":false,"search":false},"firmwareHealth":{"mutating":false,"params":0,"path":"/api/core/firmware/health","post":false,"search":false},"firmwareInfo":{"mutating":false,"params":0,"path":"/api/core/firmware/info","post":false,"search":false},"firmwareInstall":{"mutating":true,"params":1,"path":"/api/core/firmware/install","post":true,"search":false},"firmwareLicense":{"mutating":false,"params":1,"path":"/api/core/firmware/license","post":true,"search":false},"firmwareLock":{"mutating":true,"params":1,"path":"/api/core/firmware/lock","post":true,"search":false},"firmwareLog":{"mutating":false,"params":1,"path":"/api/core/firmware/log","post":true,"search":false},"firmwarePoweroff":{"mutating":true,"params":0,"path":"/api/core/firmware/poweroff","post":true,"search":false},"firmwareReboot":{"mutating":true,"params":0,"path":"/api/core/firmware/reboot","post":true,"search":false},"firmwareReinstall":{"mutating":true,"params":1,"path":"/api/core/firmware/reinstall","post":true,"search":false},"firmwareRemove":{"mutating":true,"params":1,"path":"/api/core/firmware/remove","post":true,"search":false},"firmwareResyncPlugins":{"mutating":true,"params":0,"path":"/api/core/firmware/resyncPlugins","post":true,"search":false},"firmwareRunning":{"mutating":false,"params":0,"path":"/api/core/firmware/running","post":false,"search":false},"firmwareSet":{"mutating":true,"params":0,"path":"/api/core/firmware/set","post":true,"search":false},"firmwareStatus":{"mutating":false,"params":0,"path":"/api/core/firmware/status","post":false,"search":false},"firmwareSyncPlugins":{"mutating":true,"params":0,"path":"/api/core/firmware/syncPlugins","post":true,"search":false},"firmwareUnlock":{"mutating":true,"params":1,"path":"/api/core/firmware/unlock","post":true,"search":false},"firmwareUpdate":{"mutating":true,"params":0,"path":"/api/core/firmware/update","post":true,"search":false},"firmwareUpgrade":{"mutating":true,"params":0,"path":"/api/core/firmware/upgrade","post":true,"search":false},"firmwareUpgradestatus":{"mutating":false,"params":0,"path":"/api/core/firmware/upgradestatus","post":false,"search":false}},"hostdiscovery":{"serviceSearch":{"mutating":false,"params":0,"path":"/api/hostdiscovery/service/search","post":false,"search":true}},"hwprobe":{"serviceReport":{"mutating":false,"params":0,"path":"/api/hwprobe/service/report","post":false,"search":false}},"ids":{"serviceDropAlertLog":{"mutating":true,"params":0,"path":"/api/ids/service/dropAlertLog","post":true,"search":false},"serviceGetAlertInfo":{"mutating":false,"params":2,"path":"/api/ids/service/getAlertInfo","post":false,"search":false},"serviceGetAlertLogs":{"mutating":false,"params":0,"path":"/api/ids/service/getAlertLogs","post":false,"search":false},"serviceQueryAlerts":{"mutating":false,"params":0,"path":"/api/ids/service/queryAlerts","post":false,"search":false},"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/ids/service/reconfigure","post":true,"search":false},"serviceReloadRules":{"mutating":true,"params":0,"path":"/api/ids/service/reloadRules","post":true,"search":false},"serviceUpdateRules":{"mutating":true,"params":1,"path":"/api/ids/service/updateRules","post":true,"search":false},"settingsAddPolicy":{"mutating":true,"params":0,"path":"/api/ids/settings/addPolicy","post":true,"search":false},"settingsAddPolicyRule":{"mutating":true,"params":0,"path":"/api/ids/settings/addPolicyRule","post":true,"search":false},"settingsAddUserRule":{"mutating":true,"params":0,"path":"/api/ids/settings/addUserRule","post":true,"search":false},"settingsCheckPolicyRule":{"mutating":true,"params":0,"path":"/api/ids/settings/checkPolicyRule","post":false,"search":false},"settingsDelPolicy":{"mutating":true,"params":1,"path":"/api/ids/settings/delPolicy","post":true,"search":false},"settingsDelPolicyRule":{"mutating":true,"params":1,"path":"/api/ids/settings/delPolicyRule","post":true,"search":false},"settingsDelUserRule":{"mutating":true,"params":1,"path":"/api/ids/settings/delUserRule","post":true,"search":false},"settingsGetPolicy":{"mutating":false,"params":1,"path":"/api/ids/settings/getPolicy","post":false,"search":false},"settingsGetPolicyRule":{"mutating":false,"params":1,"path":"/api/ids/settings/getPolicyRule","post":false,"search":false},"settingsGetRuleInfo":{"mutating":false,"params":1,"path":"/api/ids/settings/getRuleInfo","post":false,"search":false},"settingsGetRuleset":{"mutating":false,"params":1,"path":"/api/ids/settings/getRuleset","post":false,"search":false},"settingsGetRulesetproperties":{"mutating":false,"params":0,"path":"/api/ids/settings/getRulesetproperties","post":false,"search":false},"settingsGetUserRule":{"mutating":false,"params":1,"path":"/api/ids/settings/getUserRule","post":false,"search":false},"settingsListRuleMetadata":{"mutating":false,"params":0,"path":"/api/ids/settings/listRuleMetadata","post":false,"search":false},"settingsListRulesets":{"mutating":false,"params":0,"path":"/api/ids/settings/listRulesets","post":false,"search":false},"settingsSearchInstalledRules":{"mutating":false,"params":0,"path":"/api/ids/settings/searchInstalledRules","post":false,"search":true},"settingsSearchPolicy":{"mutating":false,"params":0,"path":"/api/ids/settings/searchPolicy","post":false,"search":true},"settingsSearchPolicyRule":{"mutating":false,"params":0,"path":"/api/ids/settings/searchPolicyRule","post":false,"search":true},"settingsSearchUserRule":{"mutating":false,"params":0,"path":"/api/ids/settings/searchUserRule","post":false,"search":true},"settingsSetPolicy":{"mutating":true,"params":1,"path":"/api/ids/settings/setPolicy","post":true,"search":false},"settingsSetPolicyRule":{"mutating":true,"params":1,"path":"/api/ids/settings/setPolicyRule","post":true,"search":false},"settingsSetRule":{"mutating":true,"params":1,"path":"/api/ids/settings/setRule","post":true,"search":false},"settingsSetRuleset":{"mutating":true,"params":1,"path":"/api/ids/settings/setRuleset","post":true,"search":false},"settingsSetRulesetproperties":{"mutating":true,"params":0,"path":"/api/ids/settings/setRulesetproperties","post":true,"search":false},"settingsSetUserRule":{"mutating":true,"params":1,"path":"/api/ids/settings/setUserRule","post":true,"search":false},"settingsTogglePolicy":{"mutating":true,"params":2,"path":"/api/ids/settings/togglePolicy","post":true,"search":false},"settingsTogglePolicyRule":{"mutating":true,"params":2,"path":"/api/ids/settings/togglePolicyRule","post":true,"search":false},"settingsToggleRule":{"mutating":true,"params":2,"path":"/api/ids/settings/toggleRule","post":true,"search":false},"settingsToggleRuleset":{"mutating":true,"params":2,"path":"/api/ids/settings/toggleRuleset","post":true,"search":false},"settingsToggleUserRule":{"mutating":true,"params":2,"path":"/api/ids/settings/toggleUserRule","post":true,"search":false}},"interfaces":{"assignmentAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/assignment/addItem","post":true,"search":false},"assignmentDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/assignment/delItem","post":true,"search":false},"assignmentGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/assignment/getItem","post":false,"search":false},"assignmentReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/assignment/reconfigure","post":true,"search":false},"assignmentSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/assignment/searchItem","post":false,"search":true},"assignmentSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/assignment/setItem","post":true,"search":false},"bridgeSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/bridge_settings/addItem","post":true,"search":false},"bridgeSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/bridge_settings/delItem","post":true,"search":false},"bridgeSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/bridge_settings/getItem","post":false,"search":false},"bridgeSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/bridge_settings/reconfigure","post":true,"search":false},"bridgeSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/bridge_settings/searchItem","post":false,"search":true},"bridgeSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/bridge_settings/setItem","post":true,"search":false},"gifSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/gif_settings/addItem","post":true,"search":false},"gifSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/gif_settings/delItem","post":true,"search":false},"gifSettingsGetIfOptions":{"mutating":false,"params":0,"path":"/api/interfaces/gif_settings/getIfOptions","post":false,"search":false},"gifSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/gif_settings/getItem","post":false,"search":false},"gifSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/gif_settings/reconfigure","post":true,"search":false},"gifSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/gif_settings/searchItem","post":false,"search":true},"gifSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/gif_settings/setItem","post":true,"search":false},"greSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/gre_settings/addItem","post":true,"search":false},"greSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/gre_settings/delItem","post":true,"search":false},"greSettingsGetIfOptions":{"mutating":false,"params":0,"path":"/api/interfaces/gre_settings/getIfOptions","post":false,"search":false},"greSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/gre_settings/getItem","post":false,"search":false},"greSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/gre_settings/reconfigure","post":true,"search":false},"greSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/gre_settings/searchItem","post":false,"search":true},"greSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/gre_settings/setItem","post":true,"search":false},"laggSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/lagg_settings/addItem","post":true,"search":false},"laggSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/lagg_settings/delItem","post":true,"search":false},"laggSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/lagg_settings/getItem","post":false,"search":false},"laggSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/lagg_settings/reconfigure","post":true,"search":false},"laggSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/lagg_settings/searchItem","post":false,"search":true},"laggSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/lagg_settings/setItem","post":true,"search":false},"loopbackSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/loopback_settings/addItem","post":true,"search":false},"loopbackSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/loopback_settings/delItem","post":true,"search":false},"loopbackSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/loopback_settings/getItem","post":false,"search":false},"loopbackSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/loopback_settings/reconfigure","post":true,"search":false},"loopbackSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/loopback_settings/searchItem","post":false,"search":true},"loopbackSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/loopback_settings/setItem","post":true,"search":false},"neighborSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/neighbor_settings/addItem","post":true,"search":false},"neighborSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/neighbor_settings/delItem","post":true,"search":false},"neighborSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/neighbor_settings/getItem","post":false,"search":false},"neighborSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/neighbor_settings/reconfigure","post":true,"search":false},"neighborSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/neighbor_settings/searchItem","post":false,"search":true},"neighborSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/neighbor_settings/setItem","post":true,"search":false},"overviewExport":{"mutating":false,"params":0,"path":"/api/interfaces/overview/export","post":false,"search":false},"overviewGetInterface":{"mutating":false,"params":1,"path":"/api/interfaces/overview/getInterface","post":false,"search":false},"overviewInterfacesInfo":{"mutating":false,"params":1,"path":"/api/interfaces/overview/interfacesInfo","post":false,"search":false},"overviewReloadInterface":{"mutating":false,"params":1,"path":"/api/interfaces/overview/reloadInterface","post":true,"search":false},"settingsGet":{"mutating":false,"params":0,"path":"/api/interfaces/settings/get","post":false,"search":false},"settingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/settings/reconfigure","post":true,"search":false},"vipSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/vip_settings/addItem","post":true,"search":false},"vipSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/vip_settings/delItem","post":true,"search":false},"vipSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/vip_settings/getItem","post":false,"search":false},"vipSettingsGetUnusedVhid":{"mutating":false,"params":0,"path":"/api/interfaces/vip_settings/getUnusedVhid","post":false,"search":false},"vipSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/vip_settings/reconfigure","post":true,"search":false},"vipSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/vip_settings/searchItem","post":false,"search":true},"vipSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/vip_settings/setItem","post":true,"search":false},"vlanSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/vlan_settings/addItem","post":true,"search":false},"vlanSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/vlan_settings/delItem","post":true,"search":false},"vlanSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/vlan_settings/getItem","post":false,"search":false},"vlanSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/vlan_settings/reconfigure","post":true,"search":false},"vlanSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/vlan_settings/searchItem","post":false,"search":true},"vlanSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/vlan_settings/setItem","post":true,"search":false},"vxlanSettingsAddItem":{"mutating":true,"params":0,"path":"/api/interfaces/vxlan_settings/addItem","post":true,"search":false},"vxlanSettingsDelItem":{"mutating":true,"params":1,"path":"/api/interfaces/vxlan_settings/delItem","post":true,"search":false},"vxlanSettingsGetItem":{"mutating":false,"params":1,"path":"/api/interfaces/vxlan_settings/getItem","post":false,"search":false},"vxlanSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/interfaces/vxlan_settings/reconfigure","post":true,"search":false},"vxlanSettingsSearchItem":{"mutating":false,"params":0,"path":"/api/interfaces/vxlan_settings/searchItem","post":false,"search":true},"vxlanSettingsSetItem":{"mutating":true,"params":1,"path":"/api/interfaces/vxlan_settings/setItem","post":true,"search":false}},"ipsec":{"connectionsAddChild":{"mutating":true,"params":0,"path":"/api/ipsec/connections/addChild","post":true,"search":false},"connectionsAddConnection":{"mutating":true,"params":0,"path":"/api/ipsec/connections/addConnection","post":true,"search":false},"connectionsAddLocal":{"mutating":true,"params":0,"path":"/api/ipsec/connections/addLocal","post":true,"search":false},"connectionsAddRemote":{"mutating":true,"params":0,"path":"/api/ipsec/connections/addRemote","post":true,"search":false},"connectionsConnectionExists":{"mutating":false,"params":1,"path":"/api/ipsec/connections/connectionExists","post":false,"search":false},"connectionsDelChild":{"mutating":true,"params":1,"path":"/api/ipsec/connections/delChild","post":true,"search":false},"connectionsDelConnection":{"mutating":true,"params":1,"path":"/api/ipsec/connections/delConnection","post":true,"search":false},"connectionsDelLocal":{"mutating":true,"params":1,"path":"/api/ipsec/connections/delLocal","post":true,"search":false},"connectionsDelRemote":{"mutating":true,"params":1,"path":"/api/ipsec/connections/delRemote","post":true,"search":false},"connectionsGetChild":{"mutating":false,"params":1,"path":"/api/ipsec/connections/getChild","post":false,"search":false},"connectionsGetConnection":{"mutating":false,"params":1,"path":"/api/ipsec/connections/getConnection","post":false,"search":false},"connectionsGetLocal":{"mutating":false,"params":1,"path":"/api/ipsec/connections/getLocal","post":false,"search":false},"connectionsGetRemote":{"mutating":false,"params":1,"path":"/api/ipsec/connections/getRemote","post":false,"search":false},"connectionsIsEnabled":{"mutating":false,"params":0,"path":"/api/ipsec/connections/isEnabled","post":false,"search":false},"connectionsSearchChild":{"mutating":false,"params":0,"path":"/api/ipsec/connections/searchChild","post":false,"search":true},"connectionsSearchConnection":{"mutating":false,"params":0,"path":"/api/ipsec/connections/searchConnection","post":false,"search":true},"connectionsSearchLocal":{"mutating":false,"params":0,"path":"/api/ipsec/connections/searchLocal","post":false,"search":true},"connectionsSearchRemote":{"mutating":false,"params":0,"path":"/api/ipsec/connections/searchRemote","post":false,"search":true},"connectionsSetChild":{"mutating":true,"params":1,"path":"/api/ipsec/connections/setChild","post":true,"search":false},"connectionsSetConnection":{"mutating":true,"params":1,"path":"/api/ipsec/connections/setConnection","post":true,"search":false},"connectionsSetLocal":{"mutating":true,"params":1,"path":"/api/ipsec/connections/setLocal","post":true,"search":false},"connectionsSetRemote":{"mutating":true,"params":1,"path":"/api/ipsec/connections/setRemote","post":true,"search":false},"connectionsSwanctl":{"mutating":false,"params":0,"path":"/api/ipsec/connections/swanctl","post":false,"search":false},"connectionsToggle":{"mutating":true,"params":1,"path":"/api/ipsec/connections/toggle","post":true,"search":false},"connectionsToggleChild":{"mutating":true,"params":2,"path":"/api/ipsec/connections/toggleChild","post":true,"search":false},"connectionsToggleConnection":{"mutating":true,"params":2,"path":"/api/ipsec/connections/toggleConnection","post":true,"search":false},"connectionsToggleLocal":{"mutating":true,"params":2,"path":"/api/ipsec/connections/toggleLocal","post":true,"search":false},"connectionsToggleRemote":{"mutating":true,"params":2,"path":"/api/ipsec/connections/toggleRemote","post":true,"search":false},"keyPairsAddItem":{"mutating":true,"params":0,"path":"/api/ipsec/key_pairs/addItem","post":true,"search":false},"keyPairsDelItem":{"mutating":true,"params":1,"path":"/api/ipsec/key_pairs/delItem","post":true,"search":false},"keyPairsGenKeyPair":{"mutating":true,"params":2,"path":"/api/ipsec/key_pairs/genKeyPair","post":false,"search":false},"keyPairsGetItem":{"mutating":false,"params":1,"path":"/api/ipsec/key_pairs/getItem","post":false,"search":false},"keyPairsSearchItem":{"mutating":false,"params":0,"path":"/api/ipsec/key_pairs/searchItem","post":false,"search":true},"keyPairsSetItem":{"mutating":true,"params":1,"path":"/api/ipsec/key_pairs/setItem","post":true,"search":false},"leasesPools":{"mutating":false,"params":0,"path":"/api/ipsec/leases/pools","post":false,"search":false},"leasesSearch":{"mutating":false,"params":0,"path":"/api/ipsec/leases/search","post":false,"search":true},"legacySubsystemApplyConfig":{"mutating":true,"params":0,"path":"/api/ipsec/legacy_subsystem/applyConfig","post":true,"search":false},"legacySubsystemStatus":{"mutating":false,"params":0,"path":"/api/ipsec/legacy_subsystem/status","post":false,"search":false},"manualSpdAdd":{"mutating":true,"params":0,"path":"/api/ipsec/manual_spd/add","post":true,"search":false},"manualSpdDel":{"mutating":true,"params":1,"path":"/api/ipsec/manual_spd/del","post":true,"search":false},"manualSpdGet":{"mutating":false,"params":1,"path":"/api/ipsec/manual_spd/get","post":false,"search":false},"manualSpdSearch":{"mutating":false,"params":0,"path":"/api/ipsec/manual_spd/search","post":false,"search":true},"manualSpdSet":{"mutating":true,"params":1,"path":"/api/ipsec/manual_spd/set","post":true,"search":false},"manualSpdToggle":{"mutating":true,"params":2,"path":"/api/ipsec/manual_spd/toggle","post":true,"search":false},"poolsAdd":{"mutating":true,"params":0,"path":"/api/ipsec/pools/add","post":true,"search":false},"poolsDel":{"mutating":true,"params":1,"path":"/api/ipsec/pools/del","post":true,"search":false},"poolsGet":{"mutating":false,"params":1,"path":"/api/ipsec/pools/get","post":false,"search":false},"poolsSearch":{"mutating":false,"params":0,"path":"/api/ipsec/pools/search","post":false,"search":true},"poolsSet":{"mutating":true,"params":1,"path":"/api/ipsec/pools/set","post":true,"search":false},"poolsToggle":{"mutating":true,"params":2,"path":"/api/ipsec/pools/toggle","post":true,"search":false},"preSharedKeysAddItem":{"mutating":true,"params":0,"path":"/api/ipsec/pre_shared_keys/addItem","post":true,"search":false},"preSharedKeysDelItem":{"mutating":true,"params":1,"path":"/api/ipsec/pre_shared_keys/delItem","post":true,"search":false},"preSharedKeysGetItem":{"mutating":false,"params":1,"path":"/api/ipsec/pre_shared_keys/getItem","post":false,"search":false},"preSharedKeysSearchItem":{"mutating":false,"params":0,"path":"/api/ipsec/pre_shared_keys/searchItem","post":false,"search":true},"preSharedKeysSetItem":{"mutating":true,"params":1,"path":"/api/ipsec/pre_shared_keys/setItem","post":true,"search":false},"sadDelete":{"mutating":true,"params":1,"path":"/api/ipsec/sad/delete","post":true,"search":false},"sadSearch":{"mutating":false,"params":0,"path":"/api/ipsec/sad/search","post":false,"search":true},"sessionsConnect":{"mutating":true,"params":1,"path":"/api/ipsec/sessions/connect","post":true,"search":false},"sessionsDisconnect":{"mutating":true,"params":1,"path":"/api/ipsec/sessions/disconnect","post":true,"search":false},"sessionsSearchPhase1":{"mutating":false,"params":0,"path":"/api/ipsec/sessions/searchPhase1","post":false,"search":true},"sessionsSearchPhase2":{"mutating":false,"params":0,"path":"/api/ipsec/sessions/searchPhase2","post":false,"search":true},"settingsGet":{"mutating":false,"params":0,"path":"/api/ipsec/settings/get","post":false,"search":false},"spdDelete":{"mutating":true,"params":1,"path":"/api/ipsec/spd/delete","post":true,"search":false},"spdSearch":{"mutating":false,"params":0,"path":"/api/ipsec/spd/search","post":false,"search":true},"tunnelDelPhase1":{"mutating":true,"params":1,"path":"/api/ipsec/tunnel/delPhase1","post":true,"search":false},"tunnelDelPhase2":{"mutating":true,"params":1,"path":"/api/ipsec/tunnel/delPhase2","post":true,"search":false},"tunnelSearchPhase1":{"mutating":false,"params":0,"path":"/api/ipsec/tunnel/searchPhase1","post":false,"search":true},"tunnelSearchPhase2":{"mutating":false,"params":0,"path":"/api/ipsec/tunnel/searchPhase2","post":false,"search":true},"tunnelToggle":{"mutating":true,"params":1,"path":"/api/ipsec/tunnel/toggle","post":true,"search":false},"tunnelTogglePhase1":{"mutating":true,"params":2,"path":"/api/ipsec/tunnel/togglePhase1","post":true,"search":false},"tunnelTogglePhase2":{"mutating":true,"params":2,"path":"/api/ipsec/tunnel/togglePhase2","post":true,"search":false},"vtiAdd":{"mutating":true,"params":0,"path":"/api/ipsec/vti/add","post":true,"search":false},"vtiDel":{"mutating":true,"params":1,"path":"/api/ipsec/vti/del","post":true,"search":false},"vtiGet":{"mutating":false,"params":1,"path":"/api/ipsec/vti/get","post":false,"search":false},"vtiSearch":{"mutating":false,"params":0,"path":"/api/ipsec/vti/search","post":false,"search":true},"vtiSet":{"mutating":true,"params":1,"path":"/api/ipsec/vti/set","post":true,"search":false},"vtiToggle":{"mutating":true,"params":2,"path":"/api/ipsec/vti/toggle","post":true,"search":false}},"kea":{"ctrlAgentGet":{"mutating":false,"params":0,"path":"/api/kea/ctrl_agent/get","post":false,"search":false},"ddnsGet":{"mutating":false,"params":0,"path":"/api/kea/ddns/get","post":false,"search":false},"dhcpv4AddOption":{"mutating":true,"params":0,"path":"/api/kea/dhcpv4/addOption","post":true,"search":false},"dhcpv4AddPeer":{"mutating":true,"params":0,"path":"/api/kea/dhcpv4/addPeer","post":true,"search":false},"dhcpv4AddReservation":{"mutating":true,"params":0,"path":"/api/kea/dhcpv4/addReservation","post":true,"search":false},"dhcpv4AddSubnet":{"mutating":true,"params":0,"path":"/api/kea/dhcpv4/addSubnet","post":true,"search":false},"dhcpv4DelOption":{"mutating":true,"params":1,"path":"/api/kea/dhcpv4/delOption","post":true,"search":false},"dhcpv4DelPeer":{"mutating":true,"params":1,"path":"/api/kea/dhcpv4/delPeer","post":true,"search":false},"dhcpv4DelReservation":{"mutating":true,"params":1,"path":"/api/kea/dhcpv4/delReservation","post":true,"search":false},"dhcpv4DelSubnet":{"mutating":true,"params":1,"path":"/api/kea/dhcpv4/delSubnet","post":true,"search":false},"dhcpv4DownloadReservations":{"mutating":false,"params":0,"path":"/api/kea/dhcpv4/downloadReservations","post":false,"search":false},"dhcpv4Get":{"mutating":false,"params":0,"path":"/api/kea/dhcpv4/get","post":false,"search":false},"dhcpv4GetOption":{"mutating":false,"params":1,"path":"/api/kea/dhcpv4/getOption","post":false,"search":false},"dhcpv4GetPeer":{"mutating":false,"params":1,"path":"/api/kea/dhcpv4/getPeer","post":false,"search":false},"dhcpv4GetReservation":{"mutating":false,"params":1,"path":"/api/kea/dhcpv4/getReservation","post":false,"search":false},"dhcpv4GetSubnet":{"mutating":false,"params":1,"path":"/api/kea/dhcpv4/getSubnet","post":false,"search":false},"dhcpv4SearchOption":{"mutating":false,"params":0,"path":"/api/kea/dhcpv4/searchOption","post":false,"search":true},"dhcpv4SearchPeer":{"mutating":false,"params":0,"path":"/api/kea/dhcpv4/searchPeer","post":false,"search":true},"dhcpv4SearchReservation":{"mutating":false,"params":0,"path":"/api/kea/dhcpv4/searchReservation","post":false,"search":true},"dhcpv4SearchSubnet":{"mutating":false,"params":0,"path":"/api/kea/dhcpv4/searchSubnet","post":false,"search":true},"dhcpv4SetOption":{"mutating":true,"params":1,"path":"/api/kea/dhcpv4/setOption","post":true,"search":false},"dhcpv4SetPeer":{"mutating":true,"params":1,"path":"/api/kea/dhcpv4/setPeer","post":true,"search":false},"dhcpv4SetReservation":{"mutating":true,"params":1,"path":"/api/kea/dhcpv4/setReservation","post":true,"search":false},"dhcpv4SetSubnet":{"mutating":true,"params":1,"path":"/api/kea/dhcpv4/setSubnet","post":true,"search":false},"dhcpv4UploadReservations":{"mutating":true,"params":0,"path":"/api/kea/dhcpv4/uploadReservations","post":true,"search":false},"dhcpv6AddOption":{"mutating":true,"params":0,"path":"/api/kea/dhcpv6/addOption","post":true,"search":false},"dhcpv6AddPdPool":{"mutating":true,"params":0,"path":"/api/kea/dhcpv6/addPdPool","post":true,"search":false},"dhcpv6AddPeer":{"mutating":true,"params":0,"path":"/api/kea/dhcpv6/addPeer","post":true,"search":false},"dhcpv6AddReservation":{"mutating":true,"params":0,"path":"/api/kea/dhcpv6/addReservation","post":true,"search":false},"dhcpv6AddSubnet":{"mutating":true,"params":0,"path":"/api/kea/dhcpv6/addSubnet","post":true,"search":false},"dhcpv6DelOption":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/delOption","post":true,"search":false},"dhcpv6DelPdPool":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/delPdPool","post":true,"search":false},"dhcpv6DelPeer":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/delPeer","post":true,"search":false},"dhcpv6DelReservation":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/delReservation","post":true,"search":false},"dhcpv6DelSubnet":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/delSubnet","post":true,"search":false},"dhcpv6DownloadReservations":{"mutating":false,"params":0,"path":"/api/kea/dhcpv6/downloadReservations","post":false,"search":false},"dhcpv6Get":{"mutating":false,"params":0,"path":"/api/kea/dhcpv6/get","post":false,"search":false},"dhcpv6GetOption":{"mutating":false,"params":1,"path":"/api/kea/dhcpv6/getOption","post":false,"search":false},"dhcpv6GetPdPool":{"mutating":false,"params":1,"path":"/api/kea/dhcpv6/getPdPool","post":false,"search":false},"dhcpv6GetPeer":{"mutating":false,"params":1,"path":"/api/kea/dhcpv6/getPeer","post":false,"search":false},"dhcpv6GetReservation":{"mutating":false,"params":1,"path":"/api/kea/dhcpv6/getReservation","post":false,"search":false},"dhcpv6GetSubnet":{"mutating":false,"params":1,"path":"/api/kea/dhcpv6/getSubnet","post":false,"search":false},"dhcpv6SearchOption":{"mutating":false,"params":0,"path":"/api/kea/dhcpv6/searchOption","post":false,"search":true},"dhcpv6SearchPdPool":{"mutating":false,"params":0,"path":"/api/kea/dhcpv6/searchPdPool","post":false,"search":true},"dhcpv6SearchPeer":{"mutating":false,"params":0,"path":"/api/kea/dhcpv6/searchPeer","post":false,"search":true},"dhcpv6SearchReservation":{"mutating":false,"params":0,"path":"/api/kea/dhcpv6/searchReservation","post":false,"search":true},"dhcpv6SearchSubnet":{"mutating":false,"params":0,"path":"/api/kea/dhcpv6/searchSubnet","post":false,"search":true},"dhcpv6SetOption":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/setOption","post":true,"search":false},"dhcpv6SetPdPool":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/setPdPool","post":true,"search":false},"dhcpv6SetPeer":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/setPeer","post":true,"search":false},"dhcpv6SetReservation":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/setReservation","post":true,"search":false},"dhcpv6SetSubnet":{"mutating":true,"params":1,"path":"/api/kea/dhcpv6/setSubnet","post":true,"search":false},"dhcpv6UploadReservations":{"mutating":true,"params":0,"path":"/api/kea/dhcpv6/uploadReservations","post":true,"search":false},"leases4DelLease":{"mutating":true,"params":1,"path":"/api/kea/leases4/delLease","post":true,"search":false},"leases4Search":{"mutating":false,"params":0,"path":"/api/kea/leases4/search","post":false,"search":true},"leases6DelLease":{"mutating":true,"params":1,"path":"/api/kea/leases6/delLease","post":true,"search":false},"leases6Search":{"mutating":false,"params":0,"path":"/api/kea/leases6/search","post":false,"search":true}},"monit":{"serviceCheck":{"mutating":true,"params":0,"path":"/api/monit/service/check","post":true,"search":false},"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/monit/service/reconfigure","post":true,"search":false},"settingsAddAlert":{"mutating":true,"params":0,"path":"/api/monit/settings/addAlert","post":true,"search":false},"settingsAddService":{"mutating":true,"params":0,"path":"/api/monit/settings/addService","post":true,"search":false},"settingsAddTest":{"mutating":true,"params":0,"path":"/api/monit/settings/addTest","post":true,"search":false},"settingsDelAlert":{"mutating":true,"params":1,"path":"/api/monit/settings/delAlert","post":true,"search":false},"settingsDelService":{"mutating":true,"params":1,"path":"/api/monit/settings/delService","post":true,"search":false},"settingsDelTest":{"mutating":true,"params":1,"path":"/api/monit/settings/delTest","post":true,"search":false},"settingsGetAlert":{"mutating":false,"params":1,"path":"/api/monit/settings/getAlert","post":false,"search":false},"settingsGetGeneral":{"mutating":false,"params":0,"path":"/api/monit/settings/getGeneral","post":false,"search":false},"settingsGetService":{"mutating":false,"params":1,"path":"/api/monit/settings/getService","post":false,"search":false},"settingsGetTest":{"mutating":false,"params":1,"path":"/api/monit/settings/getTest","post":false,"search":false},"settingsSearchAlert":{"mutating":false,"params":0,"path":"/api/monit/settings/searchAlert","post":false,"search":true},"settingsSearchService":{"mutating":false,"params":0,"path":"/api/monit/settings/searchService","post":false,"search":true},"settingsSearchTest":{"mutating":false,"params":0,"path":"/api/monit/settings/searchTest","post":false,"search":true},"settingsSetAlert":{"mutating":true,"params":1,"path":"/api/monit/settings/setAlert","post":true,"search":false},"settingsSetService":{"mutating":true,"params":1,"path":"/api/monit/settings/setService","post":true,"search":false},"settingsSetTest":{"mutating":true,"params":1,"path":"/api/monit/settings/setTest","post":true,"search":false},"settingsToggleAlert":{"mutating":true,"params":2,"path":"/api/monit/settings/toggleAlert","post":true,"search":false},"settingsToggleService":{"mutating":true,"params":2,"path":"/api/monit/settings/toggleService","post":true,"search":false},"statusGet":{"mutating":false,"params":1,"path":"/api/monit/status/get","post":false,"search":false}},"ntpd":{"serviceGps":{"mutating":false,"params":0,"path":"/api/ntpd/service/gps","post":false,"search":false},"serviceMeta":{"mutating":false,"params":0,"path":"/api/ntpd/service/meta","post":false,"search":false},"serviceStatus":{"mutating":false,"params":0,"path":"/api/ntpd/service/status","post":false,"search":false}},"openvpn":{"clientOverwritesAdd":{"mutating":true,"params":0,"path":"/api/openvpn/client_overwrites/add","post":true,"search":false},"clientOverwritesDel":{"mutating":true,"params":1,"path":"/api/openvpn/client_overwrites/del","post":true,"search":false},"clientOverwritesGet":{"mutating":false,"params":1,"path":"/api/openvpn/client_overwrites/get","post":false,"search":false},"clientOverwritesSearch":{"mutating":false,"params":0,"path":"/api/openvpn/client_overwrites/search","post":false,"search":true},"clientOverwritesSet":{"mutating":true,"params":1,"path":"/api/openvpn/client_overwrites/set","post":true,"search":false},"clientOverwritesToggle":{"mutating":true,"params":2,"path":"/api/openvpn/client_overwrites/toggle","post":true,"search":false},"exportAccounts":{"mutating":false,"params":1,"path":"/api/openvpn/export/accounts","post":false,"search":false},"exportDownload":{"mutating":false,"params":2,"path":"/api/openvpn/export/download","post":true,"search":false},"exportProviders":{"mutating":false,"params":0,"path":"/api/openvpn/export/providers","post":false,"search":false},"exportStorePresets":{"mutating":false,"params":1,"path":"/api/openvpn/export/storePresets","post":true,"search":false},"exportTemplates":{"mutating":false,"params":0,"path":"/api/openvpn/export/templates","post":false,"search":false},"exportValidatePresets":{"mutating":false,"params":1,"path":"/api/openvpn/export/validatePresets","post":true,"search":false},"instancesAdd":{"mutating":true,"params":0,"path":"/api/openvpn/instances/add","post":true,"search":false},"instancesAddStaticKey":{"mutating":true,"params":0,"path":"/api/openvpn/instances/addStaticKey","post":true,"search":false},"instancesDel":{"mutating":true,"params":1,"path":"/api/openvpn/instances/del","post":true,"search":false},"instancesDelStaticKey":{"mutating":true,"params":1,"path":"/api/openvpn/instances/delStaticKey","post":true,"search":false},"instancesGenKey":{"mutating":true,"params":1,"path":"/api/openvpn/instances/genKey","post":false,"search":false},"instancesGet":{"mutating":false,"params":1,"path":"/api/openvpn/instances/get","post":false,"search":false},"instancesGetStaticKey":{"mutating":false,"params":1,"path":"/api/openvpn/instances/getStaticKey","post":false,"search":false},"instancesSearch":{"mutating":false,"params":0,"path":"/api/openvpn/instances/search","post":false,"search":true},"instancesSearchStaticKey":{"mutating":false,"params":0,"path":"/api/openvpn/instances/searchStaticKey","post":false,"search":true},"instancesSet":{"mutating":true,"params":1,"path":"/api/openvpn/instances/set","post":true,"search":false},"instancesSetStaticKey":{"mutating":true,"params":1,"path":"/api/openvpn/instances/setStaticKey","post":true,"search":false},"instancesToggle":{"mutating":true,"params":2,"path":"/api/openvpn/instances/toggle","post":true,"search":false},"serviceKillSession":{"mutating":true,"params":0,"path":"/api/openvpn/service/killSession","post":true,"search":false},"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/openvpn/service/reconfigure","post":true,"search":false},"serviceRestartService":{"mutating":true,"params":1,"path":"/api/openvpn/service/restartService","post":true,"search":false},"serviceSearchRoutes":{"mutating":false,"params":0,"path":"/api/openvpn/service/searchRoutes","post":false,"search":true},"serviceSearchSessions":{"mutating":false,"params":0,"path":"/api/openvpn/service/searchSessions","post":false,"search":true},"serviceStartService":{"mutating":true,"params":1,"path":"/api/openvpn/service/startService","post":true,"search":false},"serviceStopService":{"mutating":true,"params":1,"path":"/api/openvpn/service/stopService","post":true,"search":false}},"radvd":{"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/radvd/service/reconfigure","post":true,"search":false},"settingsAddEntry":{"mutating":true,"params":0,"path":"/api/radvd/settings/addEntry","post":true,"search":false},"settingsDelEntry":{"mutating":true,"params":1,"path":"/api/radvd/settings/delEntry","post":true,"search":false},"settingsGetEntry":{"mutating":false,"params":1,"path":"/api/radvd/settings/getEntry","post":false,"search":false},"settingsSearchEntry":{"mutating":false,"params":0,"path":"/api/radvd/settings/searchEntry","post":false,"search":true},"settingsSetEntry":{"mutating":true,"params":1,"path":"/api/radvd/settings/setEntry","post":true,"search":false},"settingsToggleEntry":{"mutating":true,"params":2,"path":"/api/radvd/settings/toggleEntry","post":true,"search":false}},"routes":{"gatewayStatus":{"mutating":false,"params":0,"path":"/api/routes/gateway/status","post":false,"search":false},"routesAddroute":{"mutating":true,"params":0,"path":"/api/routes/routes/addroute","post":true,"search":false},"routesDelroute":{"mutating":false,"params":1,"path":"/api/routes/routes/delroute","post":true,"search":false},"routesGetroute":{"mutating":false,"params":1,"path":"/api/routes/routes/getroute","post":false,"search":false},"routesReconfigure":{"mutating":true,"params":0,"path":"/api/routes/routes/reconfigure","post":true,"search":false},"routesSearchroute":{"mutating":false,"params":0,"path":"/api/routes/routes/searchroute","post":false,"search":true},"routesSetroute":{"mutating":false,"params":1,"path":"/api/routes/routes/setroute","post":true,"search":false},"routesToggleroute":{"mutating":false,"params":2,"path":"/api/routes/routes/toggleroute","post":true,"search":false}},"routing":{"groupSettingsAdd":{"mutating":true,"params":0,"path":"/api/routing/group_settings/add","post":true,"search":false},"groupSettingsDel":{"mutating":true,"params":1,"path":"/api/routing/group_settings/del","post":true,"search":false},"groupSettingsGet":{"mutating":false,"params":1,"path":"/api/routing/group_settings/get","post":false,"search":false},"groupSettingsReconfigure":{"mutating":true,"params":0,"path":"/api/routing/group_settings/reconfigure","post":true,"search":false},"groupSettingsSearch":{"mutating":false,"params":0,"path":"/api/routing/group_settings/search","post":false,"search":true},"groupSettingsSet":{"mutating":true,"params":1,"path":"/api/routing/group_settings/set","post":true,"search":false},"settingsAddGateway":{"mutating":true,"params":0,"path":"/api/routing/settings/addGateway","post":true,"search":false},"settingsDelGateway":{"mutating":true,"params":1,"path":"/api/routing/settings/delGateway","post":true,"search":false},"settingsGetGateway":{"mutating":false,"params":1,"path":"/api/routing/settings/getGateway","post":false,"search":false},"settingsReconfigure":{"mutating":true,"params":0,"path":"/api/routing/settings/reconfigure","post":true,"search":false},"settingsSearchGateway":{"mutating":false,"params":0,"path":"/api/routing/settings/searchGateway","post":false,"search":true},"settingsSetGateway":{"mutating":true,"params":1,"path":"/api/routing/settings/setGateway","post":true,"search":false},"settingsToggleGateway":{"mutating":true,"params":2,"path":"/api/routing/settings/toggleGateway","post":true,"search":false}},"syslog":{"serviceReset":{"mutating":true,"params":0,"path":"/api/syslog/service/reset","post":true,"search":false},"serviceStats":{"mutating":false,"params":0,"path":"/api/syslog/service/stats","post":false,"search":false},"settingsAddDestination":{"mutating":true,"params":0,"path":"/api/syslog/settings/addDestination","post":true,"search":false},"settingsDelDestination":{"mutating":true,"params":1,"path":"/api/syslog/settings/delDestination","post":true,"search":false},"settingsGetDestination":{"mutating":false,"params":1,"path":"/api/syslog/settings/getDestination","post":false,"search":false},"settingsSearchDestinations":{"mutating":false,"params":0,"path":"/api/syslog/settings/searchDestinations","post":false,"search":true},"settingsSetDestination":{"mutating":true,"params":1,"path":"/api/syslog/settings/setDestination","post":true,"search":false},"settingsToggleDestination":{"mutating":true,"params":2,"path":"/api/syslog/settings/toggleDestination","post":true,"search":false}},"telegraf":{"generalGet":{"mutating":false,"params":0,"path":"/api/telegraf/general/get","post":false,"search":false},"generalSet":{"mutating":true,"params":0,"path":"/api/telegraf/general/set","post":true,"search":false},"inputGet":{"mutating":false,"params":0,"path":"/api/telegraf/input/get","post":false,"search":false},"inputSet":{"mutating":true,"params":0,"path":"/api/telegraf/input/set","post":true,"search":false},"keyAddKey":{"mutating":true,"params":0,"path":"/api/telegraf/key/addKey","post":true,"search":false},"keyDelKey":{"mutating":true,"params":1,"path":"/api/telegraf/key/delKey","post":true,"search":false},"keyGetKey":{"mutating":false,"params":1,"path":"/api/telegraf/key/getKey","post":false,"search":false},"keySearchKey":{"mutating":false,"params":0,"path":"/api/telegraf/key/searchKey","post":false,"search":true},"keySetKey":{"mutating":true,"params":1,"path":"/api/telegraf/key/setKey","post":true,"search":false},"keyToggleKey":{"mutating":true,"params":1,"path":"/api/telegraf/key/toggleKey","post":true,"search":false},"outputGet":{"mutating":false,"params":0,"path":"/api/telegraf/output/get","post":false,"search":false},"outputSet":{"mutating":true,"params":0,"path":"/api/telegraf/output/set","post":true,"search":false},"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/telegraf/service/reconfigure","post":true,"search":false},"serviceRestart":{"mutating":true,"params":0,"path":"/api/telegraf/service/restart","post":true,"search":false},"serviceStart":{"mutating":true,"params":0,"path":"/api/telegraf/service/start","post":true,"search":false},"serviceStatus":{"mutating":false,"params":0,"path":"/api/telegraf/service/status","post":false,"search":false},"serviceStop":{"mutating":true,"params":0,"path":"/api/telegraf/service/stop","post":true,"search":false}},"trafficshaper":{"serviceFlushreload":{"mutating":true,"params":0,"path":"/api/trafficshaper/service/flushreload","post":true,"search":false},"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/trafficshaper/service/reconfigure","post":true,"search":false},"serviceStatistics":{"mutating":false,"params":0,"path":"/api/trafficshaper/service/statistics","post":false,"search":false},"settingsAddPipe":{"mutating":true,"params":0,"path":"/api/trafficshaper/settings/addPipe","post":true,"search":false},"settingsAddQueue":{"mutating":true,"params":0,"path":"/api/trafficshaper/settings/addQueue","post":true,"search":false},"settingsAddRule":{"mutating":true,"params":0,"path":"/api/trafficshaper/settings/addRule","post":true,"search":false},"settingsDelPipe":{"mutating":true,"params":1,"path":"/api/trafficshaper/settings/delPipe","post":true,"search":false},"settingsDelQueue":{"mutating":true,"params":1,"path":"/api/trafficshaper/settings/delQueue","post":true,"search":false},"settingsDelRule":{"mutating":true,"params":1,"path":"/api/trafficshaper/settings/delRule","post":true,"search":false},"settingsDownloadPipes":{"mutating":false,"params":0,"path":"/api/trafficshaper/settings/downloadPipes","post":false,"search":false},"settingsDownloadQueues":{"mutating":false,"params":0,"path":"/api/trafficshaper/settings/downloadQueues","post":false,"search":false},"settingsGetPipe":{"mutating":false,"params":1,"path":"/api/trafficshaper/settings/getPipe","post":false,"search":false},"settingsGetQueue":{"mutating":false,"params":1,"path":"/api/trafficshaper/settings/getQueue","post":false,"search":false},"settingsGetRule":{"mutating":false,"params":1,"path":"/api/trafficshaper/settings/getRule","post":false,"search":false},"settingsSearchPipes":{"mutating":false,"params":0,"path":"/api/trafficshaper/settings/searchPipes","post":false,"search":true},"settingsSearchQueues":{"mutating":false,"params":0,"path":"/api/trafficshaper/settings/searchQueues","post":false,"search":true},"settingsSearchRules":{"mutating":false,"params":0,"path":"/api/trafficshaper/settings/searchRules","post":false,"search":true},"settingsSetPipe":{"mutating":true,"params":1,"path":"/api/trafficshaper/settings/setPipe","post":true,"search":false},"settingsSetQueue":{"mutating":true,"params":1,"path":"/api/trafficshaper/settings/setQueue","post":true,"search":false},"settingsSetRule":{"mutating":true,"params":1,"path":"/api/trafficshaper/settings/setRule","post":true,"search":false},"settingsTogglePipe":{"mutating":true,"params":2,"path":"/api/trafficshaper/settings/togglePipe","post":true,"search":false},"settingsToggleQueue":{"mutating":true,"params":2,"path":"/api/trafficshaper/settings/toggleQueue","post":true,"search":false},"settingsToggleRule":{"mutating":true,"params":2,"path":"/api/trafficshaper/settings/toggleRule","post":true,"search":false},"settingsUploadPipes":{"mutating":true,"params":0,"path":"/api/trafficshaper/settings/uploadPipes","post":true,"search":false},"settingsUploadQueues":{"mutating":true,"params":0,"path":"/api/trafficshaper/settings/uploadQueues","post":true,"search":false}},"trust":{"caAdd":{"mutating":true,"params":0,"path":"/api/trust/ca/add","post":true,"search":false},"caCaInfo":{"mutating":false,"params":1,"path":"/api/trust/ca/caInfo","post":false,"search":false},"caCaList":{"mutating":false,"params":0,"path":"/api/trust/ca/caList","post":false,"search":false},"caDel":{"mutating":true,"params":1,"path":"/api/trust/ca/del","post":true,"search":false},"caGenerateFile":{"mutating":true,"params":2,"path":"/api/trust/ca/generateFile","post":true,"search":false},"caGet":{"mutating":false,"params":1,"path":"/api/trust/ca/get","post":false,"search":false},"caRawDump":{"mutating":false,"params":1,"path":"/api/trust/ca/rawDump","post":false,"search":false},"caSearch":{"mutating":false,"params":0,"path":"/api/trust/ca/search","post":false,"search":true},"caSet":{"mutating":true,"params":1,"path":"/api/trust/ca/set","post":true,"search":false},"certAdd":{"mutating":true,"params":0,"path":"/api/trust/cert/add","post":true,"search":false},"certCaInfo":{"mutating":false,"params":1,"path":"/api/trust/cert/caInfo","post":false,"search":false},"certCaList":{"mutating":false,"params":0,"path":"/api/trust/cert/caList","post":false,"search":false},"certDel":{"mutating":true,"params":1,"path":"/api/trust/cert/del","post":true,"search":false},"certGenerateFile":{"mutating":true,"params":2,"path":"/api/trust/cert/generateFile","post":true,"search":false},"certGet":{"mutating":false,"params":1,"path":"/api/trust/cert/get","post":false,"search":false},"certRawDump":{"mutating":false,"params":1,"path":"/api/trust/cert/rawDump","post":false,"search":false},"certSearch":{"mutating":false,"params":0,"path":"/api/trust/cert/search","post":false,"search":true},"certSet":{"mutating":true,"params":1,"path":"/api/trust/cert/set","post":true,"search":false},"certUserList":{"mutating":false,"params":0,"path":"/api/trust/cert/userList","post":false,"search":false},"crlDel":{"mutating":true,"params":1,"path":"/api/trust/crl/del","post":true,"search":false},"crlGet":{"mutating":false,"params":1,"path":"/api/trust/crl/get","post":false,"search":false},"crlGetOcspInfoData":{"mutating":false,"params":1,"path":"/api/trust/crl/getOcspInfoData","post":false,"search":false},"crlRawDump":{"mutating":false,"params":1,"path":"/api/trust/crl/rawDump","post":false,"search":false},"crlSearch":{"mutating":false,"params":0,"path":"/api/trust/crl/search","post":false,"search":true},"crlSet":{"mutating":true,"params":1,"path":"/api/trust/crl/set","post":true,"search":false},"settingsReconfigure":{"mutating":true,"params":0,"path":"/api/trust/settings/reconfigure","post":true,"search":false}},"unbound":{"diagnosticsDumpcache":{"mutating":false,"params":0,"path":"/api/unbound/diagnostics/dumpcache","post":false,"search":false},"diagnosticsDumpinfra":{"mutating":true,"params":0,"path":"/api/unbound/diagnostics/dumpinfra","post":true,"search":false},"diagnosticsListinsecure":{"mutating":false,"params":0,"path":"/api/unbound/diagnostics/listinsecure","post":false,"search":false},"diagnosticsListlocaldata":{"mutating":false,"params":0,"path":"/api/unbound/diagnostics/listlocaldata","post":false,"search":false},"diagnosticsListlocalzones":{"mutating":false,"params":0,"path":"/api/unbound/diagnostics/listlocalzones","post":false,"search":false},"diagnosticsStats":{"mutating":false,"params":0,"path":"/api/unbound/diagnostics/stats","post":false,"search":false},"diagnosticsTestBlocklist":{"mutating":true,"params":0,"path":"/api/unbound/diagnostics/testBlocklist","post":true,"search":false},"overviewGetPolicies":{"mutating":false,"params":0,"path":"/api/unbound/overview/getPolicies","post":false,"search":false},"overviewIsBlockListEnabled":{"mutating":false,"params":0,"path":"/api/unbound/overview/isBlockListEnabled","post":false,"search":false},"overviewIsEnabled":{"mutating":false,"params":0,"path":"/api/unbound/overview/isEnabled","post":false,"search":false},"overviewReset":{"mutating":true,"params":0,"path":"/api/unbound/overview/reset","post":true,"search":false},"overviewRolling":{"mutating":false,"params":2,"path":"/api/unbound/overview/Rolling","post":false,"search":false},"overviewSearchQueries":{"mutating":false,"params":0,"path":"/api/unbound/overview/searchQueries","post":false,"search":true},"overviewTotals":{"mutating":false,"params":1,"path":"/api/unbound/overview/totals","post":false,"search":false},"serviceDnsbl":{"mutating":true,"params":0,"path":"/api/unbound/service/dnsbl","post":true,"search":false},"serviceReconfigureGeneral":{"mutating":true,"params":0,"path":"/api/unbound/service/reconfigureGeneral","post":true,"search":false},"settingsAddAcl":{"mutating":true,"params":0,"path":"/api/unbound/settings/addAcl","post":true,"search":false},"settingsAddDnsbl":{"mutating":true,"params":0,"path":"/api/unbound/settings/addDnsbl","post":true,"search":false},"settingsAddForward":{"mutating":true,"params":0,"path":"/api/unbound/settings/addForward","post":true,"search":false},"settingsAddHostAlias":{"mutating":true,"params":0,"path":"/api/unbound/settings/addHostAlias","post":true,"search":false},"settingsAddHostOverride":{"mutating":true,"params":0,"path":"/api/unbound/settings/addHostOverride","post":true,"search":false},"settingsDelAcl":{"mutating":true,"params":1,"path":"/api/unbound/settings/delAcl","post":true,"search":false},"settingsDelDnsbl":{"mutating":true,"params":1,"path":"/api/unbound/settings/delDnsbl","post":true,"search":false},"settingsDelForward":{"mutating":true,"params":1,"path":"/api/unbound/settings/delForward","post":true,"search":false},"settingsDelHostAlias":{"mutating":true,"params":1,"path":"/api/unbound/settings/delHostAlias","post":true,"search":false},"settingsDelHostOverride":{"mutating":true,"params":1,"path":"/api/unbound/settings/delHostOverride","post":true,"search":false},"settingsGetAcl":{"mutating":false,"params":1,"path":"/api/unbound/settings/getAcl","post":false,"search":false},"settingsGetDnsbl":{"mutating":false,"params":1,"path":"/api/unbound/settings/getDnsbl","post":false,"search":false},"settingsGetForward":{"mutating":false,"params":1,"path":"/api/unbound/settings/getForward","post":false,"search":false},"settingsGetHostAlias":{"mutating":false,"params":1,"path":"/api/unbound/settings/getHostAlias","post":false,"search":false},"settingsGetHostOverride":{"mutating":false,"params":1,"path":"/api/unbound/settings/getHostOverride","post":false,"search":false},"settingsGetNameservers":{"mutating":false,"params":0,"path":"/api/unbound/settings/getNameservers","post":false,"search":false},"settingsSearchAcl":{"mutating":false,"params":0,"path":"/api/unbound/settings/searchAcl","post":false,"search":true},"settingsSearchDnsbl":{"mutating":false,"params":0,"path":"/api/unbound/settings/searchDnsbl","post":false,"search":true},"settingsSearchForward":{"mutating":false,"params":0,"path":"/api/unbound/settings/searchForward","post":false,"search":true},"settingsSearchHostAlias":{"mutating":false,"params":0,"path":"/api/unbound/settings/searchHostAlias","post":false,"search":true},"settingsSearchHostOverride":{"mutating":false,"params":0,"path":"/api/unbound/settings/searchHostOverride","post":false,"search":true},"settingsSetAcl":{"mutating":true,"params":1,"path":"/api/unbound/settings/setAcl","post":true,"search":false},"settingsSetDnsbl":{"mutating":true,"params":1,"path":"/api/unbound/settings/setDnsbl","post":true,"search":false},"settingsSetForward":{"mutating":true,"params":1,"path":"/api/unbound/settings/setForward","post":true,"search":false},"settingsSetHostAlias":{"mutating":true,"params":1,"path":"/api/unbound/settings/setHostAlias","post":true,"search":false},"settingsSetHostOverride":{"mutating":true,"params":1,"path":"/api/unbound/settings/setHostOverride","post":true,"search":false},"settingsToggleAcl":{"mutating":true,"params":2,"path":"/api/unbound/settings/toggleAcl","post":true,"search":false},"settingsToggleDnsbl":{"mutating":true,"params":2,"path":"/api/unbound/settings/toggleDnsbl","post":true,"search":false},"settingsToggleForward":{"mutating":true,"params":2,"path":"/api/unbound/settings/toggleForward","post":true,"search":false},"settingsToggleHostAlias":{"mutating":true,"params":2,"path":"/api/unbound/settings/toggleHostAlias","post":true,"search":false},"settingsToggleHostOverride":{"mutating":true,"params":2,"path":"/api/unbound/settings/toggleHostOverride","post":true,"search":false},"settingsUpdateBlocklist":{"mutating":true,"params":0,"path":"/api/unbound/settings/updateBlocklist","post":true,"search":false}},"wireguard":{"clientAddClient":{"mutating":true,"params":0,"path":"/api/wireguard/client/addClient","post":true,"search":false},"clientAddClientBuilder":{"mutating":true,"params":0,"path":"/api/wireguard/client/addClientBuilder","post":true,"search":false},"clientDelClient":{"mutating":true,"params":1,"path":"/api/wireguard/client/delClient","post":true,"search":false},"clientGetClient":{"mutating":false,"params":1,"path":"/api/wireguard/client/getClient","post":false,"search":false},"clientGetClientBuilder":{"mutating":false,"params":0,"path":"/api/wireguard/client/getClientBuilder","post":false,"search":false},"clientGetServerInfo":{"mutating":false,"params":1,"path":"/api/wireguard/client/getServerInfo","post":false,"search":false},"clientListServers":{"mutating":false,"params":0,"path":"/api/wireguard/client/listServers","post":false,"search":false},"clientPsk":{"mutating":false,"params":0,"path":"/api/wireguard/client/psk","post":false,"search":false},"clientSearchClient":{"mutating":false,"params":0,"path":"/api/wireguard/client/searchClient","post":false,"search":true},"clientSetClient":{"mutating":true,"params":1,"path":"/api/wireguard/client/setClient","post":true,"search":false},"clientToggleClient":{"mutating":true,"params":1,"path":"/api/wireguard/client/toggleClient","post":true,"search":false},"serverAddServer":{"mutating":true,"params":1,"path":"/api/wireguard/server/addServer","post":true,"search":false},"serverDelServer":{"mutating":true,"params":1,"path":"/api/wireguard/server/delServer","post":true,"search":false},"serverGetServer":{"mutating":false,"params":1,"path":"/api/wireguard/server/getServer","post":false,"search":false},"serverKeyPair":{"mutating":false,"params":0,"path":"/api/wireguard/server/keyPair","post":false,"search":false},"serverSearchServer":{"mutating":false,"params":0,"path":"/api/wireguard/server/searchServer","post":false,"search":true},"serverSetServer":{"mutating":true,"params":1,"path":"/api/wireguard/server/setServer","post":true,"search":false},"serverToggleServer":{"mutating":true,"params":1,"path":"/api/wireguard/server/toggleServer","post":true,"search":false},"serviceReconfigure":{"mutating":true,"params":0,"path":"/api/wireguard/service/reconfigure","post":true,"search":false},"serviceShow":{"mutating":false,"params":0,"path":"/api/wireguard/service/show","post":false,"search":false}}};
const PLUGIN_MODULES = ["telegraf","dmidecode","hwprobe"];

// One caller for every discovered route. The dispatcher hands methods
// (uuid, body) or (body), so: leading primitives fill the path parameters the
// controller action declares, and the first object is the body. Two-parameter
// actions (toggleRuleLog(uuid, log), toggleroute(uuid, enabled)) take both
// segments. Anything more exotic goes through params.args.
function makeRoute(mod, r) {
  const seg = (v) => v !== undefined && v !== null && typeof v !== 'object';
  return function (a, b) {
    let url = r.path;
    let body;
    if (r.params > 0 && seg(a)) {
      url += '/' + a;
      if (r.params > 1 && seg(b)) {
        url += '/' + b;
      } else {
        body = b;
      }
    } else {
      body = typeof a === 'object' && a !== null ? a : b;
    }
    if (!r.post) {
      return mod.http.get(url, undefined);
    }
    return mod.http.post(url, body || (r.search ? { current: 1, rowCount: 5000 } : {}), undefined);
  };
}

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

      // OPNsense 26.7 moved the captive-portal template actions off
      // ServiceController onto a TemplateController. The fleet straddles the
      // change (26.1.11 and 26.7 both in production), so keep the pre-26.7
      // method names working on both: new route first, old route on 404.
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
        // FORK ADD (NAT search/apply): client 0.5.3 also omits searchRule and
        // apply for source_nat / one_to_one / npt, so those rule families could
        // be written but never ENUMERATED or APPLIED via the MCP (writes only
        // stage config). Routes verified live 2026-06-11 (homelab OPNsense:
        // searchRule 200 for all three).
        __fw.sourceNatSearchRule = (data, config) => __fw.http.post('/api/firewall/source_nat/searchRule', data || { current: 1, rowCount: 5000 }, config);
        __fw.sourceNatApply = (data, config) => __fw.http.post('/api/firewall/source_nat/apply', data || {}, config);
        __fw.oneToOneSearchRule = (data, config) => __fw.http.post('/api/firewall/one_to_one/searchRule', data || { current: 1, rowCount: 5000 }, config);
        __fw.oneToOneApply = (data, config) => __fw.http.post('/api/firewall/one_to_one/apply', data || {}, config);
        __fw.nptSearchRule = (data, config) => __fw.http.post('/api/firewall/npt/searchRule', data || { current: 1, rowCount: 5000 }, config);
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
          return __kea.http.post(KR + 'searchReservation', { current: 1, rowCount: 5000, ...body }, config);
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
        throw new McpError(ErrorCode.MethodNotFound, `Tool ${name} not found`);
      }

      // Skip plugin tools if not enabled
      if (tool.module === 'plugins' && !this.config.includePlugins) {
        throw new McpError(ErrorCode.MethodNotFound, `Plugin tools not enabled. Use --plugins flag to enable.`);
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
            errorMessage = `HTTP ${response.status}: ${response.statusText}\n`;
            if (response.data) {
              errorMessage += `Response: ${JSON.stringify(response.data, null, 2)}`;
            }
          }
        }
        
        return {
          content: [{
            type: 'text',
            text: `Error calling ${tool.name}.${args.method || 'unknown'}: ${errorMessage}`
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
      throw new Error(`Missing required parameter 'method'. Available methods: ${tool.methods.join(', ')}`);
    }
    
    if (!tool.methods.includes(args.method)) {
      throw new Error(`Invalid method '${args.method}'. Available methods: ${tool.methods.join(', ')}`);
    }
    
    // Get the module
    let moduleObj;
    if (tool.module === 'plugins' && tool.submodule) {
      moduleObj = client.plugins[tool.submodule];
    } else {
      moduleObj = client[tool.module];
    }

    if (!moduleObj) {
      throw new Error(`Module ${tool.module} not found`);
    }

    // Get the method
    const method = moduleObj[args.method];
    if (!method || typeof method !== 'function') {
      throw new Error(`Method ${args.method} not found in module ${tool.module}`);
    }

    // Call the method with params (if provided)
    console.error(`Calling ${tool.module}.${args.method} with params:`, args.params);
    
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
    console.error(`Core tools: 28 modules`);
    console.error(`Plugin tools: 64 modules (${this.config.includePlugins ? 'enabled' : 'disabled'})`);
    console.error(`Total available: ${this.config.includePlugins ? '92' : '28'} modules`);
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
  console.log(`
OPNsense MCP Server v0.6.0 (Modular Edition)

Usage: opnsense-mcp-server --url <url> --api-key <key> --api-secret <secret> [options]

Required:
  -u, --url <url>           OPNsense API URL (e.g., https://192.168.1.1)
  -k, --api-key <key>       API Key for authentication
  -s, --api-secret <secret> API Secret for authentication

Options:
  --no-verify-ssl           Disable SSL certificate verification
  --plugins                 Include plugin tools (adds 64 plugin modules)
  -h, --help                Show this help message

Environment Variables:
  OPNSENSE_URL              OPNsense API URL
  OPNSENSE_API_KEY          API Key
  OPNSENSE_API_SECRET       API Secret
  OPNSENSE_VERIFY_SSL       Set to 'false' to disable SSL verification
  INCLUDE_PLUGINS           Set to 'true' to include plugin tools

Examples:
  # Basic usage (28 core modules)
  opnsense-mcp-server --url https://192.168.1.1 --api-key mykey --api-secret mysecret

  # With plugins enabled (92 total modules)
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
`);
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
    console.error('Error: Missing required arguments\n');
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
