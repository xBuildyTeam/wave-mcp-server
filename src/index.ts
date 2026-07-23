/**
 * Wave OS MCP Server
 * 
 * Three layers exposed to AI coding assistants:
 * 1. Base44 Backend — entities, functions, files, auth
 * 2. Theta Compute — GPU provisioning, blockchain, smart contracts
 * 3. Wave OS Intelligence — agent orchestration, memory, chief of staff
 * 
 * Built by xBuildy for the Base44 Dev Build-Off Competition
 * July 2026
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// ============================================================
// CONFIG — Set these via environment variables or hardcode
// ============================================================

const BASE44_APP_ID = process.env.BASE44_APP_ID || "";
const BASE44_API_KEY = process.env.BASE44_API_KEY || "";
const BASE44_BASE_URL = process.env.BASE44_BASE_URL || "https://api.base44.com";
const THETA_API_KEY = process.env.THETA_API_KEY || "";
const THETA_PROJECT_ID = process.env.THETA_PROJECT_ID || "";
const THETA_RPC_URL = process.env.THETA_RPC_URL || "https://theta-rpc.thetatoken.org";
const THETA_EDGE_URL = process.env.THETA_EDGE_URL || "https://controller.thetaedgecloud.com";

// ============================================================
// HELPERS
// ============================================================

async function base44Fetch(path, options = {}) {
  const url = `${BASE44_BASE_URL}${path}`;
  const headers = {
    "Content-Type": "application/json",
    "x-api-key": BASE44_API_KEY,
    ...options.headers,
  };
  
  const response = await fetch(url, {
    ...options,
    headers,
  });
  
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Base44 API error ${response.status}: ${text}`);
  }
  
  return response.json();
}

async function thetaFetch(path, options = {}) {
  const url = `${THETA_EDGE_URL}${path}`;
  const headers = {
    "Content-Type": "application/json",
    "x-api-key": THETA_API_KEY,
    ...options.headers,
  };
  
  const response = await fetch(url, {
    ...options,
    headers,
  });
  
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Theta API error ${response.status}: ${text}`);
  }
  
  return response.json();
}

async function thetaRpc(method, params = []) {
  const response = await fetch(THETA_RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: Date.now(),
      method,
      params,
    }),
  });
  
  const data = await response.json();
  if (data.error) throw new Error(`Theta RPC error: ${data.error.message}`);
  return data.result;
}

// ============================================================
// TOOL DEFINITIONS
// ============================================================

const tools = [
  // ──────────────────────────────────────────────────────────
  // LAYER 1: BASE44 BACKEND — Data Layer
  // ──────────────────────────────────────────────────────────
  
  {
    name: "list_entities",
    description: "List all entity schemas in the Base44 app. Returns entity names and their field definitions.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "create_entity",
    description: "Create a new entity schema (database table) on the Base44 backend. Provide a name and JSON schema definition.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "PascalCase entity name (e.g. 'Customer', 'Order')" },
        schema: { type: "object", description: "JSON schema defining entity fields" },
      },
      required: ["entity_name", "schema"],
    },
  },
  {
    name: "read_records",
    description: "Read records from a Base44 entity. Supports filtering, sorting, pagination, and field projection.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "Entity name to read from" },
        query: { type: "object", description: "Filter object (e.g. {status: 'active'})" },
        limit: { type: "number", description: "Max records to return (default 50, max 500)" },
        skip: { type: "number", description: "Records to skip for pagination" },
        sort: { type: "string", description: "Sort field with optional - prefix for descending" },
        fields: { type: "array", items: { type: "string" }, description: "Fields to project (reduces payload)" },
      },
      required: ["entity_name"],
    },
  },
  {
    name: "create_records",
    description: "Create one or more records in a Base44 entity. Pass an array of data objects.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "Entity name to create records in" },
        data: { type: "array", items: { type: "object" }, description: "Array of record data objects" },
      },
      required: ["entity_name", "data"],
    },
  },
  {
    name: "update_records",
    description: "Update records in a Base44 entity that match a query filter.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "Entity name to update" },
        query: { type: "object", description: "Filter to select records to update" },
        data: { type: "object", description: "Data to update matching records with" },
      },
      required: ["entity_name", "query", "data"],
    },
  },
  {
    name: "delete_records",
    description: "Delete records from a Base44 entity that match a query filter.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "Entity name to delete from" },
        query: { type: "object", description: "Filter to select records to delete" },
      },
      required: ["entity_name", "query"],
    },
  },
  {
    name: "aggregate_records",
    description: "Run a MongoDB aggregation pipeline over a Base44 entity for complex reads (group-by, counts, sums, averages, top-N).",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "Entity name to aggregate" },
        pipeline: { type: "array", items: { type: "object" }, description: "MongoDB aggregation pipeline stages" },
      },
      required: ["entity_name", "pipeline"],
    },
  },
  {
    name: "call_function",
    description: "Call a deployed Base44 backend function via HTTP. Pass function name, method, and payload.",
    inputSchema: {
      type: "object",
      properties: {
        function_name: { type: "string", description: "Deployed backend function name" },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"], description: "HTTP method (default POST)" },
        payload: { type: "object", description: "JSON body to send to the function" },
      },
      required: ["function_name"],
    },
  },
  {
    name: "upload_file",
    description: "Upload a file to Base44 public storage and get a CDN-backed URL.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: { type: "string", description: "Path to the file to upload" },
      },
      required: ["file_path"],
    },
  },

  // ──────────────────────────────────────────────────────────
  // LAYER 2: THETA COMPUTE — GPU + Blockchain
  // ──────────────────────────────────────────────────────────
  
  {
    name: "theta_list_models",
    description: "List available AI models on Theta EdgeCloud for inference tasks.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "theta_run_inference",
    description: "Send a prompt to a Theta EdgeCloud AI model for inference. Returns the model's response.",
    inputSchema: {
      type: "object",
      properties: {
        model: { type: "string", description: "Model ID (e.g. 'chtz4ssnbcf405uy4e05')" },
        messages: { type: "array", items: { type: "object" }, description: "Chat messages array [{role, content}]" },
        max_tokens: { type: "number", description: "Max tokens to generate (default 2048)" },
        temperature: { type: "number", description: "Temperature (0-2, default 0.7)" },
      },
      required: ["model", "messages"],
    },
  },
  {
    name: "theta_check_gpu_status",
    description: "Check status of running Theta EdgeCloud GPU instances for this project.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "theta_estimate_cost",
    description: "Estimate TFUEL cost for a GPU compute job before running it.",
    inputSchema: {
      type: "object",
      properties: {
        model: { type: "string", description: "Model ID to estimate for" },
        duration_minutes: { type: "number", description: "Estimated runtime in minutes" },
      },
      required: ["model", "duration_minutes"],
    },
  },
  {
    name: "theta_deploy_contract",
    description: "Deploy a smart contract to Theta mainnet. Pass compiled bytecode and ABI. Uses evmVersion istanbul (no PUSH0).",
    inputSchema: {
      type: "object",
      properties: {
        bytecode: { type: "string", description: "Hex-encoded contract bytecode (with 0x prefix)" },
        abi: { type: "array", items: { type: "object" }, description: "Contract ABI" },
        constructor_args: { type: "array", items: { type: "string" }, description: "Constructor arguments (hex encoded)" },
      },
      required: ["bytecode", "abi"],
    },
  },
  {
    name: "theta_read_contract",
    description: "Call a view/read function on a deployed Theta smart contract.",
    inputSchema: {
      type: "object",
      properties: {
        contract_address: { type: "string", description: "Contract address" },
        function_signature: { type: "string", description: "Function signature hash (e.g. '0x70a08231' for balanceOf)" },
        params: { type: "array", items: { type: "string" }, description: "Encoded function parameters" },
      },
      required: ["contract_address", "function_signature"],
    },
  },
  {
    name: "theta_get_balance",
    description: "Get TFUEL and WAVE token balance for a wallet address on Theta mainnet.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string", description: "Wallet address to check" },
        token_contract: { type: "string", description: "Optional TNT20 token contract address (defaults to WAVE token)" },
      },
      required: ["wallet_address"],
    },
  },
  {
    name: "theta_get_transaction",
    description: "Fetch transaction details by hash from Theta mainnet.",
    inputSchema: {
      type: "object",
      properties: {
        tx_hash: { type: "string", description: "Transaction hash" },
      },
      required: ["tx_hash"],
    },
  },

  // ──────────────────────────────────────────────────────────
  // LAYER 3: WAVE OS INTELLIGENCE — Agent Orchestration
  // ──────────────────────────────────────────────────────────
  
  {
    name: "wave_morning_briefing",
    description: "Get an aggregated morning briefing from Wave OS Chief of Staff. Includes calendar events, credit status, active sessions, tasks, and notifications with prioritized action items.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        proactivity_level: { type: "string", enum: ["low", "medium", "high"], description: "Proactivity level (default medium)" },
      },
      required: ["workspace_id"],
    },
  },
  {
    name: "wave_triage",
    description: "Run a triage scan across Wave OS entities for urgent items — calendar conflicts, credit warnings, failed pipelines, overdue tasks. Returns severity-ranked list.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        proactivity_level: { type: "string", enum: ["low", "medium", "high"], description: "Proactivity level (default medium)" },
      },
      required: ["workspace_id"],
    },
  },
  {
    name: "wave_follow_up_scan",
    description: "Scan Wave OS memory for tasks with natural language due dates. Returns overdue/due_today/upcoming buckets.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
      },
      required: ["workspace_id"],
    },
  },
  {
    name: "wave_meeting_prep",
    description: "Get preparation context for an upcoming meeting — pulls attendee info from memory, generates AI-suggested agenda via Theta AI.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        meeting_id: { type: "string", description: "Calendar event ID or title" },
      },
      required: ["workspace_id"],
    },
  },
  {
    name: "wave_save_memory",
    description: "Save a memory to Wave OS memory system. Auto-categorizes by content type (contact/preference/task/note/project/code/general).",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        content: { type: "string", description: "Memory content to save" },
        category: { type: "string", enum: ["contact", "preference", "task", "note", "project", "code", "general"], description: "Optional explicit category" },
        tags: { type: "array", items: { type: "string" }, description: "Optional tags" },
      },
      required: ["workspace_id", "content"],
    },
  },
  {
    name: "wave_recall_memory",
    description: "Search Wave OS memories by category or keyword. Returns matching memory entries.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        query: { type: "string", description: "Search keyword" },
        category: { type: "string", enum: ["contact", "preference", "task", "note", "project", "code", "general"], description: "Filter by category" },
      },
      required: ["workspace_id"],
    },
  },
  {
    name: "wave_delegate_subagent",
    description: "Delegate a task to a Wave OS sub-agent for focused background execution. Max 5 parallel, 1 level nesting.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        task: { type: "string", description: "Task description for the sub-agent" },
        context: { type: "string", description: "Additional context for the sub-agent" },
      },
      required: ["workspace_id", "task"],
    },
  },
  {
    name: "wave_chat",
    description: "Send a message to the Wave OS Assistant and get an AI-powered response. Uses Theta EdgeCloud for inference. Costs 1 credit per interaction.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        message: { type: "string", description: "Message to send to the assistant" },
        context: { type: "string", description: "Optional conversation context" },
      },
      required: ["workspace_id", "message"],
    },
  },
];

// ============================================================
// TOOL HANDLERS
// ============================================================

async function handleToolCall(name, args) {
  switch (name) {
    // ── LAYER 1: BASE44 BACKEND ─────────────────────────────
    
    case "list_entities":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/entities`);
    
    case "create_entity":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/entities`, {
        method: "POST",
        body: JSON.stringify(args),
      });
    
    case "read_records":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/entities/${args.entity_name}/records`, {
        method: "POST",
        body: JSON.stringify({
          query: args.query || {},
          limit: args.limit || 50,
          skip: args.skip || 0,
          sort: args.sort,
          fields: args.fields,
        }),
      });
    
    case "create_records":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/entities/${args.entity_name}/records`, {
        method: "PUT",
        body: JSON.stringify({ data: args.data }),
      });
    
    case "update_records":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/entities/${args.entity_name}/records`, {
        method: "PATCH",
        body: JSON.stringify({ query: args.query, data: args.data }),
      });
    
    case "delete_records":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/entities/${args.entity_name}/records`, {
        method: "DELETE",
        body: JSON.stringify({ query: args.query }),
      });
    
    case "aggregate_records":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/entities/${args.entity_name}/aggregate`, {
        method: "POST",
        body: JSON.stringify({ pipeline: args.pipeline }),
      });
    
    case "call_function":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/${args.function_name}`, {
        method: args.method || "POST",
        body: JSON.stringify(args.payload || {}),
      });
    
    case "upload_file":
      // Read file and upload to Base44 storage
      const fs = await import("fs/promises");
      const fileBuffer = await fs.readFile(args.file_path);
      const formData = new FormData();
      const blob = new Blob([fileBuffer]);
      formData.append("file", blob, args.file_path.split("/").pop());
      
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/files/upload`, {
        method: "POST",
        body: formData,
        headers: { "Content-Type": undefined },
      });
    
    // ── LAYER 2: THETA COMPUTE ──────────────────────────────
    
    case "theta_list_models":
      return await thetaFetch("/api/v1/models");
    
    case "theta_run_inference":
      return await thetaFetch("/api/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({
          model: args.model,
          messages: args.messages,
          max_tokens: args.max_tokens || 2048,
          temperature: args.temperature || 0.7,
        }),
      });
    
    case "theta_check_gpu_status":
      return await thetaFetch(`/api/v1/projects/${THETA_PROJECT_ID}/instances`);
    
    case "theta_estimate_cost":
      // Return estimated TFUEL cost
      const costPerMinute = 0.15; // TFUEL per credit minute
      const creditsNeeded = Math.ceil(args.duration_minutes * 4); // 4 credits per GPU minute
      const tfuelCost = (creditsNeeded * costPerMinute).toFixed(2);
      return {
        model: args.model,
        duration_minutes: args.duration_minutes,
        credits_needed: creditsNeeded,
        estimated_tfuel: tfuelCost,
        note: "Costs are approximate. Actual usage may vary.",
      };
    
    case "theta_deploy_contract":
      // Theta mainnet eth_sendTransaction via RPC
      return await thetaRpc("eth_sendTransaction", [{
        data: args.bytecode + (args.constructor_args || []).join(""),
        gas: "0x7A1200", // 8M gas
      }]);
    
    case "theta_read_contract":
      return await thetaRpc("eth_call", [{
        to: args.contract_address,
        data: args.function_signature + (args.params || []).join(""),
      }, "latest"]);
    
    case "theta_get_balance":
      // Get TFUEL balance
      const tfuelBalance = await thetaRpc("eth_getBalance", [args.wallet_address, "latest"]);
      
      // Get WAVE token balance if contract provided
      let tokenBalance = null;
      const tokenContract = args.token_contract || "0x93de35b55ace27cee301184e010de73518950753";
      const balanceResult = await thetaRpc("eth_call", [{
        to: tokenContract,
        data: "0x70a08231000000000000000000000000" + args.wallet_address.slice(2),
      }, "latest"]);
      tokenBalance = balanceResult;
      
      return {
        wallet: args.wallet_address,
        tfuel_wei: tfuelBalance,
        tfuel: (parseInt(tfuelBalance, 16) / 1e18).toFixed(4),
        wave_token_raw: tokenBalance,
        wave_token: (parseInt(tokenBalance, 16) / 1e18).toFixed(2),
      };
    
    case "theta_get_transaction":
      return await thetaRpc("eth_getTransactionByHash", [args.tx_hash]);
    
    // ── LAYER 3: WAVE OS INTELLIGENCE ───────────────────────
    
    case "wave_morning_briefing":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/waveChiefOfStaff`, {
        method: "POST",
        body: JSON.stringify({
          action: "morningBriefing",
          workspace_id: args.workspace_id,
          proactivity_level: args.proactivity_level || "medium",
        }),
      });
    
    case "wave_triage":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/waveChiefOfStaff`, {
        method: "POST",
        body: JSON.stringify({
          action: "triage",
          workspace_id: args.workspace_id,
          proactivity_level: args.proactivity_level || "medium",
        }),
      });
    
    case "wave_follow_up_scan":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/waveChiefOfStaff`, {
        method: "POST",
        body: JSON.stringify({
          action: "followUpScan",
          workspace_id: args.workspace_id,
        }),
      });
    
    case "wave_meeting_prep":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/waveChiefOfStaff`, {
        method: "POST",
        body: JSON.stringify({
          action: "meetingPrep",
          workspace_id: args.workspace_id,
          meeting_id: args.meeting_id,
        }),
      });
    
    case "wave_save_memory":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/waveChat`, {
        method: "POST",
        body: JSON.stringify({
          action: "saveMemory",
          workspace_id: args.workspace_id,
          content: args.content,
          category: args.category,
          tags: args.tags,
        }),
      });
    
    case "wave_recall_memory":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/waveChat`, {
        method: "POST",
        body: JSON.stringify({
          action: "recallMemory",
          workspace_id: args.workspace_id,
          query: args.query,
          category: args.category,
        }),
      });
    
    case "wave_delegate_subagent":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/waveChat`, {
        method: "POST",
        body: JSON.stringify({
          action: "delegateSubAgent",
          workspace_id: args.workspace_id,
          task: args.task,
          context: args.context,
        }),
      });
    
    case "wave_chat":
      return await base44Fetch(`/api/apps/${BASE44_APP_ID}/functions/waveChat`, {
        method: "POST",
        body: JSON.stringify({
          action: "chat",
          workspace_id: args.workspace_id,
          message: args.message,
          context: args.context,
        }),
      });
    
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ============================================================
// RESOURCES — Expose app metadata to the AI
// ============================================================

const resources = [
  {
    uri: "wave-os://app-info",
    name: "Wave OS App Info",
    description: "Information about the connected Wave OS Base44 app",
    mimeType: "application/json",
  },
  {
    uri: "wave-os://entity-schema",
    name: "Entity Schema Reference",
    description: "All entity schemas available in the connected Base44 app",
    mimeType: "application/json",
  },
  {
    uri: "wave-os://theta-config",
    name: "Theta Configuration",
    description: "Theta EdgeCloud and blockchain configuration details",
    mimeType: "application/json",
  },
];

async function handleReadResource(uri) {
  switch (uri) {
    case "wave-os://app-info":
      return JSON.stringify({
        app_id: BASE44_APP_ID,
        name: "Wave OS",
        domain: "oswave.io",
        description: "AI-powered operating system with decentralized compute",
        built_by: "xBuildy",
      }, null, 2);
    
    case "wave-os://entity-schema":
      const schemas = await base44Fetch(`/api/apps/${BASE44_APP_ID}/entities`);
      return JSON.stringify(schemas, null, 2);
    
    case "wave-os://theta-config":
      return JSON.stringify({
        edge_url: THETA_EDGE_URL,
        rpc_url: THETA_RPC_URL,
        project_id: THETA_PROJECT_ID,
        wave_token_contract: "0x93de35b55ace27cee301184e010de73518950753",
        treasury: "0xA8C5BDFB662284518470eae1B7beC2Dc432eB659",
        note: "All smart contracts use evmVersion istanbul (no PUSH0)",
      }, null, 2);
    
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
}

// ============================================================
// SERVER SETUP
// ============================================================

const server = new Server(
  { name: "wave-os-mcp-server", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {} } }
);

// List tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map(t => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  })),
}));

// Call tool
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  try {
    const result = await handleToolCall(name, args);
    return {
      content: [{
        type: "text",
        text: typeof result === "string" ? result : JSON.stringify(result, null, 2),
      }],
    };
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: `Error: ${error.message}`,
      }],
      isError: true,
    };
  }
});

// List resources
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources,
}));

// Read resource
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;
  try {
    const content = await handleReadResource(uri);
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: content,
      }],
    };
  } catch (error) {
    throw new Error(`Failed to read resource ${uri}: ${error.message}`);
  }
});

// ============================================================
// START SERVER
// ============================================================

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("Wave OS MCP Server running on stdio");
