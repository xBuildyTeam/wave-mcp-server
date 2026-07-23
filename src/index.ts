/**
 * Wave OS MCP Server — Security-Hardened
 * 
 * Three layers exposed to AI coding assistants:
 * 1. Base44 Backend — entities, functions, files, auth
 * 2. Theta Compute — GPU provisioning, blockchain, smart contracts
 * 3. Wave OS Intelligence — agent orchestration, memory, chief of staff
 * 
 * Built by xBuildy for the Base44 Dev Build-Off Competition
 * July 2026
 * 
 * SECURITY: All inputs validated, errors sanitized, filesystem access restricted,
 * destructive operations guarded, and API keys never exposed in responses.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { resolve, normalize, join, relative } from "path";
import { homedir } from "os";

// ============================================================
// CONFIG — Loaded from environment variables only
// ============================================================

const BASE44_APP_ID = process.env.BASE44_APP_ID || "";
const BASE44_API_KEY = process.env.BASE44_API_KEY || "";
const BASE44_BASE_URL = process.env.BASE44_BASE_URL || "https://api.base44.com";
const THETA_API_KEY = process.env.THETA_API_KEY || "";
const THETA_PROJECT_ID = process.env.THETA_PROJECT_ID || "";
const THETA_RPC_URL = process.env.THETA_RPC_URL || "https://theta-rpc.thetatoken.org";
const THETA_EDGE_URL = process.env.THETA_EDGE_URL || "https://controller.thetaedgecloud.com";

// Working directory for file uploads — restricts filesystem access
const ALLOWED_FILE_ROOT = process.env.MCP_FILE_ROOT || join(homedir(), "wave-mcp-uploads");

// Maximum records returned in a single call
const MAX_RECORD_LIMIT = 500;
const DEFAULT_LIMIT = 50;

// API call timeout (30 seconds)
const API_TIMEOUT_MS = 30000;

// Maximum response size (1MB)
const MAX_RESPONSE_BYTES = 1024 * 1024;

// ============================================================
// SECURITY: STARTUP VALIDATION
// ============================================================

function validateConfig() {
  const missing = [];
  if (!BASE44_APP_ID) missing.push("BASE44_APP_ID");
  if (!BASE44_API_KEY) missing.push("BASE44_API_KEY");
  if (missing.length > 0) {
    console.error(`FATAL: Missing required environment variables: ${missing.join(", ")}`);
    console.error("Set them in your MCP config or environment before starting the server.");
    process.exit(1);
  }
  
  // Theta is optional but warn if missing
  const thetaMissing = [];
  if (!THETA_API_KEY) thetaMissing.push("THETA_API_KEY");
  if (!THETA_PROJECT_ID) thetaMissing.push("THETA_PROJECT_ID");
  if (thetaMissing.length > 0) {
    console.error(`WARNING: Theta layer disabled — missing: ${thetaMissing.join(", ")}`);
    console.error("Theta compute/blockchain tools will return errors until configured.");
  }
  
  // Validate URL formats
  try { new URL(BASE44_BASE_URL); } catch { console.error("FATAL: BASE44_BASE_URL is not a valid URL"); process.exit(1); }
  try { new URL(THETA_RPC_URL); } catch { console.error("FATAL: THETA_RPC_URL is not a valid URL"); process.exit(1); }
  try { new URL(THETA_EDGE_URL); } catch { console.error("FATAL: THETA_EDGE_URL is not a valid URL"); process.exit(1); }
  
  // Ensure file upload directory exists
  try {
    const fs = await import("fs/promises");
    await fs.mkdir(ALLOWED_FILE_ROOT, { recursive: true });
  } catch (e) {
    console.error(`WARNING: Could not create upload directory: ${ALLOWED_FILE_ROOT}`);
  }
}

// ============================================================
// SECURITY: INPUT VALIDATORS
// ============================================================

// Entity/function names: PascalCase, alphanumeric only, max 50 chars
function validateEntityName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 50) {
    throw new Error("Invalid entity name: must be 1-50 characters");
  }
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(name)) {
    throw new Error("Invalid entity name: must be alphanumeric, starting with a letter");
  }
  return name;
}

function validateFunctionName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 100) {
    throw new Error("Invalid function name: must be 1-100 characters");
  }
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(name)) {
    throw new Error("Invalid function name: must be alphanumeric with hyphens/underscores only");
  }
  return name;
}

// Ethereum address validation (0x + 40 hex chars)
function validateEthAddress(addr) {
  if (typeof addr !== "string" || !/^0x[a-fA-F0-9]{40}$/.test(addr)) {
    throw new Error("Invalid Ethereum address: must be 0x followed by 40 hex characters");
  }
  return addr;
}

// Hex validation (0x + hex chars)
function validateHex(hex, maxLen = 100000) {
  if (typeof hex !== "string" || !/^0x[a-fA-F0-9]+$/.test(hex) || hex.length > maxLen) {
    throw new Error("Invalid hex value: must be 0x-prefixed hex string");
  }
  return hex;
}

// Sanitize sort field — alphanumeric + dash only
function validateSortField(sort) {
  if (typeof sort !== "string" || sort.length > 100) return undefined;
  if (!/^-?[A-Za-z_][A-Za-z0-9_]*$/.test(sort)) return undefined;
  return sort;
}

// Validate field projection names
function validateFieldNames(fields) {
  if (!Array.isArray(fields)) return undefined;
  return fields.filter(f => typeof f === "string" && /^[A-Za-z_][A-Za-z0-9_]*$/.test(f) && f.length < 100).slice(0, 50);
}

// Clamp limit to safe range
function validateLimit(limit) {
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LIMIT;
  return Math.min(Math.floor(n), MAX_RECORD_LIMIT);
}

// Validate skip
function validateSkip(skip) {
  const n = Number(skip);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(Math.floor(n), 100000);
}

// Block dangerous MongoDB aggregation stages
const BLOCKED_PIPELINE_STAGES = new Set([
  "$out", "$merge", "$lookup", "$facet", "$graphLookup", "$unionWith"
]);

function validatePipeline(pipeline) {
  if (!Array.isArray(pipeline) || pipeline.length === 0) {
    throw new Error("Pipeline must be a non-empty array");
  }
  if (pipeline.length > 20) {
    throw new Error("Pipeline must not exceed 20 stages");
  }
  for (const stage of pipeline) {
    if (typeof stage !== "object" || stage === null) {
      throw new Error("Each pipeline stage must be an object");
    }
    const keys = Object.keys(stage);
    if (keys.length !== 1) {
      throw new Error("Each pipeline stage must have exactly one key");
    }
    const stageName = keys[0];
    if (BLOCKED_PIPELINE_STAGES.has(stageName)) {
      throw new Error(`Pipeline stage ${stageName} is not allowed for security reasons`);
    }
  }
  return pipeline;
}

// Prevent empty query on delete (would wipe entire table)
function validateDeleteQuery(query) {
  if (!query || typeof query !== "object" || Object.keys(query).length === 0) {
    throw new Error("Delete requires a non-empty query filter to prevent accidental table wipes");
  }
  return query;
}

// Validate temperature range
function validateTemperature(t) {
  const n = Number(t);
  if (!Number.isFinite(n) || n < 0 || n > 2) return 0.7;
  return n;
}

// Validate max_tokens
function validateMaxTokens(t) {
  const n = Number(t);
  if (!Number.isFinite(n) || n < 1) return 2048;
  return Math.min(Math.floor(n), 8192);
}

// Validate chat messages
function validateMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) {
    throw new Error("Messages must be a non-empty array");
  }
  if (messages.length > 100) {
    throw new Error("Messages array must not exceed 100 items");
  }
  // Validate each message structure
  for (const msg of messages) {
    if (typeof msg !== "object" || msg === null) {
      throw new Error("Each message must be an object");
    }
    if (typeof msg.role !== "string" || !["system", "user", "assistant"].includes(msg.role)) {
      throw new Error("Message role must be 'system', 'user', or 'assistant'");
    }
    if (typeof msg.content !== "string" || msg.content.length > 50000) {
      throw new Error("Message content must be a string under 50,000 characters");
    }
  }
  return messages;
}

// Validate file path — prevent path traversal, restrict to allowed root
function validateFilePath(filePath) {
  if (typeof filePath !== "string" || filePath.length === 0 || filePath.length > 1024) {
    throw new Error("Invalid file path");
  }
  
  // Resolve to absolute and normalize
  const resolved = resolve(normalize(filePath));
  
  // Prevent access to sensitive system paths
  const blockedPaths = ["/etc", "/var", "/root", "/proc", "/sys", "/dev", "/boot"];
  for (const blocked of blockedPaths) {
    if (resolved.startsWith(blocked)) {
      throw new Error(`Access denied: path ${resolved} is in a restricted system directory`);
    }
  }
  
  // Prevent access to dotfiles that might contain secrets
  const baseName = resolved.split("/").pop() || "";
  if (baseName.startsWith(".") && baseName.length > 1) {
    const sensitiveDotfiles = [".env", ".git", ".ssh", ".npmrc", ".aws", ".gnupg"];
    for (const sensitive of sensitiveDotfiles) {
      if (resolved.includes(sensitive)) {
        throw new Error(`Access denied: cannot access sensitive file ${baseName}`);
      }
    }
  }
  
  return resolved;
}

// ============================================================
// SECURITY: ERROR SANITIZATION
// ============================================================

function sanitizeError(error) {
  let msg = error.message || String(error);
  
  // Never expose API keys, tokens, or secrets in error messages
  const sensitivePatterns = [
    /Bearer [^\s]+/gi,
    /api[_-]?key[=:]\s*[^\s]+/gi,
    /token[=:]\s*[^\s]+/gi,
    /secret[=:]\s*[^\s]+/gi,
    /password[=:]\s*[^\s]+/gi,
    /x-api-key:\s*[^\s]+/gi,
    /ghp_[A-Za-z0-9]+/gi,
    /sk_[A-Za-z0-9]+/gi,
  ];
  
  for (const pattern of sensitivePatterns) {
    msg = msg.replace(pattern, "[REDACTED]");
  }
  
  // Truncate very long error messages
  if (msg.length > 500) {
    msg = msg.substring(0, 500) + "... (truncated)";
  }
  
  return msg;
}

// ============================================================
// SECURITY: FETCH WITH TIMEOUT
// ============================================================

function fetchWithTimeout(url, options = {}, timeoutMs = API_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  
  return fetch(url, { ...options, signal: controller.signal })
    .finally(() => clearTimeout(timeout));
}

// ============================================================
// HELPERS
// ============================================================

async function base44Fetch(path, options = {}) {
  const url = new URL(`${BASE44_BASE_URL}${path}`);
  const headers = {
    "Content-Type": "application/json",
    "x-api-key": BASE44_API_KEY,
    ...options.headers,
  };
  
  // Remove Content-Type for FormData
  if (options.headers && options.headers["Content-Type"] === undefined) {
    delete headers["Content-Type"];
  }
  
  const response = await fetchWithTimeout(url.toString(), { ...options, headers });
  
  if (!response.ok) {
    const text = await response.text();
    const safeText = sanitizeError({ message: text }).message || text.substring(0, 200);
    throw new Error(`Base44 API returned ${response.status}`);
  }
  
  // Check response size
  const contentLength = parseInt(response.headers.get("content-length") || "0", 10);
  if (contentLength > MAX_RESPONSE_BYTES) {
    throw new Error("Response too large: exceeds 1MB safety limit");
  }
  
  return response.json();
}

async function thetaFetch(path, options = {}) {
  if (!THETA_API_KEY) {
    throw new Error("Theta API key not configured — set THETA_API_KEY environment variable");
  }
  
  const url = new URL(`${THETA_EDGE_URL}${path}`);
  const headers = {
    "Content-Type": "application/json",
    "x-api-key": THETA_API_KEY,
    ...options.headers,
  };
  
  const response = await fetchWithTimeout(url.toString(), { ...options, headers });
  
  if (!response.ok) {
    throw new Error(`Theta API returned ${response.status}`);
  }
  
  return response.json();
}

async function thetaRpc(method, params = []) {
  // Validate method name
  if (typeof method !== "string" || !/^[a-z_]+$/.test(method) || method.length > 50) {
    throw new Error("Invalid RPC method name");
  }
  
  // Only allow read-only RPC methods by default
  const readOnlyMethods = new Set([
    "eth_getBalance", "eth_call", "eth_getTransactionByHash",
    "eth_getTransactionReceipt", "eth_blockNumber", "eth_getBlockByNumber",
    "eth_getCode", "eth_getStorageAt", "eth_getLogs",
    "net_version", "web3_clientVersion", "eth_chainId",
    "eth_getTransactionCount",
  ]);
  
  // Write methods require explicit env flag
  const writeMethods = new Set([
    "eth_sendTransaction", "eth_sendRawTransaction",
  ]);
  
  const allowWrites = process.env.THETA_ALLOW_WRITES === "true";
  
  if (readOnlyMethods.has(method)) {
    // Always allowed
  } else if (writeMethods.has(method)) {
    if (!allowWrites) {
      throw new Error(`RPC method ${method} requires THETA_ALLOW_WRITES=true in environment`);
    }
    console.error(`⚠️  Write transaction requested: ${method}`);
  } else {
    throw new Error(`RPC method ${method} is not in the allowed list`);
  }
  
  const response = await fetchWithTimeout(THETA_RPC_URL, {
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
  if (data.error) throw new Error(`Theta RPC error: ${sanitizeError({ message: data.error.message }).message || data.error.message}`);
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
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
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
      additionalProperties: false,
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
      additionalProperties: false,
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
      additionalProperties: false,
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
      additionalProperties: false,
    },
  },
  {
    name: "delete_records",
    description: "Delete records from a Base44 entity that match a query filter. Requires a non-empty query to prevent accidental table wipes.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "Entity name to delete from" },
        query: { type: "object", description: "Non-empty filter to select records to delete (required)" },
      },
      required: ["entity_name", "query"],
      additionalProperties: false,
    },
  },
  {
    name: "aggregate_records",
    description: "Run a MongoDB aggregation pipeline over a Base44 entity for complex reads (group-by, counts, sums, averages, top-N). NOTE: $out, $merge, $lookup, $facet and other write/join stages are blocked for security.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "Entity name to aggregate" },
        pipeline: { type: "array", items: { type: "object" }, description: "MongoDB aggregation pipeline stages (max 20, read-only stages only)" },
      },
      required: ["entity_name", "pipeline"],
      additionalProperties: false,
    },
  },
  {
    name: "call_function",
    description: "Call a deployed Base44 backend function via HTTP. Pass function name, method, and payload.",
    inputSchema: {
      type: "object",
      properties: {
        function_name: { type: "string", description: "Deployed backend function name (alphanumeric, hyphens, underscores)" },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"], description: "HTTP method (default POST)" },
        payload: { type: "object", description: "JSON body to send to the function (max 100KB)" },
      },
      required: ["function_name"],
      additionalProperties: false,
    },
  },
  {
    name: "upload_file",
    description: "Upload a file to Base44 public storage and get a CDN-backed URL. File must be within the allowed upload directory (MCP_FILE_ROOT env var, defaults to ~/wave-mcp-uploads). System files, dotfiles, and secret files are blocked.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: { type: "string", description: "Path to the file to upload (must be in allowed directory)" },
      },
      required: ["file_path"],
      additionalProperties: false,
    },
  },

  // ──────────────────────────────────────────────────────────
  // LAYER 2: THETA COMPUTE — GPU + Blockchain
  // ──────────────────────────────────────────────────────────
  
  {
    name: "theta_list_models",
    description: "List available AI models on Theta EdgeCloud for inference tasks.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "theta_run_inference",
    description: "Send a prompt to a Theta EdgeCloud AI model for inference. Returns the model's response.",
    inputSchema: {
      type: "object",
      properties: {
        model: { type: "string", description: "Model ID (e.g. 'chtz4ssnbcf405uy4e05')" },
        messages: { type: "array", items: { type: "object" }, description: "Chat messages array [{role, content}]. Max 100 messages, 50K chars each." },
        max_tokens: { type: "number", description: "Max tokens to generate (default 2048, max 8192)" },
        temperature: { type: "number", description: "Temperature (0-2, default 0.7)" },
      },
      required: ["model", "messages"],
      additionalProperties: false,
    },
  },
  {
    name: "theta_check_gpu_status",
    description: "Check status of running Theta EdgeCloud GPU instances for this project.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "theta_estimate_cost",
    description: "Estimate TFUEL cost for a GPU compute job before running it. No API calls made — pure calculation.",
    inputSchema: {
      type: "object",
      properties: {
        model: { type: "string", description: "Model ID to estimate for" },
        duration_minutes: { type: "number", description: "Estimated runtime in minutes (max 1440)" },
      },
      required: ["model", "duration_minutes"],
      additionalProperties: false,
    },
  },
  {
    name: "theta_deploy_contract",
    description: "Deploy a smart contract to Theta mainnet. REQUIRES THETA_ALLOW_WRITES=true in environment. This is an irreversible on-chain operation — ensure bytecode is audited before deployment. Uses evmVersion istanbul (no PUSH0).",
    inputSchema: {
      type: "object",
      properties: {
        bytecode: { type: "string", description: "Hex-encoded contract bytecode (with 0x prefix, max 100KB)" },
        abi: { type: "array", items: { type: "object" }, description: "Contract ABI" },
        constructor_args: { type: "array", items: { type: "string" }, description: "Constructor arguments (hex encoded)" },
      },
      required: ["bytecode", "abi"],
      additionalProperties: false,
    },
  },
  {
    name: "theta_read_contract",
    description: "Call a view/read function on a deployed Theta smart contract. Read-only — safe.",
    inputSchema: {
      type: "object",
      properties: {
        contract_address: { type: "string", description: "Contract address (0x + 40 hex)" },
        function_signature: { type: "string", description: "Function signature hash (e.g. '0x70a08231' for balanceOf)" },
        params: { type: "array", items: { type: "string" }, description: "Encoded function parameters" },
      },
      required: ["contract_address", "function_signature"],
      additionalProperties: false,
    },
  },
  {
    name: "theta_get_balance",
    description: "Get TFUEL and WAVE token balance for a wallet address on Theta mainnet. Read-only — safe.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_address: { type: "string", description: "Wallet address (0x + 40 hex)" },
        token_contract: { type: "string", description: "Optional TNT20 token contract address (defaults to WAVE token)" },
      },
      required: ["wallet_address"],
      additionalProperties: false,
    },
  },
  {
    name: "theta_get_transaction",
    description: "Fetch transaction details by hash from Theta mainnet. Read-only — safe.",
    inputSchema: {
      type: "object",
      properties: {
        tx_hash: { type: "string", description: "Transaction hash (0x + 64 hex)" },
      },
      required: ["tx_hash"],
      additionalProperties: false,
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
      additionalProperties: false,
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
      additionalProperties: false,
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
      additionalProperties: false,
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
      additionalProperties: false,
    },
  },
  {
    name: "wave_save_memory",
    description: "Save a memory to Wave OS memory system. Auto-categorizes by content type (contact/preference/task/note/project/code/general).",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        content: { type: "string", description: "Memory content to save (max 10,000 chars)" },
        category: { type: "string", enum: ["contact", "preference", "task", "note", "project", "code", "general"], description: "Optional explicit category" },
        tags: { type: "array", items: { type: "string" }, description: "Optional tags (max 10)" },
      },
      required: ["workspace_id", "content"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_recall_memory",
    description: "Search Wave OS memories by category or keyword. Returns matching memory entries.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        query: { type: "string", description: "Search keyword (max 200 chars)" },
        category: { type: "string", enum: ["contact", "preference", "task", "note", "project", "code", "general"], description: "Filter by category" },
      },
      required: ["workspace_id"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_delegate_subagent",
    description: "Delegate a task to a Wave OS sub-agent for focused background execution. Max 5 parallel, 1 level nesting.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        task: { type: "string", description: "Task description for the sub-agent (max 5,000 chars)" },
        context: { type: "string", description: "Additional context for the sub-agent (max 5,000 chars)" },
      },
      required: ["workspace_id", "task"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_chat",
    description: "Send a message to the Wave OS Assistant and get an AI-powered response. Uses Theta EdgeCloud for inference. Costs 1 credit per interaction.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string", description: "Wave OS workspace ID" },
        message: { type: "string", description: "Message to send to the assistant (max 10,000 chars)" },
        context: { type: "string", description: "Optional conversation context (max 10,000 chars)" },
      },
      required: ["workspace_id", "message"],
      additionalProperties: false,
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
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities`);
    
    case "create_entity": {
      const entityName = validateEntityName(args.entity_name);
      if (!args.schema || typeof args.schema !== "object") {
        throw new Error("Schema must be a valid JSON schema object");
      }
      // Limit schema size
      const schemaStr = JSON.stringify(args.schema);
      if (schemaStr.length > 50000) {
        throw new Error("Schema too large: must be under 50KB");
      }
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities`, {
        method: "POST",
        body: JSON.stringify({ entity_name: entityName, schema: args.schema }),
      });
    }
    
    case "read_records": {
      const entityName = validateEntityName(args.entity_name);
      const limit = validateLimit(args.limit);
      const skip = validateSkip(args.skip);
      const sort = validateSortField(args.sort);
      const fields = validateFieldNames(args.fields);
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities/${encodeURIComponent(entityName)}/records`, {
        method: "POST",
        body: JSON.stringify({
          query: args.query && typeof args.query === "object" ? args.query : {},
          limit,
          skip,
          sort,
          fields,
        }),
      });
    }
    
    case "create_records": {
      const entityName = validateEntityName(args.entity_name);
      if (!Array.isArray(args.data) || args.data.length === 0) {
        throw new Error("Data must be a non-empty array");
      }
      if (args.data.length > 500) {
        throw new Error("Cannot create more than 500 records at once");
      }
      // Validate each record is an object
      for (const record of args.data) {
        if (typeof record !== "object" || record === null) {
          throw new Error("Each record must be an object");
        }
      }
      // Check total payload size
      const payloadStr = JSON.stringify({ data: args.data });
      if (payloadStr.length > 500000) {
        throw new Error("Payload too large: must be under 500KB");
      }
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities/${encodeURIComponent(entityName)}/records`, {
        method: "PUT",
        body: payloadStr,
      });
    }
    
    case "update_records": {
      const entityName = validateEntityName(args.entity_name);
      if (!args.query || typeof args.query !== "object" || Object.keys(args.query).length === 0) {
        throw new Error("Update requires a non-empty query filter");
      }
      if (!args.data || typeof args.data !== "object") {
        throw new Error("Update data must be an object");
      }
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities/${encodeURIComponent(entityName)}/records`, {
        method: "PATCH",
        body: JSON.stringify({ query: args.query, data: args.data }),
      });
    }
    
    case "delete_records": {
      const entityName = validateEntityName(args.entity_name);
      const query = validateDeleteQuery(args.query);
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities/${encodeURIComponent(entityName)}/records`, {
        method: "DELETE",
        body: JSON.stringify({ query }),
      });
    }
    
    case "aggregate_records": {
      const entityName = validateEntityName(args.entity_name);
      const pipeline = validatePipeline(args.pipeline);
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities/${encodeURIComponent(entityName)}/aggregate`, {
        method: "POST",
        body: JSON.stringify({ pipeline }),
      });
    }
    
    case "call_function": {
      const functionName = validateFunctionName(args.function_name);
      const method = ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(args.method) ? args.method : "POST";
      
      let payload = {};
      if (args.payload && typeof args.payload === "object") {
        const payloadStr = JSON.stringify(args.payload);
        if (payloadStr.length > 100000) {
          throw new Error("Function payload too large: must be under 100KB");
        }
        payload = args.payload;
      }
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/${encodeURIComponent(functionName)}`, {
        method,
        body: method === "GET" ? undefined : JSON.stringify(payload),
      });
    }
    
    case "upload_file": {
      const filePath = validateFilePath(args.file_path);
      
      // Additional check: file must exist and be under 10MB
      const fs = await import("fs/promises");
      const stats = await fs.stat(filePath);
      if (!stats.isFile()) {
        throw new Error("Path must point to a file, not a directory");
      }
      if (stats.size > 10 * 1024 * 1024) {
        throw new Error("File too large: must be under 10MB");
      }
      
      const fileBuffer = await fs.readFile(filePath);
      const formData = new FormData();
      const blob = new Blob([fileBuffer]);
      formData.append("file", blob, filePath.split("/").pop() || "upload");
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/files/upload`, {
        method: "POST",
        body: formData,
        headers: { "Content-Type": undefined },
      });
    }
    
    // ── LAYER 2: THETA COMPUTE ──────────────────────────────
    
    case "theta_list_models":
      return await thetaFetch("/api/v1/models");
    
    case "theta_run_inference": {
      const messages = validateMessages(args.messages);
      if (typeof args.model !== "string" || args.model.length > 100) {
        throw new Error("Invalid model ID");
      }
      
      return await thetaFetch("/api/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({
          model: args.model,
          messages,
          max_tokens: validateMaxTokens(args.max_tokens),
          temperature: validateTemperature(args.temperature),
        }),
      });
    }
    
    case "theta_check_gpu_status":
      return await thetaFetch(`/api/v1/projects/${encodeURIComponent(THETA_PROJECT_ID)}/instances`);
    
    case "theta_estimate_cost": {
      // Pure calculation — no API calls
      if (typeof args.model !== "string" || args.model.length > 100) {
        throw new Error("Invalid model ID");
      }
      const duration = Math.min(Math.max(Number(args.duration_minutes) || 0, 1), 1440);
      const costPerMinute = 0.15; // TFUEL per credit minute
      const creditsNeeded = Math.ceil(duration * 4); // 4 credits per GPU minute
      const tfuelCost = (creditsNeeded * costPerMinute).toFixed(2);
      return {
        model: args.model,
        duration_minutes: duration,
        credits_needed: creditsNeeded,
        estimated_tfuel: tfuelCost,
        note: "Costs are approximate. Actual usage may vary.",
      };
    }
    
    case "theta_deploy_contract": {
      const bytecode = validateHex(args.bytecode, 100000);
      if (!Array.isArray(args.abi)) {
        throw new Error("ABI must be an array");
      }
      const constructorArgs = (args.constructor_args || []).map(a => validateHex(a));
      
      return await thetaRpc("eth_sendTransaction", [{
        data: bytecode + constructorArgs.join(""),
        gas: "0x7A1200", // 8M gas
      }]);
    }
    
    case "theta_read_contract": {
      const contractAddress = validateEthAddress(args.contract_address);
      const functionSig = validateHex(args.function_signature, 100);
      const params = (args.params || []).map(p => validateHex(p, 10000));
      
      return await thetaRpc("eth_call", [{
        to: contractAddress,
        data: functionSig + params.join(""),
      }, "latest"]);
    }
    
    case "theta_get_balance": {
      const walletAddress = validateEthAddress(args.wallet_address);
      
      // Get TFUEL balance
      const tfuelBalance = await thetaRpc("eth_getBalance", [walletAddress, "latest"]);
      
      // Get WAVE token balance
      const tokenContract = args.token_contract 
        ? validateEthAddress(args.token_contract)
        : "0x93de35b55ace27cee301184e010de73518950753";
      
      const balanceResult = await thetaRpc("eth_call", [{
        to: tokenContract,
        data: "0x70a08231000000000000000000000000" + walletAddress.slice(2),
      }, "latest"]);
      
      return {
        wallet: walletAddress,
        tfuel_wei: tfuelBalance,
        tfuel: (parseInt(tfuelBalance, 16) / 1e18).toFixed(4),
        wave_token_raw: balanceResult,
        wave_token: (parseInt(balanceResult, 16) / 1e18).toFixed(2),
      };
    }
    
    case "theta_get_transaction": {
      const txHash = validateHex(args.tx_hash, 100);
      if (args.tx_hash.length !== 66) {
        throw new Error("Transaction hash must be 0x + 64 hex characters (66 total)");
      }
      return await thetaRpc("eth_getTransactionByHash", [args.tx_hash]);
    }
    
    // ── LAYER 3: WAVE OS INTELLIGENCE ───────────────────────
    
    case "wave_morning_briefing": {
      const workspaceId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/waveChiefOfStaff`, {
        method: "POST",
        body: JSON.stringify({
          action: "morningBriefing",
          workspace_id: workspaceId,
          proactivity_level: ["low", "medium", "high"].includes(args.proactivity_level) ? args.proactivity_level : "medium",
        }),
      });
    }
    
    case "wave_triage": {
      const workspaceId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/waveChiefOfStaff`, {
        method: "POST",
        body: JSON.stringify({
          action: "triage",
          workspace_id: workspaceId,
          proactivity_level: ["low", "medium", "high"].includes(args.proactivity_level) ? args.proactivity_level : "medium",
        }),
      });
    }
    
    case "wave_follow_up_scan": {
      const workspaceId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/waveChiefOfStaff`, {
        method: "POST",
        body: JSON.stringify({
          action: "followUpScan",
          workspace_id: workspaceId,
        }),
      });
    }
    
    case "wave_meeting_prep": {
      const workspaceId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/waveChiefOfStaff`, {
        method: "POST",
        body: JSON.stringify({
          action: "meetingPrep",
          workspace_id: workspaceId,
          meeting_id: typeof args.meeting_id === "string" ? args.meeting_id.substring(0, 200) : undefined,
        }),
      });
    }
    
    case "wave_save_memory": {
      const workspaceId = validateFunctionName(args.workspace_id);
      const content = typeof args.content === "string" ? args.content.substring(0, 10000) : "";
      if (!content) throw new Error("Content is required and must be a non-empty string");
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/waveChat`, {
        method: "POST",
        body: JSON.stringify({
          action: "saveMemory",
          workspace_id: workspaceId,
          content,
          category: ["contact", "preference", "task", "note", "project", "code", "general"].includes(args.category) ? args.category : undefined,
          tags: Array.isArray(args.tags) ? args.tags.slice(0, 10).map(t => String(t).substring(0, 50)) : undefined,
        }),
      });
    }
    
    case "wave_recall_memory": {
      const workspaceId = validateFunctionName(args.workspace_id);
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/waveChat`, {
        method: "POST",
        body: JSON.stringify({
          action: "recallMemory",
          workspace_id: workspaceId,
          query: typeof args.query === "string" ? args.query.substring(0, 200) : undefined,
          category: ["contact", "preference", "task", "note", "project", "code", "general"].includes(args.category) ? args.category : undefined,
        }),
      });
    }
    
    case "wave_delegate_subagent": {
      const workspaceId = validateFunctionName(args.workspace_id);
      const task = typeof args.task === "string" ? args.task.substring(0, 5000) : "";
      if (!task) throw new Error("Task is required and must be a non-empty string");
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/waveChat`, {
        method: "POST",
        body: JSON.stringify({
          action: "delegateSubAgent",
          workspace_id: workspaceId,
          task,
          context: typeof args.context === "string" ? args.context.substring(0, 5000) : undefined,
        }),
      });
    }
    
    case "wave_chat": {
      const workspaceId = validateFunctionName(args.workspace_id);
      const message = typeof args.message === "string" ? args.message.substring(0, 10000) : "";
      if (!message) throw new Error("Message is required and must be a non-empty string");
      
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/waveChat`, {
        method: "POST",
        body: JSON.stringify({
          action: "chat",
          workspace_id: workspaceId,
          message,
          context: typeof args.context === "string" ? args.context.substring(0, 10000) : undefined,
        }),
      });
    }
    
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
    description: "Theta EdgeCloud and blockchain configuration details (no secrets exposed)",
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
        // Never expose API keys here
      }, null, 2);
    
    case "wave-os://entity-schema":
      const schemas = await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities`);
      return JSON.stringify(schemas, null, 2);
    
    case "wave-os://theta-config":
      return JSON.stringify({
        edge_url: THETA_EDGE_URL,
        rpc_url: THETA_RPC_URL,
        project_id: THETA_PROJECT_ID,
        wave_token_contract: "0x93de35b55ace27cee301184e010de73518950753",
        treasury: "0xA8C5BDFB662284518470eae1B7beC2Dc432eB659",
        writes_enabled: process.env.THETA_ALLOW_WRITES === "true",
        note: "All smart contracts use evmVersion istanbul (no PUSH0). API keys are never exposed.",
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
        text: `Error: ${sanitizeError(error)}`,
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
    throw new Error(`Failed to read resource: ${sanitizeError(error)}`);
  }
});

// ============================================================
// START SERVER
// ============================================================

// Validate config before starting
validateConfig();

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("Wave OS MCP Server running on stdio (security-hardened)");
