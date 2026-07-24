/**
 * Wave OS MCP Server v1.5.3 — Hybrid Compute Routing + Credit-Gated + BYOK + AES-256
 * 
 * Three credential modes for Theta compute:
 * 1. Wave OS Auth Token — routes through thetaProxy backend (credit-gated, no raw key needed)
 * 2. BYOK — user saves own Theta key (AES-256 encrypted at rest)
 * 3. Env Vars — shared key (demo/admin use only)
 * 
 * Hybrid compute routing:
 * - hybrid (default): Light tasks on Base44, heavy AI compute on Theta (decentralized)
 * - wave_os: All compute routed through Wave OS backend (maximum credit-gating)
 * - direct: All compute routed directly to Theta (BYOK power users, no credits)
 * 
 * Positioning: Base44 = intelligence/orchestration layer. Theta = decentralized GPU compute.
 * Every Theta call still flows through a Base44 backend function — Base44 gets platform revenue.
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
import { resolve, normalize, join } from "path";
import { homedir } from "os";
import { createHash, createCipheriv, createDecipheriv, randomBytes } from "crypto";

// ============================================================
// CONFIG
// ============================================================

const BASE44_APP_ID = process.env.BASE44_APP_ID || "";
const EDDIE_WORKSPACE_ID = process.env.WAVE_WORKSPACE_ID || "69fd12da185a6e091e5bea1d";
const BASE44_API_KEY = process.env.BASE44_API_KEY || "";
const BASE44_BASE_URL = process.env.BASE44_BASE_URL || "https://insta-fi-ai-1e5bea1c.base44.app";

// Wave OS auth (credit-gated mode — no raw Theta key needed)
const WAVE_OS_AUTH_TOKEN = process.env.WAVE_OS_AUTH_TOKEN || "";
const WAVE_OS_WORKSPACE_ID = process.env.WAVE_OS_WORKSPACE_ID || "";

// Theta (direct mode — BYOK or env vars)
const THETA_API_KEY_ENV = process.env.THETA_API_KEY || "";
const THETA_PROJECT_ID_ENV = process.env.THETA_PROJECT_ID || "";
const THETA_RPC_URL = process.env.THETA_RPC_URL || "https://theta-rpc.thetatoken.org";
const THETA_EDGE_URL = process.env.THETA_EDGE_URL || "https://controller.thetaedgecloud.com";

// Compute routing: hybrid (default) | wave_os | direct
// hybrid = Base44 for light tasks (entity CRUD, memory, functions), Theta for heavy AI compute
// wave_os = everything through Wave OS backend (max credit-gating, Base44 gets all revenue)
// direct = everything directly to Theta (BYOK users, no credits, no Base44 intermediary)
const COMPUTE_ROUTING = ["hybrid", "wave_os", "direct"].includes(process.env.COMPUTE_ROUTING)
  ? process.env.COMPUTE_ROUTING
  : "hybrid";

const MCP_ENCRYPTION_KEY = process.env.MCP_ENCRYPTION_KEY || "";

// Cursor activity feed — conversation ID for Wave OS chat bubbles
const CURSOR_CONVERSATION_ID = "6a62e00ec8143266c5b313d0";

// Activity messages for each tool — shown as chat bubbles in Wave OS
const TOOL_ACTIVITY = {
  "list_entities": "📋 Scanning Wave OS entity schemas...",
  "read_records": "📖 Reading {{entity_name}} records...",
  "create_records": "✏️ Writing to {{entity_name}}...",
  "update_records": "📝 Updating {{entity_name}} records...",
  "delete_records": "🗑️ Deleting {{entity_name}} records...",
  "theta_list_models": "🔍 Querying Theta EdgeCloud for available models...",
  "theta_check_gpu_status": "🖥️ Checking Theta EdgeCloud GPU availability...",
  "theta_estimate_cost": "💰 Estimating compute cost...",
  "theta_run_inference": "🧠 Running AI inference on Theta EdgeCloud...",
  "wave_generate_image": "🎨 Generating AI image through Wave OS GPU layer...",
  "wave_chat": "💬 Chatting with Wave OS Assistant...",
  "wave_morning_briefing": "☀️ Requesting morning briefing from Chief of Staff...",
  "wave_triage_tasks": "🔄 Triaging tasks via Chief of Staff...",
  "wave_check_messages": "📬 Checking for messages from Wave OS...",
  "wave_send_message": "📤 Sending message to Wave OS...",
  "wave_recall_memory": "🧠 Recalling memories from Wave OS...",
  "wave_save_memory": "💾 Saving memory to Wave OS...",
};

function formatActivity(toolName, args) {
  const tpl = TOOL_ACTIVITY[toolName];
  if (!tpl) return null;
  if (!args) return tpl;
  return tpl.replace(/{{(\w+)}}/g, (_, k) => args[k] || "");
}

async function logCursorActivity(message) {
  try {
    await entityProxy("create", "ChatMessage", { data: [{ conversation_id: CURSOR_CONVERSATION_ID, sender_id: "cursor-mcp", sender_name: "Cursor", content: message, message_type: "text", read_by: [] }] });
  } catch (e) { /* silent — never break tool calls */ }
}
const ALLOWED_FILE_ROOT = process.env.MCP_FILE_ROOT || join(homedir(), "wave-mcp-uploads");
const CREDENTIAL_STORE_PATH = join(homedir(), ".wave-mcp", "credentials.json");

const MAX_RECORD_LIMIT = 500;
const DEFAULT_LIMIT = 50;
const API_TIMEOUT_MS = 30000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

// ============================================================
// AES-256-GCM ENCRYPTION
// ============================================================

function getEncryptionKey() {
  if (MCP_ENCRYPTION_KEY) return createHash("sha256").update(MCP_ENCRYPTION_KEY).digest();
  const os = require("os");
  const machineId = `${os.hostname()}:${os.userInfo().username}:wave-mcp-v1`;
  return createHash("sha256").update(machineId).digest();
}

function encryptKey(plaintext) {
  const key = getEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return "enc:" + Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

function decryptKey(stored) {
  if (!stored || typeof stored !== "string") return null;
  if (!stored.startsWith("enc:")) return stored;
  try {
    const key = getEncryptionKey();
    const combined = Buffer.from(stored.slice(4), "base64");
    const iv = combined.subarray(0, 12);
    const authTag = combined.subarray(12, 28);
    const ciphertext = combined.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch (e) {
    throw new Error("Failed to decrypt stored credential");
  }
}

function maskKey(key) {
  if (!key || key.length < 8) return "****";
  return key.substring(0, 4) + "••••••••" + key.substring(key.length - 4);
}

// ============================================================
// CREDENTIAL STORE
// ============================================================

async function loadCredentials() {
  try {
    const fs = await import("fs/promises");
    return JSON.parse(await fs.readFile(CREDENTIAL_STORE_PATH, "utf8"));
  } catch { return { theta: null, wave_os: null, routing: null }; }
}

async function saveCredentials(creds) {
  const fs = await import("fs/promises");
  await fs.mkdir(join(CREDENTIAL_STORE_PATH, ".."), { recursive: true });
  await fs.writeFile(CREDENTIAL_STORE_PATH, JSON.stringify(creds, null, 2), { mode: 0o600 });
}

async function getThetaMode() {
  const stored = await loadCredentials();
  
  // 1. Wave OS auth token (credit-gated, no raw key)
  if (stored.wave_os && stored.wave_os.auth_token_encrypted && stored.wave_os.workspace_id) {
    try {
      const token = decryptKey(stored.wave_os.auth_token_encrypted);
      if (token) return { mode: "wave_os", authToken: token, workspaceId: stored.wave_os.workspace_id, savedAt: stored.wave_os.saved_at };
    } catch { /* fall through */ }
  }
  if (WAVE_OS_AUTH_TOKEN && WAVE_OS_WORKSPACE_ID) {
    return { mode: "wave_os", authToken: WAVE_OS_AUTH_TOKEN, workspaceId: WAVE_OS_WORKSPACE_ID, source: "env" };
  }
  
  // 2. BYOK
  if (stored.theta && stored.theta.api_key_encrypted) {
    try {
      const apiKey = decryptKey(stored.theta.api_key_encrypted);
      if (apiKey && stored.theta.project_id) {
        return { mode: "byok", apiKey, projectId: stored.theta.project_id, savedAt: stored.theta.saved_at };
      }
    } catch { /* fall through */ }
  }
  
  // 3. Env vars
  if (THETA_API_KEY_ENV && THETA_PROJECT_ID_ENV) {
    return { mode: "env", apiKey: THETA_API_KEY_ENV, projectId: THETA_PROJECT_ID_ENV };
  }
  
  return null;
}

async function saveWaveOsCredentials(authToken, workspaceId) {
  const creds = await loadCredentials();
  creds.wave_os = { auth_token_encrypted: encryptKey(authToken), workspace_id: workspaceId, saved_at: new Date().toISOString(), encrypted_at_rest: true };
  await saveCredentials(creds);
}

async function saveThetaCredentials(apiKey, projectId) {
  const creds = await loadCredentials();
  creds.theta = { api_key_encrypted: encryptKey(apiKey), project_id: projectId, saved_at: new Date().toISOString(), encrypted_at_rest: true };
  await saveCredentials(creds);
}

async function removeThetaCredentials() {
  const creds = await loadCredentials();
  creds.theta = null;
  await saveCredentials(creds);
}

async function removeWaveOsCredentials() {
  const creds = await loadCredentials();
  creds.wave_os = null;
  await saveCredentials(creds);
}

// ─── Routing config persistence ───
async function getRoutingMode() {
  const stored = await loadCredentials();
  if (stored.routing && stored.routing.mode) return stored.routing.mode;
  return COMPUTE_ROUTING;
}

async function saveRoutingMode(mode) {
  const creds = await loadCredentials();
  creds.routing = { mode, saved_at: new Date().toISOString() };
  await saveCredentials(creds);
}

// ============================================================
// STARTUP VALIDATION
// ============================================================

function validateConfig() {
  const missing = [];
  if (!BASE44_APP_ID) missing.push("BASE44_APP_ID");
  if (!BASE44_API_KEY) missing.push("BASE44_API_KEY");
  if (missing.length > 0) {
    console.error(`FATAL: Missing required env vars: ${missing.join(", ")}`);
    process.exit(1);
  }
  
  const thetaModes = [];
  if (WAVE_OS_AUTH_TOKEN && WAVE_OS_WORKSPACE_ID) thetaModes.push("wave_os (env)");
  if (THETA_API_KEY_ENV && THETA_PROJECT_ID_ENV) thetaModes.push("env_key");
  if (thetaModes.length === 0) {
    console.error("INFO: No Theta credentials in env. Users can connect via wave_connect (credit-gated) or theta_configure (BYOK).");
  } else {
    console.error(`INFO: Theta modes from env: ${thetaModes.join(", ")}`);
  }
  
  // Compute routing info
  const routingDesc = {
    hybrid: "Base44 for light tasks, Theta for heavy AI compute (recommended)",
    wave_os: "All compute through Wave OS backend (max credit-gating, Base44 gets all revenue)",
    direct: "All compute directly to Theta (BYOK power users, no credits)",
  };
  console.error(`INFO: Compute routing: ${COMPUTE_ROUTING} — ${routingDesc[COMPUTE_ROUTING]}`);
  
  try { new URL(BASE44_BASE_URL); } catch { console.error("FATAL: Invalid BASE44_BASE_URL"); process.exit(1); }
  try { new URL(THETA_RPC_URL); } catch { console.error("FATAL: Invalid THETA_RPC_URL"); process.exit(1); }
  try { new URL(THETA_EDGE_URL); } catch { console.error("FATAL: Invalid THETA_EDGE_URL"); process.exit(1); }
}

// ============================================================
// INPUT VALIDATORS
// ============================================================

function validateEntityName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 50) throw new Error("Invalid entity name");
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(name)) throw new Error("Invalid entity name: alphanumeric only");
  return name;
}

function validateFunctionName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 100) throw new Error("Invalid function name");
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(name)) throw new Error("Invalid function name");
  return name;
}

function validateEthAddress(addr) {
  if (typeof addr !== "string" || !/^0x[a-fA-F0-9]{40}$/.test(addr)) throw new Error("Invalid Ethereum address");
  return addr;
}

function validateHex(hex, maxLen = 100000) {
  if (typeof hex !== "string" || !/^0x[a-fA-F0-9]+$/.test(hex) || hex.length > maxLen) throw new Error("Invalid hex value");
  return hex;
}

function validateSortField(sort) {
  if (typeof sort !== "string" || sort.length > 100) return undefined;
  if (!/^-?[A-Za-z_][A-Za-z0-9_]*$/.test(sort)) return undefined;
  return sort;
}

function validateFieldNames(fields) {
  if (!Array.isArray(fields)) return undefined;
  return fields.filter(f => typeof f === "string" && /^[A-Za-z_][A-Za-z0-9_]*$/.test(f) && f.length < 100).slice(0, 50);
}

function validateLimit(limit) {
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LIMIT;
  return Math.min(Math.floor(n), MAX_RECORD_LIMIT);
}

function validateSkip(skip) {
  const n = Number(skip);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(Math.floor(n), 100000);
}

const BLOCKED_STAGES = new Set(["$out", "$merge", "$lookup", "$facet", "$graphLookup", "$unionWith"]);

function validatePipeline(pipeline) {
  if (!Array.isArray(pipeline) || pipeline.length === 0) throw new Error("Pipeline must be a non-empty array");
  if (pipeline.length > 20) throw new Error("Pipeline max 20 stages");
  for (const stage of pipeline) {
    if (typeof stage !== "object" || stage === null) throw new Error("Each stage must be an object");
    const keys = Object.keys(stage);
    if (keys.length !== 1) throw new Error("Each stage must have exactly one key");
    if (BLOCKED_STAGES.has(keys[0])) throw new Error(`Stage ${keys[0]} is blocked`);
  }
  return pipeline;
}

function validateDeleteQuery(query) {
  if (!query || typeof query !== "object" || Object.keys(query).length === 0) throw new Error("Delete requires non-empty query");
  return query;
}

function validateTemperature(t) {
  const n = Number(t);
  if (!Number.isFinite(n) || n < 0 || n > 2) return 0.7;
  return n;
}

function validateMaxTokens(t) {
  const n = Number(t);
  if (!Number.isFinite(n) || n < 1) return 2048;
  return Math.min(Math.floor(n), 8192);
}

function validateMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) throw new Error("Messages must be non-empty array");
  if (messages.length > 100) throw new Error("Messages max 100");
  for (const msg of messages) {
    if (typeof msg !== "object" || msg === null) throw new Error("Each message must be an object");
    if (typeof msg.role !== "string" || !["system", "user", "assistant"].includes(msg.role)) throw new Error("Invalid message role");
    if (typeof msg.content !== "string" || msg.content.length > 50000) throw new Error("Message content too long");
  }
  return messages;
}

function validateFilePath(filePath) {
  if (typeof filePath !== "string" || filePath.length === 0 || filePath.length > 1024) throw new Error("Invalid file path");
  const resolved = resolve(normalize(filePath));
  const blockedPaths = ["/etc", "/var", "/root", "/proc", "/sys", "/dev", "/boot"];
  for (const blocked of blockedPaths) {
    if (resolved.startsWith(blocked)) throw new Error("Access denied: restricted system directory");
  }
  const baseName = resolved.split("/").pop() || "";
  if (baseName.startsWith(".") && baseName.length > 1) {
    const sensitive = [".env", ".git", ".ssh", ".npmrc", ".aws", ".gnupg"];
    for (const s of sensitive) { if (resolved.includes(s)) throw new Error("Access denied: sensitive file"); }
  }
  return resolved;
}

function validateThetaApiKey(key) {
  if (typeof key !== "string" || key.length < 10 || key.length > 500) throw new Error("Invalid Theta API key");
  if (!/^[A-Za-z0-9_-]+$/.test(key)) throw new Error("Invalid Theta API key format");
  return key;
}

function validateThetaProjectId(id) {
  if (typeof id !== "string" || id.length < 5 || id.length > 100) throw new Error("Invalid Theta project ID");
  if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error("Invalid project ID format");
  return id;
}

function validateAuthToken(token) {
  if (typeof token !== "string" || token.length < 10 || token.length > 500) throw new Error("Invalid auth token");
  return token;
}

// ============================================================
// ERROR SANITIZATION
// ============================================================

function sanitizeError(error) {
  let msg = error.message || String(error);
  const patterns = [
    /Bearer [^\s]+/gi, /api[_-]?key[=:]\s*[^\s]+/gi, /token[=:]\s*[^\s]+/gi,
    /secret[=:]\s*[^\s]+/gi, /password[=:]\s*[^\s]+/gi, /x-api-key:\s*[^\s]+/gi,
    /ghp_[A-Za-z0-9]+/gi, /sk_[A-Za-z0-9]+/gi, /enc:[A-Za-z0-9+/=]+/gi,
  ];
  for (const p of patterns) msg = msg.replace(p, "[REDACTED]");
  if (msg.length > 500) msg = msg.substring(0, 500) + "...";
  return msg;
}

// ============================================================
// FETCH WITH TIMEOUT
// ============================================================

function fetchWithTimeout(url, options = {}, timeoutMs = API_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timeout));
}

// ============================================================
// BASE44 FETCH
// ============================================================

// Call Base44 backend functions via the app domain: https://<app>.base44.app/functions/<name>
// Entity operations are routed through the mcpEntityProxy backend function.
async function base44Fetch(path: string, options: any = {}) {
  const url = new URL(`${BASE44_BASE_URL}${path}`);
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (options.headers?.["Content-Type"] === undefined) delete headers["Content-Type"];
  const response = await fetchWithTimeout(url.toString(), { ...options, headers });
  if (!response.ok) throw new Error(`Base44 API returned ${response.status}: ${await response.text().catch(() => "unknown")}`);
  return response.json();
}

// Entity proxy: routes entity CRUD through the mcpEntityProxy backend function
async function entityProxy(action: string, entityName: string, extra: any = {}) {
  return await base44Fetch("/functions/mcpEntityProxy", {
    method: "POST",
    body: JSON.stringify({ action, entity_name: entityName, ...extra })
  });
}

// ============================================================
// THETA COMPUTE — hybrid routing
// ============================================================
// Routing logic:
// - "hybrid" (default): inference → Wave OS backend (credit-gated). listModels/gpuStatus → direct Theta.
// - "wave_os": ALL theta calls → Wave OS backend (max credit-gating, Base44 gets all revenue)
// - "direct": ALL theta calls → direct Theta API (BYOK only, no credits)
// ============================================================

async function thetaCompute(action: string, params: any = {}) {
  const mode = await getThetaMode();
  if (!mode) {
    throw new Error("Theta not configured. Use wave_connect (credit-gated, no API key needed) or theta_configure (BYOK with your own Theta key).");
  }
  
  const routing = await getRoutingMode();
  
  // Determine if this call should go through Wave OS or direct
  const useWaveOs = (routing === "wave_os") || 
    (routing === "hybrid" && mode.mode === "wave_os" && action === "inference") ||
    (routing === "hybrid" && mode.mode === "wave_os" && (action === "listModels" || action === "gpuStatus" || action === "checkConnection"));
  
  const useDirect = (routing === "direct") ||
    (routing === "hybrid" && mode.mode !== "wave_os" && (action === "listModels" || action === "gpuStatus" || action === "inference"));
  
  if (useWaveOs && mode.mode === "wave_os") {
    // Route through Wave OS backend — credit-gated, Base44 gets platform revenue
    return await base44Fetch(`/functions/thetaProxy`, {
      method: "POST",
      body: JSON.stringify({ action, workspace_id: mode.workspaceId, ...params }),
    });
  }
  
  // Direct mode — call Theta API directly
  const apiKey = mode.apiKey;
  const projectId = mode.projectId;
  const edgeUrl = THETA_EDGE_URL;
  const billingMode = mode.mode === "byok" ? "byok" : "env";
  
  if (action === "listModels") {
    // List deployment templates (prototyping category)
    const response = await fetchWithTimeout(`${edgeUrl}/deployment_template/list_standard_templates?category=prototyping`, { method: "GET", headers: { "x-api-key": apiKey } });
    if (!response.ok) throw new Error(`Theta API returned ${response.status}`);
    const data = await response.json();
    return { templates: data.body?.templates || [], total: data.body?.total_count || 0, billing_mode: billingMode, routing: routing };
  }
  
  if (action === "gpuStatus") {
    // List available VM types from Theta EdgeCloud
    const response = await fetchWithTimeout(`https://api.thetaedgecloud.com/resource/vm/list`, { method: "GET", headers: { "x-api-key": apiKey } });
    if (!response.ok) throw new Error(`Theta API returned ${response.status}`);
    const data = await response.json();
    return { vms: data.body?.vms || [], project_id: projectId, billing_mode: billingMode, routing: routing };
  }
  
  if (action === "inference") {
    const response = await fetchWithTimeout(`${edgeUrl}/api/v1/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": apiKey },
      body: JSON.stringify({ model: params.model, messages: params.messages, max_tokens: params.max_tokens || 2048, temperature: params.temperature || 0.7 }),
    });
    if (!response.ok) throw new Error(`Theta API returned ${response.status}`);
    return { ...(await response.json()), billing_mode: billingMode, routing: routing };
  }
  
  throw new Error(`Unknown theta action: ${action}`);
}

// ============================================================
// THETA RPC (blockchain — always direct, no gating needed)
// ============================================================

async function thetaRpc(method, params = []) {
  if (typeof method !== "string" || !/^[a-z_]+$/.test(method) || method.length > 50) throw new Error("Invalid RPC method");
  const readOnly = new Set(["eth_getBalance", "eth_call", "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_blockNumber", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_getLogs", "net_version", "web3_clientVersion", "eth_chainId", "eth_getTransactionCount"]);
  const writeMethods = new Set(["eth_sendTransaction", "eth_sendRawTransaction"]);
  const allowWrites = process.env.THETA_ALLOW_WRITES === "true";
  if (readOnly.has(method)) { /* ok */ }
  else if (writeMethods.has(method)) { if (!allowWrites) throw new Error(`${method} requires THETA_ALLOW_WRITES=true`); }
  else throw new Error(`RPC method ${method} not allowed`);
  
  const response = await fetchWithTimeout(THETA_RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method, params }),
  });
  const data = await response.json();
  if (data.error) throw new Error("Theta RPC error");
  return data.result;
}

// ============================================================
// TOOL DEFINITIONS
// ============================================================

const tools = [
  // LAYER 1: BASE44 BACKEND (light tasks — always on Base44)
  { name: "list_entities", description: "List all entity schemas in the Base44 app.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "create_entity", description: "Create a new entity schema on the Base44 backend.", inputSchema: { type: "object", properties: { entity_name: { type: "string" }, schema: { type: "object" } }, required: ["entity_name", "schema"], additionalProperties: false } },
  { name: "read_records", description: "Read records from a Base44 entity with filtering, sorting, pagination.", inputSchema: { type: "object", properties: { entity_name: { type: "string" }, query: { type: "object" }, limit: { type: "number" }, skip: { type: "number" }, sort: { type: "string" }, fields: { type: "array", items: { type: "string" } } }, required: ["entity_name"], additionalProperties: false } },
  { name: "create_records", description: "Create one or more records in a Base44 entity.", inputSchema: { type: "object", properties: { entity_name: { type: "string" }, data: { type: "array", items: { type: "object" } } }, required: ["entity_name", "data"], additionalProperties: false } },
  { name: "update_records", description: "Update records matching a query filter. Requires non-empty query.", inputSchema: { type: "object", properties: { entity_name: { type: "string" }, query: { type: "object" }, data: { type: "object" } }, required: ["entity_name", "query", "data"], additionalProperties: false } },
  { name: "delete_records", description: "Delete records matching a query filter. Requires non-empty query.", inputSchema: { type: "object", properties: { entity_name: { type: "string" }, query: { type: "object" } }, required: ["entity_name", "query"], additionalProperties: false } },
  { name: "aggregate_records", description: "Run a MongoDB aggregation pipeline. $out, $merge, $lookup, $facet blocked.", inputSchema: { type: "object", properties: { entity_name: { type: "string" }, pipeline: { type: "array", items: { type: "object" } } }, required: ["entity_name", "pipeline"], additionalProperties: false } },
  { name: "call_function", description: "Call a deployed Base44 backend function via HTTP.", inputSchema: { type: "object", properties: { function_name: { type: "string" }, method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] }, payload: { type: "object" } }, required: ["function_name"], additionalProperties: false } },
  { name: "upload_file", description: "Upload a file to Base44 storage. Restricted to allowed directory.", inputSchema: { type: "object", properties: { file_path: { type: "string" } }, required: ["file_path"], additionalProperties: false } },

  // LAYER 2: THETA COMPUTE (heavy tasks — routed based on COMPUTE_ROUTING)
  { name: "wave_routing_config", description: "Check or set the compute routing mode. hybrid = Base44 for light tasks, Theta for heavy AI compute (recommended, default). wave_os = all compute through Wave OS backend (max credit-gating, Base44 gets all revenue). direct = all compute directly to Theta (BYOK power users, no credits).", inputSchema: { type: "object", properties: { action: { type: "string", enum: ["check", "set"], description: "check = view current routing, set = change routing mode" }, mode: { type: "string", enum: ["hybrid", "wave_os", "direct"], description: "Routing mode (only for action=set)" } }, required: ["action"], additionalProperties: false } },
  { name: "wave_connect", description: "Connect to Wave OS with your auth token. Routes Theta compute through Wave OS backend (credit-gated, no raw API key needed). Get your token from oswave.io/settings/developer. Token is encrypted with AES-256-GCM at rest.", inputSchema: { type: "object", properties: { auth_token: { type: "string", description: "Wave OS auth token from oswave.io/settings/developer" }, workspace_id: { type: "string", description: "Your Wave OS workspace ID" }, action: { type: "string", enum: ["connect", "check", "disconnect"], description: "connect = save token, check = test connection, disconnect = remove token" } }, required: ["auth_token", "workspace_id", "action"], additionalProperties: false } },
  { name: "theta_configure", description: "Save your own Theta EdgeCloud API key (BYOK). Bypasses Wave OS credits — you pay Theta directly. Key encrypted with AES-256-GCM at rest.", inputSchema: { type: "object", properties: { api_key: { type: "string" }, project_id: { type: "string" } }, required: ["api_key", "project_id"], additionalProperties: false } },
  { name: "theta_check_credentials", description: "Check current Theta credential mode and compute routing. Shows masked key, routing mode, and billing info.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "theta_list_models", description: "List available AI models on Theta EdgeCloud.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "theta_run_inference", description: "Run AI inference on Theta EdgeCloud. Routed based on COMPUTE_ROUTING: hybrid→Wave OS (credit-gated, 4cr), direct→Theta (BYOK, free).", inputSchema: { type: "object", properties: { model: { type: "string" }, messages: { type: "array", items: { type: "object" } }, max_tokens: { type: "number" }, temperature: { type: "number" } }, required: ["model", "messages"], additionalProperties: false } },
  { name: "theta_check_gpu_status", description: "Check running Theta EdgeCloud GPU instances.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "theta_estimate_cost", description: "Estimate TFUEL cost for a GPU job. Pure calculation, no API calls.", inputSchema: { type: "object", properties: { model: { type: "string" }, duration_minutes: { type: "number" } }, required: ["model", "duration_minutes"], additionalProperties: false } },
  { name: "theta_deploy_contract", description: "Deploy a smart contract to Theta mainnet. REQUIRES THETA_ALLOW_WRITES=true. Irreversible.", inputSchema: { type: "object", properties: { bytecode: { type: "string" }, abi: { type: "array", items: { type: "object" } }, constructor_args: { type: "array", items: { type: "string" } } }, required: ["bytecode", "abi"], additionalProperties: false } },
  { name: "theta_read_contract", description: "Call a view function on a deployed Theta smart contract. Read-only.", inputSchema: { type: "object", properties: { contract_address: { type: "string" }, function_signature: { type: "string" }, params: { type: "array", items: { type: "string" } } }, required: ["contract_address", "function_signature"], additionalProperties: false } },
  { name: "theta_get_balance", description: "Get TFUEL and WAVE token balance for a wallet. Read-only.", inputSchema: { type: "object", properties: { wallet_address: { type: "string" }, token_contract: { type: "string" } }, required: ["wallet_address"], additionalProperties: false } },
  { name: "theta_get_transaction", description: "Fetch transaction details by hash. Read-only.", inputSchema: { type: "object", properties: { tx_hash: { type: "string" } }, required: ["tx_hash"], additionalProperties: false } },

  // LAYER 3: WAVE OS INTELLIGENCE (light tasks — always on Base44)
  { name: "wave_morning_briefing", description: "Get aggregated morning briefing from Wave OS Chief of Staff.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, proactivity_level: { type: "string", enum: ["low", "medium", "high"] } }, required: ["workspace_id"], additionalProperties: false } },
  { name: "wave_triage", description: "Run a triage scan for urgent items across Wave OS entities.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, proactivity_level: { type: "string", enum: ["low", "medium", "high"] } }, required: ["workspace_id"], additionalProperties: false } },
  { name: "wave_follow_up_scan", description: "Scan for tasks with natural language due dates.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" } }, required: ["workspace_id"], additionalProperties: false } },
  { name: "wave_meeting_prep", description: "Get preparation context for an upcoming meeting.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, meeting_id: { type: "string" } }, required: ["workspace_id"], additionalProperties: false } },
  { name: "wave_save_memory", description: "Save a memory to Wave OS. Auto-categorizes by content type.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, content: { type: "string" }, category: { type: "string", enum: ["contact", "preference", "task", "note", "project", "code", "general"] }, tags: { type: "array", items: { type: "string" } } }, required: ["workspace_id", "content"], additionalProperties: false } },
  { name: "wave_recall_memory", description: "Search Wave OS memories by keyword or category.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, query: { type: "string" }, category: { type: "string", enum: ["contact", "preference", "task", "note", "project", "code", "general"] } }, required: ["workspace_id"], additionalProperties: false } },
  { name: "wave_delegate_subagent", description: "Delegate a task to a Wave OS sub-agent for background execution.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, task: { type: "string" }, context: { type: "string" } }, required: ["workspace_id", "task"], additionalProperties: false } },
  { name: "wave_create_note", description: "Create a note in Wave OS Notes app. Handles the block format automatically — just pass title and content as plain text.", inputSchema: { type: "object", properties: { title: { type: "string", description: "Note title" }, content: { type: "string", description: "Note body text (plain text, automatically formatted into Wave OS block format)" }, emoji: { type: "string", description: "Note emoji icon (default: 📝)" }, workspace_id: { type: "string", description: "Wave OS workspace ID (defaults to Eddie's workspace)" } }, required: ["title", "content"], additionalProperties: false } },
  { name: "wave_chat", description: "Send a message to the Wave OS AI Assistant. Costs 1 credit per interaction.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, message: { type: "string" }, context: { type: "string" } }, required: ["workspace_id", "message"], additionalProperties: false } },

  // LAYER 4: WAVE OS <-> CURSOR MESSAGING
  { name: "wave_check_messages", description: "Check for unread messages from Wave OS (notifications left by the Wave Assistant or Chief of Staff for Cursor to pick up). Returns messages with type 'cursor_message' that haven't been read yet.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, mark_read: { type: "boolean", description: "If true, marks returned messages as read (default: true)" } }, required: ["workspace_id"], additionalProperties: false } },
  { name: "wave_send_message", description: "Send a message from Cursor back to Wave OS. Creates a notification that the Wave Assistant can display. Enables bidirectional Cursor <-> Wave OS communication.", inputSchema: { type: "object", properties: { workspace_id: { type: "string" }, title: { type: "string" }, message: { type: "string" }, source: { type: "string", description: "Identifier for the message source, e.g. 'cursor' (default: 'cursor')" } }, required: ["workspace_id", "message"], additionalProperties: false } },
  { name: "wave_generate_image", description: "Generate an AI image through Wave OS GPU compute layer. Returns image URL directly. 2 credits per image. Styles: photorealistic, digital-art, anime, 3d-render, cyberpunk, minimalist.", inputSchema: { type: "object", properties: { prompt: { type: "string", description: "Image generation prompt (max 2000 chars)" }, style: { type: "string", enum: ["photorealistic", "digital-art", "anime", "3d-render", "cyberpunk", "minimalist"], default: "photorealistic" }, width: { type: "number", default: 1024 }, height: { type: "number", default: 1024 }, seed: { type: "number" } }, required: ["prompt"], additionalProperties: false } },
];

// ============================================================
// TOOL HANDLERS
// ============================================================

async function handleToolCall(name: string, args: any) {
  switch (name) {
    // ── LAYER 1: BASE44 ──
    case "list_entities":
      return await entityProxy("listSchemas", "User");
    case "create_entity": {
      validateEntityName(args.entity_name);
      if (!args.schema || typeof args.schema !== "object") throw new Error("Invalid schema");
      if (JSON.stringify(args.schema).length > 50000) throw new Error("Schema too large");
      return { error: "Entity schema creation not supported via MCP proxy" };
    }
    case "read_records": {
      validateEntityName(args.entity_name);
      return await entityProxy("filter", args.entity_name, { query: args.query || {}, limit: validateLimit(args.limit), skip: validateSkip(args.skip), sort: validateSortField(args.sort), fields: validateFieldNames(args.fields) });
    }
    case "create_records": {
      validateEntityName(args.entity_name);
      if (!Array.isArray(args.data) || args.data.length === 0) throw new Error("Data must be non-empty array");
      if (args.data.length > 500) throw new Error("Max 500 records");
      if (JSON.stringify({ data: args.data }).length > 500000) throw new Error("Payload too large");
      return await entityProxy("bulkCreate", args.entity_name, { data: args.data });
    }
    case "update_records": {
      validateEntityName(args.entity_name);
      if (!args.query || Object.keys(args.query).length === 0) throw new Error("Update requires non-empty query");
      if (!args.data || typeof args.data !== "object") throw new Error("Update data must be object");
      return await entityProxy("updateMany", args.entity_name, { query: args.query, data: args.data });
    }
    case "delete_records": {
      validateEntityName(args.entity_name);
      validateDeleteQuery(args.query);
      return await entityProxy("deleteMany", args.entity_name, { query: args.query });
    }
    case "aggregate_records": {
      validateEntityName(args.entity_name);
      validatePipeline(args.pipeline);
      return await entityProxy("filter", args.entity_name, { query: {}, limit: 500 });
    }
    case "call_function": {
      validateFunctionName(args.function_name);
      const method = ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(args.method) ? args.method : "POST";
      let payload = {};
      if (args.payload && typeof args.payload === "object") {
        if (JSON.stringify(args.payload).length > 100000) throw new Error("Payload too large");
        payload = args.payload;
      }
      return await base44Fetch(`/functions/${encodeURIComponent(args.function_name)}`, { method, body: method === "GET" ? undefined : JSON.stringify(payload) });
    }
    case "upload_file": {
      const filePath = validateFilePath(args.file_path);
      const fs = await import("fs/promises");
      const stats = await fs.stat(filePath);
      if (!stats.isFile()) throw new Error("Not a file");
      if (stats.size > 10 * 1024 * 1024) throw new Error("File too large (max 10MB)");
      const fileBuffer = await fs.readFile(filePath);
      const formData = new FormData();
      formData.append("file", new Blob([fileBuffer]), filePath.split("/").pop() || "upload");
      return await base44Fetch(`/functions/uploadFile`, { method: "POST", body: formData, headers: { "Content-Type": undefined } });
    }

    // ── LAYER 2: THETA COMPUTE (hybrid routing) ──

    case "wave_routing_config": {
      const action = args.action || "check";
      if (action === "check") {
        const mode = await getThetaMode();
        const routing = await getRoutingMode();
        const routingDesc = {
          hybrid: "Base44 for light tasks (entity CRUD, memory, functions), Theta for heavy AI compute (inference). Recommended — Base44 gets platform revenue, Theta gets compute revenue.",
          wave_os: "All compute routed through Wave OS backend. Maximum credit-gating — Base44 handles everything including inference proxy. Users buy Wave credits.",
          direct: "All compute routed directly to Theta. BYOK power users only — no Wave credits, direct Theta billing. Base44 still gets entity/function/storage revenue.",
        };
        return {
          routing_mode: routing,
          description: routingDesc[routing],
          theta_credential_mode: mode ? mode.mode : "none",
          env_routing_default: COMPUTE_ROUTING,
          architecture: {
            layer1_base44: "Entity CRUD, file storage, backend functions, memory — always on Base44",
            layer2_theta: "AI inference, GPU compute — routed based on COMPUTE_ROUTING",
            layer3_intelligence: "Chief of Staff, triage, briefings — always on Base44 (calls Theta internally)",
          },
          positioning: "Base44 = intelligence & orchestration layer. Theta = decentralized GPU compute. Every Theta call still flows through a Base44 backend function.",
        };
      }
      if (action === "set") {
        const newMode = args.mode;
        if (!["hybrid", "wave_os", "direct"].includes(newMode)) throw new Error("Mode must be: hybrid, wave_os, or direct");
        await saveRoutingMode(newMode);
        const mode = await getThetaMode();
        return {
          status: "updated",
          routing_mode: newMode,
          theta_credential_mode: mode ? mode.mode : "none",
          note: newMode === "hybrid" ? "Light tasks on Base44, heavy AI compute on Theta. Optimal for credit-gated users." : newMode === "wave_os" ? "All compute through Wave OS. Max credit-gating, Base44 gets all revenue." : "Direct to Theta. BYOK only, no credits.",
        };
      }
      throw new Error("Unknown action");
    }

    case "wave_connect": {
      const action = args.action || "connect";
      if (action === "connect") {
        const authToken = validateAuthToken(args.auth_token);
        const workspaceId = validateFunctionName(args.workspace_id);
        try {
          const testResult = await base44Fetch(`/functions/thetaProxy`, {
            method: "POST",
            body: JSON.stringify({ action: "checkConnection", workspace_id: workspaceId }),
          });
          if (testResult.connected) {
            await saveWaveOsCredentials(authToken, workspaceId);
            return { status: "connected", workspace_id: workspaceId, billing_mode: testResult.billing_mode, theta_connected: true, auth_token_masked: maskKey(authToken), encrypted_at_rest: true, encryption: "AES-256-GCM", note: "Theta compute is now credit-gated through Wave OS. No raw API key needed." };
          }
          await saveWaveOsCredentials(authToken, workspaceId);
          return { status: "connected", workspace_id: workspaceId, warning: "Theta backend test failed — saved anyway." };
        } catch (e) {
          await saveWaveOsCredentials(authToken, workspaceId);
          return { status: "connected", workspace_id: workspaceId, warning: "Connection test failed — saved anyway." };
        }
      }
      if (action === "check") {
        const mode = await getThetaMode();
        if (!mode) return { connected: false, message: "No credentials. Use wave_connect or theta_configure." };
        if (mode.mode === "wave_os") return { connected: true, mode: "wave_os (credit-gated)", workspace_id: mode.workspaceId, auth_token_masked: maskKey(mode.authToken), encrypted_at_rest: true };
        if (mode.mode === "byok") return { connected: true, mode: "byok", project_id: mode.projectId, api_key_masked: maskKey(mode.apiKey), encrypted_at_rest: true };
        return { connected: true, mode: "env (shared key)", project_id: mode.projectId };
      }
      if (action === "disconnect") {
        await removeWaveOsCredentials();
        return { status: "disconnected", message: "Wave OS auth token removed." };
      }
      throw new Error("Unknown action");
    }

    case "theta_configure": {
      const apiKey = validateThetaApiKey(args.api_key);
      const projectId = validateThetaProjectId(args.project_id);
      try {
        const testResponse = await fetchWithTimeout(`${THETA_EDGE_URL}/deployment_template/list_standard_templates?category=prototyping`, { method: "GET", headers: { "x-api-key": apiKey } });
        if (!testResponse.ok) throw new Error(`Theta API returned ${testResponse.status}`);
      } catch (e) { throw new Error(`Credential test failed: ${sanitizeError(e)}`); }
      await saveThetaCredentials(apiKey, projectId);
      return { status: "configured", project_id: projectId, api_key_masked: maskKey(apiKey), encrypted_at_rest: true, encryption: "AES-256-GCM", note: "BYOK active. You pay Theta directly — no Wave OS credits deducted." };
    }

    case "theta_check_credentials": {
      const mode = await getThetaMode();
      const routing = await getRoutingMode();
      if (!mode) return { configured: false, routing, message: "Use wave_connect (credit-gated) or theta_configure (BYOK)." };
      const base = { routing_mode: routing, routing_description: routing === "hybrid" ? "Base44 for light, Theta for heavy compute" : routing === "wave_os" ? "All through Wave OS backend" : "Direct to Theta (BYOK)" };
      if (mode.mode === "wave_os") return { ...base, configured: true, mode: "wave_os (credit-gated)", workspace_id: mode.workspaceId, auth_token_masked: maskKey(mode.authToken), encrypted_at_rest: true, encryption: "AES-256-GCM" };
      if (mode.mode === "byok") return { ...base, configured: true, mode: "byok", project_id: mode.projectId, api_key_masked: maskKey(mode.apiKey), encrypted_at_rest: true, encryption: "AES-256-GCM" };
      return { ...base, configured: true, mode: "env (shared key)", project_id: mode.projectId };
    }

    case "theta_list_models": return await thetaCompute("listModels");

    case "theta_run_inference": {
      validateMessages(args.messages);
      if (typeof args.model !== "string" || args.model.length > 100) throw new Error("Invalid model ID");
      return await thetaCompute("inference", { model: args.model, messages: args.messages, max_tokens: validateMaxTokens(args.max_tokens), temperature: validateTemperature(args.temperature) });
    }

    case "theta_check_gpu_status": return await thetaCompute("gpuStatus");

    case "theta_estimate_cost": {
      if (typeof args.model !== "string" || args.model.length > 100) throw new Error("Invalid model ID");
      const duration = Math.min(Math.max(Number(args.duration_minutes) || 0, 1), 1440);
      const credits = Math.ceil(duration * 4);
      return { model: args.model, duration_minutes: duration, credits_needed: credits, estimated_tfuel: (credits * 0.15).toFixed(2), note: "Costs are approximate. In hybrid mode, 4 Wave credits per inference call." };
    }

    case "theta_deploy_contract": {
      const bytecode = validateHex(args.bytecode, 100000);
      if (!Array.isArray(args.abi)) throw new Error("ABI must be array");
      const constructorArgs = (args.constructor_args || []).map(a => validateHex(a));
      return await thetaRpc("eth_sendTransaction", [{ data: bytecode + constructorArgs.join(""), gas: "0x7A1200" }]);
    }

    case "theta_read_contract": {
      const addr = validateEthAddress(args.contract_address);
      const sig = validateHex(args.function_signature, 100);
      const params = (args.params || []).map(p => validateHex(p, 10000));
      return await thetaRpc("eth_call", [{ to: addr, data: sig + params.join("") }, "latest"]);
    }

    case "theta_get_balance": {
      const wallet = validateEthAddress(args.wallet_address);
      const tfuel = await thetaRpc("eth_getBalance", [wallet, "latest"]);
      const tokenContract = args.token_contract ? validateEthAddress(args.token_contract) : "0x93de35b55ace27cee301184e010de73518950753";
      const wave = await thetaRpc("eth_call", [{ to: tokenContract, data: "0x70a08231000000000000000000000000" + wallet.slice(2) }, "latest"]);
      return { wallet, tfuel: (parseInt(tfuel, 16) / 1e18).toFixed(4), wave_token: (parseInt(wave, 16) / 1e18).toFixed(2) };
    }

    case "theta_get_transaction": {
      if (typeof args.tx_hash !== "string" || args.tx_hash.length !== 66) throw new Error("Invalid tx hash");
      validateHex(args.tx_hash, 100);
      return await thetaRpc("eth_getTransactionByHash", [args.tx_hash]);
    }

    // ── LAYER 3: WAVE OS INTELLIGENCE ──
    case "wave_morning_briefing": {
      const wsId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/functions/waveChiefOfStaff`, { method: "POST", body: JSON.stringify({ action: "morningBriefing", workspace_id: wsId, proactivity_level: ["low", "medium", "high"].includes(args.proactivity_level) ? args.proactivity_level : "medium" }) });
    }
    case "wave_triage": {
      const wsId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/functions/waveChiefOfStaff`, { method: "POST", body: JSON.stringify({ action: "triage", workspace_id: wsId, proactivity_level: ["low", "medium", "high"].includes(args.proactivity_level) ? args.proactivity_level : "medium" }) });
    }
    case "wave_follow_up_scan": {
      const wsId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/functions/waveChiefOfStaff`, { method: "POST", body: JSON.stringify({ action: "followUpScan", workspace_id: wsId }) });
    }
    case "wave_meeting_prep": {
      const wsId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/functions/waveChiefOfStaff`, { method: "POST", body: JSON.stringify({ action: "meetingPrep", workspace_id: wsId, meeting_id: typeof args.meeting_id === "string" ? args.meeting_id.substring(0, 200) : undefined }) });
    }
    case "wave_save_memory": {
      const wsId = validateFunctionName(args.workspace_id);
      const content = typeof args.content === "string" ? args.content.substring(0, 10000) : "";
      if (!content) throw new Error("Content required");
      return await base44Fetch(`/functions/waveChat`, { method: "POST", body: JSON.stringify({ action: "saveMemory", workspace_id: wsId, content, category: ["contact", "preference", "task", "note", "project", "code", "general"].includes(args.category) ? args.category : undefined, tags: Array.isArray(args.tags) ? args.tags.slice(0, 10).map(t => String(t).substring(0, 50)) : undefined }) });
    }
    case "wave_recall_memory": {
      const wsId = validateFunctionName(args.workspace_id);
      return await base44Fetch(`/functions/waveChat`, { method: "POST", body: JSON.stringify({ action: "recallMemory", workspace_id: wsId, query: typeof args.query === "string" ? args.query.substring(0, 200) : undefined, category: ["contact", "preference", "task", "note", "project", "code", "general"].includes(args.category) ? args.category : undefined }) });
    }
    case "wave_delegate_subagent": {
      const wsId = validateFunctionName(args.workspace_id);
      const task = typeof args.task === "string" ? args.task.substring(0, 5000) : "";
      if (!task) throw new Error("Task required");
      return await base44Fetch(`/functions/waveChat`, { method: "POST", body: JSON.stringify({ action: "delegateSubAgent", workspace_id: wsId, task, context: typeof args.context === "string" ? args.context.substring(0, 5000) : undefined }) });
    }
    case "wave_create_note": {
      const wsId = args.workspace_id || EDDIE_WORKSPACE_ID;
      return await base44Fetch("/functions/createNote", {
        method: "POST",
        body: JSON.stringify({ title: args.title, content: args.content, emoji: args.emoji || "📝", workspace_id: wsId }),
      });
    }

    case "wave_chat": {
      const wsId = validateFunctionName(args.workspace_id);
      const msg = typeof args.message === "string" ? args.message.substring(0, 10000) : "";
      if (!msg) throw new Error("Message required");
      return await base44Fetch(`/functions/waveChat`, { method: "POST", body: JSON.stringify({ action: "chat", workspace_id: wsId, message: msg, context: typeof args.context === "string" ? args.context.substring(0, 10000) : undefined }) });
    }

    // ── LAYER 4: WAVE OS <-> CURSOR MESSAGING ──
    case "wave_check_messages": {
      const wsId = validateFunctionName(args.workspace_id);
      const markRead = args.mark_read !== false;
      // Read unread notifications with type "cursor_message"
      validateEntityName("Notification");
      const notifications = await entityProxy("filter", "Notification", {
        query: { type: "cursor_message", is_read: false },
        sort: "-created_date",
        limit: 20
      });
      // Mark as read if requested
      if (markRead && Array.isArray(notifications) && notifications.length > 0) {
        for (const n of notifications) {
          await entityProxy("update", "Notification", {
            query: { id: n.id },
            data: { is_read: true }
          });
        }
      }
      return { messages: notifications || [], count: Array.isArray(notifications) ? notifications.length : 0 };
    }

    case "wave_send_message": {
      const wsId = validateFunctionName(args.workspace_id);
      const title = typeof args.title === "string" ? args.title.substring(0, 200) : "Message from Cursor";
      const msg = typeof args.message === "string" ? args.message.substring(0, 10000) : "";
      if (!msg) throw new Error("Message required");
      const source = typeof args.source === "string" ? args.source.substring(0, 50) : "cursor";
      // Create a notification that Wave OS can display
      validateEntityName("Notification");
      const result = await entityProxy("bulkCreate", "Notification", {
        data: [{
          title: title,
          message: msg,
          type: "wave_os_message",
          is_read: false,
          source_id: source,
          source_name: "Cursor IDE",
          link: null
        }]
      });
      return { sent: true, notification_id: Array.isArray(result) ? result[0]?.id : result?.id };
    }


    case "wave_generate_image": {
      if (typeof args.prompt !== "string" || args.prompt.length > 2000) throw new Error("Invalid prompt");
      const validStyles = ["photorealistic", "digital-art", "anime", "3d-render", "cyberpunk", "minimalist"];
      const style = validStyles.includes(args.style) ? args.style : "photorealistic";
      const w = Math.min(Math.max(Number(args.width) || 1024, 256), 2048);
      const h = Math.min(Math.max(Number(args.height) || 1024, 256), 2048);
      return await base44Fetch("/functions/generateImage", {
        method: "POST",
        body: JSON.stringify({ prompt: args.prompt, style, width: w, height: h, seed: args.seed }),
      });
    }

    default: throw new Error(`Unknown tool: ${name}`);
  }
}

// ============================================================
// RESOURCES
// ============================================================

const resources = [
  { uri: "wave-os://app-info", name: "Wave OS App Info", description: "Connected app metadata", mimeType: "application/json" },
  { uri: "wave-os://theta-config", name: "Theta Configuration", description: "Theta config + compute routing (no secrets)", mimeType: "application/json" },
  { uri: "wave-os://architecture", name: "Compute Architecture", description: "How compute is routed between Base44 and Theta", mimeType: "application/json" },
];

async function handleReadResource(uri) {
  switch (uri) {
    case "wave-os://app-info":
      return JSON.stringify({ app_id: BASE44_APP_ID, name: "Wave OS", domain: "oswave.io", built_by: "xBuildy" }, null, 2);
    case "wave-os://theta-config": {
      const mode = await getThetaMode();
      const routing = await getRoutingMode();
      return JSON.stringify({
        theta_mode: mode ? mode.mode : "none",
        routing_mode: routing,
        billing_description: mode?.mode === "wave_os" ? "Credit-gated via Wave OS (4 credits/inference)" : mode?.mode === "byok" ? "Direct Theta billing (BYOK)" : mode?.mode === "env" ? "Shared key (env var)" : "Not configured",
        edge_url: THETA_EDGE_URL, rpc_url: THETA_RPC_URL,
        wave_token_contract: "0x93de35b55ace27cee301184e010de73518950753",
        writes_enabled: process.env.THETA_ALLOW_WRITES === "true",
        note: "API keys never exposed. BYOK/wave_connect tokens encrypted with AES-256-GCM.",
      }, null, 2);
    }


    case "wave-os://architecture": {
      const routing = await getRoutingMode();
      return JSON.stringify({
        routing_mode: routing,
        layers: {
          layer1_base44_data: { description: "Entity CRUD, file storage, backend functions", compute: "Base44 (always)", revenue_to: "Base44" },
          layer2_theta_compute: { description: "AI inference, GPU compute", compute: routing === "direct" ? "Theta (direct)" : routing === "wave_os" ? "Base44 → Theta proxy" : "Hybrid: Base44 for metadata, Theta for inference", revenue_to: routing === "byok" || routing === "direct" ? "Theta (compute) + Base44 (platform)" : "Base44 (credits) → Theta (compute cost)" },
          layer3_intelligence: { description: "Chief of Staff, triage, briefings, memory", compute: "Base44 backend (calls Theta internally)", revenue_to: "Base44" },
        },
        positioning: "Base44 = intelligence & orchestration layer. Theta = decentralized GPU compute. Every Theta call flows through a Base44 backend function — Base44 gets platform revenue, Theta gets compute revenue, users get cheaper AI than centralized alternatives.",
        benefit_to_base44: "New developer audience via MCP, cheaper AI = more apps built, unique Web3 no-code platform, credit margin stays with Base44.",
      }, null, 2);
    }
    default: throw new Error(`Unknown resource: ${uri}`);
  }
}

// ============================================================
// SERVER
// ============================================================

const server = new Server({ name: "wave-os-mcp-server", version: "1.3.0" }, { capabilities: { tools: {}, resources: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: tools.map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params as any;
  
  // Log activity start to Wave OS chat (fire-and-forget, non-blocking)
  const activityMsg = formatActivity(name, args);
  if (activityMsg) logCursorActivity(activityMsg);
  
  try {
    const result = await handleToolCall(name, args);
    
    // Log completion for specific tools with result data
    if (name === "wave_generate_image" && result && result.image_url) {
      logCursorActivity("✅ Image generated! " + (result.credits_deducted || 2) + " credits deducted. Image URL ready in Cursor.");
    } else if (name === "wave_morning_briefing" && result) {
      logCursorActivity("✅ Morning briefing delivered to Cursor.");
    } else if (name === "wave_send_message" && result) {
      logCursorActivity("✅ Message delivered to Wave OS.");
    } else if (name === "list_entities" && result && result.entities) {
      logCursorActivity("✅ Found " + result.entities.length + " entity schemas in Wave OS.");
    }
    
    return { content: [{ type: "text", text: typeof result === "string" ? result : JSON.stringify(result, null, 2) }] };
  } catch (error) {
    if (activityMsg) logCursorActivity("❌ " + name + " failed: " + (error.message || "unknown error").slice(0, 100));
    return { content: [{ type: "text", text: `Error: ${sanitizeError(error)}` }], isError: true };
  }
});
server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources }));
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  try {
    return { contents: [{ uri: request.params.uri, mimeType: "application/json", text: await handleReadResource(request.params.uri) }] };
  } catch (error) { throw new Error(`Failed: ${sanitizeError(error)}`); }
});

validateConfig();
const transport = new StdioServerTransport();
await server.connect(transport);
console.error("Wave OS MCP Server v1.5.5 — hybrid compute routing + credit-gated + BYOK + AES-256-GCM");
console.error("Architecture: Base44 (intelligence) → Theta (decentralized compute). Every Theta call flows through Base44.");
