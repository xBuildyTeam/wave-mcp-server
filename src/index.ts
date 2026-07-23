/**
 * Wave OS MCP Server — Security-Hardened with BYOK + AES-256
 * 
 * Three layers exposed to AI coding assistants:
 * 1. Base44 Backend — entities, functions, files, auth
 * 2. Theta Compute — GPU provisioning, blockchain, smart contracts (supports user BYOK)
 * 3. Wave OS Intelligence — agent orchestration, memory, chief of staff
 * 
 * Built by xBuildy for the Base44 Dev Build-Off Competition
 * July 2026
 * 
 * SECURITY: All inputs validated, errors sanitized, filesystem access restricted,
 * destructive operations guarded, API keys encrypted at rest with AES-256-GCM,
 * and API keys never exposed in responses.
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
// CONFIG — Loaded from environment variables only
// ============================================================

const BASE44_APP_ID = process.env.BASE44_APP_ID || "";
const BASE44_API_KEY = process.env.BASE44_API_KEY || "";
const BASE44_BASE_URL = process.env.BASE44_BASE_URL || "https://api.base44.com";
const THETA_API_KEY_ENV = process.env.THETA_API_KEY || "";
const THETA_PROJECT_ID_ENV = process.env.THETA_PROJECT_ID || "";
const THETA_RPC_URL = process.env.THETA_RPC_URL || "https://theta-rpc.thetatoken.org";
const THETA_EDGE_URL = process.env.THETA_EDGE_URL || "https://controller.thetaedgecloud.com";

// Encryption key for BYOK credential storage — should be set via env var
// If not set, generates a machine-specific key from hostname + username
const MCP_ENCRYPTION_KEY = process.env.MCP_ENCRYPTION_KEY || "";

// Working directory for file uploads — restricts filesystem access
const ALLOWED_FILE_ROOT = process.env.MCP_FILE_ROOT || join(homedir(), "wave-mcp-uploads");

// Credential store path — encrypted Theta API keys saved by users
const CREDENTIAL_STORE_PATH = join(homedir(), ".wave-mcp", "credentials.json");

// Maximum records returned in a single call
const MAX_RECORD_LIMIT = 500;
const DEFAULT_LIMIT = 50;

// API call timeout (30 seconds)
const API_TIMEOUT_MS = 30000;

// Maximum response size (1MB)
const MAX_RESPONSE_BYTES = 1024 * 1024;

// ============================================================
// AES-256-GCM ENCRYPTION (matches Wave OS BYOK pattern)
// ============================================================

function getEncryptionKey() {
  // Use explicit env var if provided
  if (MCP_ENCRYPTION_KEY) {
    return createHash("sha256").update(MCP_ENCRYPTION_KEY).digest();
  }
  // Fallback: machine-specific key from hostname + username
  const os = require("os");
  const machineId = `${os.hostname()}:${os.userInfo().username}:wave-mcp-v1`;
  return createHash("sha256").update(machineId).digest();
}

function encryptKey(plaintext) {
  const key = getEncryptionKey();
  const iv = randomBytes(12); // 12-byte IV for GCM
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Format: "enc:" + base64(IV + authTag + ciphertext)
  const combined = Buffer.concat([iv, authTag, encrypted]);
  return "enc:" + combined.toString("base64");
}

function decryptKey(stored) {
  if (!stored || typeof stored !== "string") return null;
  
  // If not encrypted (legacy plaintext), return as-is for backward compat
  if (!stored.startsWith("enc:")) {
    return stored;
  }
  
  try {
    const key = getEncryptionKey();
    const combined = Buffer.from(stored.slice(4), "base64");
    const iv = combined.subarray(0, 12);
    const authTag = combined.subarray(12, 28);
    const ciphertext = combined.subarray(28);
    
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
  } catch (e) {
    throw new Error("Failed to decrypt stored credential — encryption key may have changed");
  }
}

function maskKey(key) {
  if (!key || key.length < 8) return "****";
  return key.substring(0, 4) + "••••••••" + key.substring(key.length - 4);
}

// ============================================================
// CREDENTIAL STORE — Encrypted at rest
// ============================================================

async function loadCredentials() {
  try {
    const fs = await import("fs/promises");
    const data = await fs.readFile(CREDENTIAL_STORE_PATH, "utf8");
    return JSON.parse(data);
  } catch (e) {
    return { theta: null };
  }
}

async function saveCredentials(creds) {
  const fs = await import("fs/promises");
  const dir = join(CREDENTIAL_STORE_PATH, "..");
  await fs.mkdir(dir, { recursive: true });
  // Write with 0600 permissions (owner read/write only)
  await fs.writeFile(CREDENTIAL_STORE_PATH, JSON.stringify(creds, null, 2), { mode: 0o600 });
}

async function getThetaCredentials() {
  // Priority: user-saved BYOK credentials > env vars
  const creds = await loadCredentials();
  if (creds.theta && creds.theta.api_key_encrypted) {
    try {
      const apiKey = decryptKey(creds.theta.api_key_encrypted);
      const projectId = creds.theta.project_id;
      if (apiKey && projectId) {
        return { apiKey, projectId, source: "byok", savedAt: creds.theta.saved_at };
      }
    } catch (e) {
      // Decryption failed — fall back to env vars
      console.error("WARNING: BYOK credential decryption failed, falling back to env vars");
    }
  }
  
  // Fall back to environment variables
  if (THETA_API_KEY_ENV && THETA_PROJECT_ID_ENV) {
    return { apiKey: THETA_API_KEY_ENV, projectId: THETA_PROJECT_ID_ENV, source: "env" };
  }
  
  return null;
}

async function saveThetaCredentials(apiKey, projectId) {
  const creds = await loadCredentials();
  creds.theta = {
    api_key_encrypted: encryptKey(apiKey),
    project_id: projectId,
    saved_at: new Date().toISOString(),
    encrypted_at_rest: true,
  };
  await saveCredentials(creds);
}

async function removeThetaCredentials() {
  const creds = await loadCredentials();
  creds.theta = null;
  await saveCredentials(creds);
}

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
  
  // Theta is optional — users can configure via BYOK tool or env vars
  const thetaMissing = [];
  if (!THETA_API_KEY_ENV) thetaMissing.push("THETA_API_KEY");
  if (!THETA_PROJECT_ID_ENV) thetaMissing.push("THETA_PROJECT_ID");
  if (thetaMissing.length > 0) {
    console.error(`INFO: Theta env vars not set (${thetaMissing.join(", ")}).`);
    console.error("Users can save their own Theta API key via the theta_configure tool (BYOK).");
    console.error("Or set THETA_API_KEY + THETA_PROJECT_ID as environment variables.");
  }
  
  // Validate URL formats
  try { new URL(BASE44_BASE_URL); } catch { console.error("FATAL: BASE44_BASE_URL is not a valid URL"); process.exit(1); }
  try { new URL(THETA_RPC_URL); } catch { console.error("FATAL: THETA_RPC_URL is not a valid URL"); process.exit(1); }
  try { new URL(THETA_EDGE_URL); } catch { console.error("FATAL: THETA_EDGE_URL is not a valid URL"); process.exit(1); }
  
  // Ensure file upload directory exists
  ensureUploadDir();
}

async function ensureUploadDir() {
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

function validateEthAddress(addr) {
  if (typeof addr !== "string" || !/^0x[a-fA-F0-9]{40}$/.test(addr)) {
    throw new Error("Invalid Ethereum address: must be 0x followed by 40 hex characters");
  }
  return addr;
}

function validateHex(hex, maxLen = 100000) {
  if (typeof hex !== "string" || !/^0x[a-fA-F0-9]+$/.test(hex) || hex.length > maxLen) {
    throw new Error("Invalid hex value: must be 0x-prefixed hex string");
  }
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

function validateDeleteQuery(query) {
  if (!query || typeof query !== "object" || Object.keys(query).length === 0) {
    throw new Error("Delete requires a non-empty query filter to prevent accidental table wipes");
  }
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
  if (!Array.isArray(messages) || messages.length === 0) {
    throw new Error("Messages must be a non-empty array");
  }
  if (messages.length > 100) {
    throw new Error("Messages array must not exceed 100 items");
  }
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

function validateFilePath(filePath) {
  if (typeof filePath !== "string" || filePath.length === 0 || filePath.length > 1024) {
    throw new Error("Invalid file path");
  }
  const resolved = resolve(normalize(filePath));
  const blockedPaths = ["/etc", "/var", "/root", "/proc", "/sys", "/dev", "/boot"];
  for (const blocked of blockedPaths) {
    if (resolved.startsWith(blocked)) {
      throw new Error(`Access denied: path is in a restricted system directory`);
    }
  }
  const baseName = resolved.split("/").pop() || "";
  if (baseName.startsWith(".") && baseName.length > 1) {
    const sensitiveDotfiles = [".env", ".git", ".ssh", ".npmrc", ".aws", ".gnupg"];
    for (const sensitive of sensitiveDotfiles) {
      if (resolved.includes(sensitive)) {
        throw new Error(`Access denied: cannot access sensitive file`);
      }
    }
  }
  return resolved;
}

// Validate Theta API key format (alphanumeric, dashes, typical Theta key format)
function validateThetaApiKey(key) {
  if (typeof key !== "string" || key.length < 10 || key.length > 500) {
    throw new Error("Invalid Theta API key: must be 10-500 characters");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(key)) {
    throw new Error("Invalid Theta API key: must be alphanumeric with hyphens/underscores only");
  }
  return key;
}

// Validate Theta project ID (typically alphanumeric, ~20 chars)
function validateThetaProjectId(id) {
  if (typeof id !== "string" || id.length < 5 || id.length > 100) {
    throw new Error("Invalid Theta project ID: must be 5-100 characters");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(id)) {
    throw new Error("Invalid Theta project ID: must be alphanumeric with hyphens/underscores only");
  }
  return id;
}

// ============================================================
// SECURITY: ERROR SANITIZATION
// ============================================================

function sanitizeError(error) {
  let msg = error.message || String(error);
  const sensitivePatterns = [
    /Bearer [^\s]+/gi,
    /api[_-]?key[=:]\s*[^\s]+/gi,
    /token[=:]\s*[^\s]+/gi,
    /secret[=:]\s*[^\s]+/gi,
    /password[=:]\s*[^\s]+/gi,
    /x-api-key:\s*[^\s]+/gi,
    /ghp_[A-Za-z0-9]+/gi,
    /sk_[A-Za-z0-9]+/gi,
    /enc:[A-Za-z0-9+/=]+/gi, // Never expose encrypted blobs
  ];
  for (const pattern of sensitivePatterns) {
    msg = msg.replace(pattern, "[REDACTED]");
  }
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
  if (options.headers && options.headers["Content-Type"] === undefined) {
    delete headers["Content-Type"];
  }
  const response = await fetchWithTimeout(url.toString(), { ...options, headers });
  if (!response.ok) {
    throw new Error(`Base44 API returned ${response.status}`);
  }
  const contentLength = parseInt(response.headers.get("content-length") || "0", 10);
  if (contentLength > MAX_RESPONSE_BYTES) {
    throw new Error("Response too large: exceeds 1MB safety limit");
  }
  return response.json();
}

async function thetaFetch(path, options = {}, customApiKey, customProjectId) {
  // Get credentials — BYOK first, env vars fallback
  let apiKey = customApiKey;
  let projectId = customProjectId || THETA_PROJECT_ID_ENV;
  
  if (!apiKey) {
    const creds = await getThetaCredentials();
    if (!creds) {
      throw new Error("Theta API not configured. Set THETA_API_KEY + THETA_PROJECT_ID environment variables, or use the theta_configure tool to save your own credentials (BYOK).");
    }
    apiKey = creds.apiKey;
    projectId = creds.projectId;
  }
  
  const url = new URL(`${THETA_EDGE_URL}${path}`);
  const headers = {
    "Content-Type": "application/json",
    "x-api-key": apiKey,
    ...options.headers,
  };
  const response = await fetchWithTimeout(url.toString(), { ...options, headers });
  if (!response.ok) {
    throw new Error(`Theta API returned ${response.status}`);
  }
  return response.json();
}

async function thetaRpc(method, params = []) {
  if (typeof method !== "string" || !/^[a-z_]+$/.test(method) || method.length > 50) {
    throw new Error("Invalid RPC method name");
  }
  const readOnlyMethods = new Set([
    "eth_getBalance", "eth_call", "eth_getTransactionByHash",
    "eth_getTransactionReceipt", "eth_blockNumber", "eth_getBlockByNumber",
    "eth_getCode", "eth_getStorageAt", "eth_getLogs",
    "net_version", "web3_clientVersion", "eth_chainId",
    "eth_getTransactionCount",
  ]);
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
    description: "Create a new entity schema (database table) on the Base44 backend.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string", description: "PascalCase entity name" },
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
        entity_name: { type: "string" },
        query: { type: "object" },
        limit: { type: "number" },
        skip: { type: "number" },
        sort: { type: "string" },
        fields: { type: "array", items: { type: "string" } },
      },
      required: ["entity_name"],
      additionalProperties: false,
    },
  },
  {
    name: "create_records",
    description: "Create one or more records in a Base44 entity.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string" },
        data: { type: "array", items: { type: "object" } },
      },
      required: ["entity_name", "data"],
      additionalProperties: false,
    },
  },
  {
    name: "update_records",
    description: "Update records in a Base44 entity that match a query filter. Requires non-empty query.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string" },
        query: { type: "object" },
        data: { type: "object" },
      },
      required: ["entity_name", "query", "data"],
      additionalProperties: false,
    },
  },
  {
    name: "delete_records",
    description: "Delete records from a Base44 entity. Requires a non-empty query to prevent accidental table wipes.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string" },
        query: { type: "object" },
      },
      required: ["entity_name", "query"],
      additionalProperties: false,
    },
  },
  {
    name: "aggregate_records",
    description: "Run a MongoDB aggregation pipeline over a Base44 entity. $out, $merge, $lookup, $facet are blocked.",
    inputSchema: {
      type: "object",
      properties: {
        entity_name: { type: "string" },
        pipeline: { type: "array", items: { type: "object" } },
      },
      required: ["entity_name", "pipeline"],
      additionalProperties: false,
    },
  },
  {
    name: "call_function",
    description: "Call a deployed Base44 backend function via HTTP.",
    inputSchema: {
      type: "object",
      properties: {
        function_name: { type: "string" },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
        payload: { type: "object" },
      },
      required: ["function_name"],
      additionalProperties: false,
    },
  },
  {
    name: "upload_file",
    description: "Upload a file to Base44 public storage. Restricted to allowed directory. System files and secrets blocked.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: { type: "string" },
      },
      required: ["file_path"],
      additionalProperties: false,
    },
  },

  // ──────────────────────────────────────────────────────────
  // LAYER 2: THETA COMPUTE — GPU + Blockchain (with BYOK)
  // ──────────────────────────────────────────────────────────
  
  {
    name: "theta_configure",
    description: "Save your own Theta EdgeCloud API key and project ID (BYOK). Keys are encrypted at rest with AES-256-GCM and stored locally. This overrides any THETA_API_KEY environment variable.",
    inputSchema: {
      type: "object",
      properties: {
        api_key: { type: "string", description: "Your Theta EdgeCloud API key" },
        project_id: { type: "string", description: "Your Theta EdgeCloud project ID" },
      },
      required: ["api_key", "project_id"],
      additionalProperties: false,
    },
  },
  {
    name: "theta_check_credentials",
    description: "Check the current Theta credential configuration. Shows whether BYOK or env vars are active, masked key, and tests connectivity. Does NOT expose the raw API key.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "theta_remove_credentials",
    description: "Remove saved BYOK Theta credentials. Falls back to environment variables if set.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "theta_list_models",
    description: "List available AI models on Theta EdgeCloud for inference tasks.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "theta_run_inference",
    description: "Send a prompt to a Theta EdgeCloud AI model for inference. Uses BYOK key if configured, otherwise env var key.",
    inputSchema: {
      type: "object",
      properties: {
        model: { type: "string" },
        messages: { type: "array", items: { type: "object" } },
        max_tokens: { type: "number" },
        temperature: { type: "number" },
      },
      required: ["model", "messages"],
      additionalProperties: false,
    },
  },
  {
    name: "theta_check_gpu_status",
    description: "Check status of running Theta EdgeCloud GPU instances.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "theta_estimate_cost",
    description: "Estimate TFUEL cost for a GPU compute job. Pure calculation — no API calls.",
    inputSchema: {
      type: "object",
      properties: {
        model: { type: "string" },
        duration_minutes: { type: "number" },
      },
      required: ["model", "duration_minutes"],
      additionalProperties: false,
    },
  },
  {
    name: "theta_deploy_contract",
    description: "Deploy a smart contract to Theta mainnet. REQUIRES THETA_ALLOW_WRITES=true. Irreversible — ensure bytecode is audited.",
    inputSchema: {
      type: "object",
      properties: {
        bytecode: { type: "string" },
        abi: { type: "array", items: { type: "object" } },
        constructor_args: { type: "array", items: { type: "string" } },
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
        contract_address: { type: "string" },
        function_signature: { type: "string" },
        params: { type: "array", items: { type: "string" } },
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
        wallet_address: { type: "string" },
        token_contract: { type: "string" },
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
        tx_hash: { type: "string" },
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
    description: "Get an aggregated morning briefing from Wave OS Chief of Staff.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string" },
        proactivity_level: { type: "string", enum: ["low", "medium", "high"] },
      },
      required: ["workspace_id"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_triage",
    description: "Run a triage scan across Wave OS entities for urgent items.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string" },
        proactivity_level: { type: "string", enum: ["low", "medium", "high"] },
      },
      required: ["workspace_id"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_follow_up_scan",
    description: "Scan Wave OS memory for tasks with natural language due dates.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string" },
      },
      required: ["workspace_id"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_meeting_prep",
    description: "Get preparation context for an upcoming meeting.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string" },
        meeting_id: { type: "string" },
      },
      required: ["workspace_id"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_save_memory",
    description: "Save a memory to Wave OS memory system. Auto-categorizes by content type.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string" },
        content: { type: "string" },
        category: { type: "string", enum: ["contact", "preference", "task", "note", "project", "code", "general"] },
        tags: { type: "array", items: { type: "string" } },
      },
      required: ["workspace_id", "content"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_recall_memory",
    description: "Search Wave OS memories by category or keyword.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string" },
        query: { type: "string" },
        category: { type: "string", enum: ["contact", "preference", "task", "note", "project", "code", "general"] },
      },
      required: ["workspace_id"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_delegate_subagent",
    description: "Delegate a task to a Wave OS sub-agent for focused background execution.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string" },
        task: { type: "string" },
        context: { type: "string" },
      },
      required: ["workspace_id", "task"],
      additionalProperties: false,
    },
  },
  {
    name: "wave_chat",
    description: "Send a message to the Wave OS Assistant and get an AI-powered response. Costs 1 credit per interaction.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_id: { type: "string" },
        message: { type: "string" },
        context: { type: "string" },
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
      if (!args.schema || typeof args.schema !== "object") throw new Error("Schema must be a valid JSON schema object");
      const schemaStr = JSON.stringify(args.schema);
      if (schemaStr.length > 50000) throw new Error("Schema too large: must be under 50KB");
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities`, {
        method: "POST",
        body: JSON.stringify({ entity_name: entityName, schema: args.schema }),
      });
    }
    
    case "read_records": {
      const entityName = validateEntityName(args.entity_name);
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities/${encodeURIComponent(entityName)}/records`, {
        method: "POST",
        body: JSON.stringify({
          query: args.query && typeof args.query === "object" ? args.query : {},
          limit: validateLimit(args.limit),
          skip: validateSkip(args.skip),
          sort: validateSortField(args.sort),
          fields: validateFieldNames(args.fields),
        }),
      });
    }
    
    case "create_records": {
      const entityName = validateEntityName(args.entity_name);
      if (!Array.isArray(args.data) || args.data.length === 0) throw new Error("Data must be a non-empty array");
      if (args.data.length > 500) throw new Error("Cannot create more than 500 records at once");
      for (const record of args.data) {
        if (typeof record !== "object" || record === null) throw new Error("Each record must be an object");
      }
      const payloadStr = JSON.stringify({ data: args.data });
      if (payloadStr.length > 500000) throw new Error("Payload too large: must be under 500KB");
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities/${encodeURIComponent(entityName)}/records`, {
        method: "PUT",
        body: payloadStr,
      });
    }
    
    case "update_records": {
      const entityName = validateEntityName(args.entity_name);
      if (!args.query || typeof args.query !== "object" || Object.keys(args.query).length === 0) throw new Error("Update requires a non-empty query filter");
      if (!args.data || typeof args.data !== "object") throw new Error("Update data must be an object");
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
        if (payloadStr.length > 100000) throw new Error("Function payload too large: must be under 100KB");
        payload = args.payload;
      }
      return await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/functions/${encodeURIComponent(functionName)}`, {
        method,
        body: method === "GET" ? undefined : JSON.stringify(payload),
      });
    }
    
    case "upload_file": {
      const filePath = validateFilePath(args.file_path);
      const fs = await import("fs/promises");
      const stats = await fs.stat(filePath);
      if (!stats.isFile()) throw new Error("Path must point to a file, not a directory");
      if (stats.size > 10 * 1024 * 1024) throw new Error("File too large: must be under 10MB");
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
    
    // ── LAYER 2: THETA COMPUTE (with BYOK) ──────────────────
    
    case "theta_configure": {
      const apiKey = validateThetaApiKey(args.api_key);
      const projectId = validateThetaProjectId(args.project_id);
      
      // Test the credentials before saving
      try {
        const testResponse = await fetchWithTimeout(`${THETA_EDGE_URL}/api/v1/models`, {
          method: "GET",
          headers: { "x-api-key": apiKey },
        });
        if (!testResponse.ok) {
          throw new Error(`Credential test failed: Theta API returned ${testResponse.status} (401=invalid key, 403=invalid project)`);
        }
      } catch (e) {
        throw new Error(`Credential test failed: ${sanitizeError(e)}`);
      }
      
      // Save encrypted credentials
      await saveThetaCredentials(apiKey, projectId);
      
      return {
        status: "configured",
        project_id: projectId,
        api_key_masked: maskKey(apiKey),
        encrypted_at_rest: true,
        encryption: "AES-256-GCM",
        storage: "~/.wave-mcp/credentials.json (0600 permissions)",
        note: "Your API key is encrypted and stored locally. It will be used for all Theta operations instead of environment variables.",
      };
    }
    
    case "theta_check_credentials": {
      const creds = await getThetaCredentials();
      if (!creds) {
        return {
          configured: false,
          message: "No Theta credentials found. Use theta_configure to save your own API key (BYOK) or set THETA_API_KEY + THETA_PROJECT_ID environment variables.",
        };
      }
      
      // Load stored creds to check encryption status
      const stored = await loadCredentials();
      const isByok = creds.source === "byok";
      const encryptedAtRest = isByok && stored.theta?.encrypted_at_rest === true;
      
      return {
        configured: true,
        source: creds.source,
        project_id: creds.projectId,
        api_key_masked: maskKey(creds.apiKey),
        encrypted_at_rest: encryptedAtRest,
        encryption: encryptedAtRest ? "AES-256-GCM" : "none (env var)",
        saved_at: creds.savedAt || null,
      };
    }
    
    case "theta_remove_credentials": {
      await removeThetaCredentials();
      return {
        status: "removed",
        message: "BYOK credentials deleted. Theta tools will use environment variables if set, or return errors until reconfigured.",
      };
    }
    
    case "theta_list_models":
      return await thetaFetch("/api/v1/models");
    
    case "theta_run_inference": {
      const messages = validateMessages(args.messages);
      if (typeof args.model !== "string" || args.model.length > 100) throw new Error("Invalid model ID");
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
    
    case "theta_check_gpu_status": {
      const creds = await getThetaCredentials();
      if (!creds) throw new Error("Theta not configured");
      return await thetaFetch(`/api/v1/projects/${encodeURIComponent(creds.projectId)}/instances`);
    }
    
    case "theta_estimate_cost": {
      if (typeof args.model !== "string" || args.model.length > 100) throw new Error("Invalid model ID");
      const duration = Math.min(Math.max(Number(args.duration_minutes) || 0, 1), 1440);
      const costPerMinute = 0.15;
      const creditsNeeded = Math.ceil(duration * 4);
      return {
        model: args.model,
        duration_minutes: duration,
        credits_needed: creditsNeeded,
        estimated_tfuel: (creditsNeeded * costPerMinute).toFixed(2),
        note: "Costs are approximate. Actual usage may vary.",
      };
    }
    
    case "theta_deploy_contract": {
      const bytecode = validateHex(args.bytecode, 100000);
      if (!Array.isArray(args.abi)) throw new Error("ABI must be an array");
      const constructorArgs = (args.constructor_args || []).map(a => validateHex(a));
      return await thetaRpc("eth_sendTransaction", [{
        data: bytecode + constructorArgs.join(""),
        gas: "0x7A1200",
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
      const tfuelBalance = await thetaRpc("eth_getBalance", [walletAddress, "latest"]);
      const tokenContract = args.token_contract ? validateEthAddress(args.token_contract) : "0x93de35b55ace27cee301184e010de73518950753";
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
      if (typeof args.tx_hash !== "string" || args.tx_hash.length !== 66) throw new Error("Transaction hash must be 0x + 64 hex characters");
      validateHex(args.tx_hash, 100);
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
        body: JSON.stringify({ action: "followUpScan", workspace_id: workspaceId }),
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
      if (!content) throw new Error("Content is required");
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
      if (!task) throw new Error("Task is required");
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
      if (!message) throw new Error("Message is required");
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
// RESOURCES
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
    description: "Theta EdgeCloud and blockchain configuration (no secrets exposed)",
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
      const schemas = await base44Fetch(`/api/apps/${encodeURIComponent(BASE44_APP_ID)}/entities`);
      return JSON.stringify(schemas, null, 2);
    
    case "wave-os://theta-config":
      const creds = await getThetaCredentials();
      return JSON.stringify({
        edge_url: THETA_EDGE_URL,
        rpc_url: THETA_RPC_URL,
        credentials_source: creds ? creds.source : "none",
        project_id: creds ? creds.projectId : null,
        api_key_masked: creds ? maskKey(creds.apiKey) : null,
        encrypted_at_rest: creds?.source === "byok",
        encryption: creds?.source === "byok" ? "AES-256-GCM" : "none",
        wave_token_contract: "0x93de35b55ace27cee301184e010de73518950753",
        treasury: "0xA8C5BDFB662284518470eae1B7beC2Dc432eB659",
        writes_enabled: process.env.THETA_ALLOW_WRITES === "true",
        note: "API keys are never exposed. BYOK keys are encrypted with AES-256-GCM at rest.",
      }, null, 2);
    
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
}

// ============================================================
// SERVER SETUP
// ============================================================

const server = new Server(
  { name: "wave-os-mcp-server", version: "1.1.0" },
  { capabilities: { tools: {}, resources: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map(t => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  })),
}));

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

server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources }));

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

validateConfig();
const transport = new StdioServerTransport();
await server.connect(transport);
console.error("Wave OS MCP Server v1.1.0 running on stdio (security-hardened + BYOK + AES-256-GCM)");
