# Wave OS MCP Server

> Three layers, one MCP server. Base44 handles your data, Theta handles your compute, and Wave OS handles your intelligence — all accessible from any AI coding assistant via the Model Context Protocol.

Built by **xBuildy** for the [Base44 Dev Build-Off](https://backendcompetition.base44.app/) — July 2026.

## Architecture

```
Cursor / Claude Code / Any MCP Client
        │
        ▼
┌─────────────────────────────────────────┐
│         Wave OS MCP Server              │
│                                         │
│  Layer 1: Base44 Backend (Data)        │
│  ├─ Entity CRUD (create, read, update)  │
│  ├─ Aggregation pipelines               │
│  ├─ Backend function calls              │
│  └─ File uploads                        │
│                                         │
│  Layer 2: Theta Compute (GPU + Chain)   │
│  ├─ AI model inference                  │
│  ├─ GPU instance management             │
│  ├─ Smart contract deployment           │
│  ├─ Contract reads (view functions)     │
│  ├─ Wallet balance queries              │
│  └─ Transaction lookups                 │
│                                         │
│  Layer 3: Wave OS Intelligence          │
│  ├─ Morning briefing (Chief of Staff)   │
│  ├─ Triage scanning                     │
│  ├─ Follow-up tracking                  │
│  ├─ Meeting prep                        │
│  ├─ Memory save/recall                  │
│  ├─ Sub-agent delegation                │
│  └─ Wave Assistant chat                 │
└─────────────────────────────────────────┘
        │              │              │
        ▼              ▼              ▼
   Base44 API    Theta EdgeCloud   Theta RPC
   (database,    (GPU compute,     (blockchain,
    functions,    AI inference)     smart contracts)
    auth, files)
```

## Quick Start

### 1. Install dependencies

```bash
cd wave-mcp-server
npm install
```

### 2. Set environment variables

```bash
export BASE44_APP_ID="your_app_id"
export BASE44_API_KEY="your_api_key"
export THETA_API_KEY="your_theta_api_key"
export THETA_PROJECT_ID="your_theta_project_id"
```

### 3. Build

```bash
npm run build
```

### 4. Configure in Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "wave-os": {
      "command": "node",
      "args": ["/path/to/wave-mcp-server/dist/index.js"],
      "env": {
        "BASE44_APP_ID": "your_app_id",
        "BASE44_API_KEY": "your_api_key",
        "THETA_API_KEY": "your_theta_api_key",
        "THETA_PROJECT_ID": "your_theta_project_id"
      }
    }
  }
}
```

### 5. Run in Cursor

Restart Cursor, open a new chat, and the Wave OS tools will be available to the AI assistant.

## Available Tools (21 total)

### Layer 1: Base44 Backend (9 tools)
| Tool | Description |
|------|-------------|
| `list_entities` | List all entity schemas |
| `create_entity` | Create a new entity schema |
| `read_records` | Read/filter/sort/paginate records |
| `create_records` | Create one or more records |
| `update_records` | Update records matching a filter |
| `delete_records` | Delete records matching a filter |
| `aggregate_records` | Run MongoDB aggregation pipelines |
| `call_function` | Call any deployed backend function |
| `upload_file` | Upload a file to public storage |

### Layer 2: Theta Compute (8 tools)
| Tool | Description |
|------|-------------|
| `theta_list_models` | List available AI models |
| `theta_run_inference` | Run AI inference on Theta EdgeCloud |
| `theta_check_gpu_status` | Check running GPU instances |
| `theta_estimate_cost` | Estimate TFUEL cost for a job |
| `theta_deploy_contract` | Deploy a smart contract to Theta mainnet |
| `theta_read_contract` | Call a view function on a deployed contract |
| `theta_get_balance` | Get wallet TFUEL and WAVE token balances |
| `theta_get_transaction` | Fetch transaction details by hash |

### Layer 3: Wave OS Intelligence (8 tools)
| Tool | Description |
|------|-------------|
| `wave_morning_briefing` | Get aggregated daily briefing |
| `wave_triage` | Scan for urgent items across all entities |
| `wave_follow_up_scan` | Check overdue/due/upcoming follow-ups |
| `wave_meeting_prep` | Get preparation context for a meeting |
| `wave_save_memory` | Save a memory (auto-categorized) |
| `wave_recall_memory` | Search memories by keyword/category |
| `wave_delegate_subagent` | Delegate a task to a sub-agent |
| `wave_chat` | Chat with Wave OS AI Assistant |

## Demo Flows

### Flow 1: Full-Stack Build
```
You: "Create a Customer entity on my Base44 app"
AI: [calls create_entity] → Entity created with fields: name, email, status

You: "Add 5 sample customers"
AI: [calls create_records] → 5 records inserted

You: "Run sentiment analysis on these customers"
AI: [calls call_function to deploy sentiment function]
    [calls theta_run_inference to analyze each customer]
    [calls update_records to store sentiment scores]

You: "Show me the results"
AI: [calls read_records with fields projection] → Returns enriched data
```

### Flow 2: Intelligence Layer
```
You: "What needs my attention today?"
AI: [calls wave_triage] → Returns: 2 calendar conflicts, 1 credit warning, 3 overdue tasks

You: "Save a note that Customer X is VIP"
AI: [calls wave_save_memory] → Memory saved with category "contact"

You: "Delegate a follow-up task to a sub-agent for Customer X"
AI: [calls wave_delegate_subagent] → Sub-agent spawned, task assigned
```

### Flow 3: Blockchain + Data
```
You: "Check the treasury wallet balance"
AI: [calls theta_get_balance] → Returns TFUEL and WAVE balances

You: "How many token holders do we have?"
AI: [calls read_records on TokenHolder entity] → Returns holder list

You: "Deploy a new TNT20 token contract"
AI: [calls theta_deploy_contract] → Contract deployed to mainnet
    [calls create_records to log the deployment]
```

## Competition Pitch

> Three layers, one MCP server. Base44 handles your data, Theta handles your compute, and Wave OS agent orchestration handles your intelligence. Your AI coding assistant can create an entity, deploy a function, provision a GPU, run inference, delegate a task to a sub-agent, get a morning briefing, and save a memory — all from a single prompt in Cursor.

## License

MIT © xBuildy
