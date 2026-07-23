# AGENTS.md

## Cursor Cloud specific instructions

### What this is
Single product: **Wave OS MCP Server** (`wave-os-mcp-server`), a Model Context Protocol
server over **stdio** (not an HTTP service). All source lives in `src/index.ts`. Commands
are defined in `package.json` (`dev`, `build`, `start`). There is no test runner or lint
script configured.

### Running it
- Dev runner is `npm run dev` (`tsx src/index.ts`). `tsx` transpiles without type-checking,
  so it runs even though the strict `tsc` build currently fails (see caveat below).
- The process talks MCP over **stdio** and blocks waiting for a client. It is not meant to
  be run standalone in a terminal for interactive use — spawn it from an MCP client
  (`cursor-mcp-config.json` shows the client config shape).
- Startup requires `BASE44_APP_ID` and `BASE44_API_KEY` or it calls `process.exit(1)` with
  `FATAL: Missing required env vars`. For local smoke-testing that only exercises the MCP
  protocol and local-only tools, any non-empty dummy values work.

### Testing without live credentials
Most tools call external SaaS (Base44 API, Theta EdgeCloud/RPC) and need real credentials.
Two tools run purely locally and are safe for smoke tests: `theta_estimate_cost` (pure
calc) and `wave_routing_config` (action `check`/`set`). The three resources
(`wave-os://app-info`, `wave-os://theta-config`, `wave-os://architecture`) also read
locally. To drive the server end-to-end, spawn it with an MCP stdio client (the
`@modelcontextprotocol/sdk` client is already installed) and set dummy `BASE44_*` env vars.

### Known caveat: `npm run build` fails
`npm run build` (`tsc`) does **not** compile — `src/index.ts` is written in an untyped JS
style but `tsconfig.json` has `strict: true`, producing many `TS7006`/type errors. This is
pre-existing and unrelated to environment setup. Use `npm run dev` for development. Do not
"fix" this by loosening types unless the task explicitly asks for it. Because `build` fails,
`npm start` (which runs `dist/index.js`) will not work until the build is fixed.

### Credentials / secrets (only for full external testing)
Set as env vars when the task needs live Base44/Theta/Wave OS behavior:
`BASE44_APP_ID`, `BASE44_API_KEY` (required to boot), plus optional
`WAVE_OS_AUTH_TOKEN` + `WAVE_OS_WORKSPACE_ID` (credit-gated Theta), `THETA_API_KEY` +
`THETA_PROJECT_ID` (BYOK), `MCP_ENCRYPTION_KEY`, `COMPUTE_ROUTING`, `THETA_ALLOW_WRITES`.
BYOK/wave tokens are persisted AES-256-GCM-encrypted at `~/.wave-mcp/credentials.json`.
