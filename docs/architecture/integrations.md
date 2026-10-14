# Integrations: MCP, A2A and agent identity

The platform is both a client of agents (it validates them) and a service
that agents and pipelines call (it gates them). Both directions use the same
protocols as the rest of the portfolio.

## Inbound

### MCP server (`/mcp/`)

Official `mcp` Python SDK (`MCPServer`, streamable HTTP, stateless, JSON
responses), mounted in the FastAPI app and run in its lifespan. DNS-rebinding
protection is on: the Host header must be in `CRT_MCP_ALLOWED_HOSTS`.

| Tool | Input | Output | Action authorized |
|---|---|---|---|
| `list_suites` | none | `SuiteCatalogOut` | `redteam.suites:read` |
| `start_validation_run` | target_id, target_version, suite, seed?, environment | `RunOut` | `redteam.runs:start` |
| `get_run` | run_id | `RunOut` with per-category stats | `redteam.runs:read` |
| `evaluate_release_gate` | run_id | `DecisionOut` (outcome, rules, assessments, report digest) | `redteam.gate:evaluate` |
| `compare_versions` | target_id, baseline, candidate | `RegressionReport` | `redteam.runs:read` |

Every call authenticates the request's bearer token, authorizes through the
AccessController and records an `mcp.<tool>` audit event. There is no MCP
tool for approval: approving a release is human-only.

### A2A (`/.well-known/agent-card.json`, `POST /a2a`)

Agent Card fields: `protocolVersion` 0.3.0, `name`, `description`, `url`,
`preferredTransport` JSONRPC, `version`, `provider`, `capabilities`
(no streaming, no push), `defaultInputModes`, `defaultOutputModes`,
`securitySchemes.bearer` (HTTP bearer JWT), `security`, `skills`.

`message/send` selects a skill with a data part `{"skill": "<id>", ...}`:

| Skill | Returns |
|---|---|
| `start-validation-run` | Task `submitted`; poll `tasks/get` with the task id (run id) |
| `evaluate-release-gate` | Task `completed`, or `input-required` when a person must approve |
| `compare-versions` | Task `completed` with the regression report |

Run status maps to task state: queued `submitted`, running `working`,
completed `completed`, aborted `canceled`, failed `failed`. Errors use
JSON-RPC codes (-32700, -32600, -32601, -32602, -32001 task not found,
-32003 forbidden); missing or invalid credentials are HTTP 401.

### Agent identity

Tokens whose issuer is `CRT_FABRIC_ISSUER` are agent credentials. They are
not verified locally: the platform calls the fabric's `/v1/authorize`, which
verifies the credential (signature, epoch, revocation, delegation chain) and
evaluates the action. Agent scopes therefore look like
`redteam.runs:start`, `redteam.gate:evaluate`. If no fabric is configured,
agent tokens are refused, never allowed by default. Fabric outages fail
closed (HTTP 503).

## Outbound (targets)

| Kind | Transport | Request | Reply |
|---|---|---|---|
| `http` | `POST <endpoint>` JSON | `agent-invocation.request` | `agent-reply.response` |
| `mcp` | MCP `tools/call` of `mcp_tool` (default `run_task`) | invocation as arguments | structured content = agent reply, or text |
| `a2a` | JSON-RPC `message/send`, then `tasks/get` until terminal | task text part + context data part | Message or Task; tool calls in a data part |
| `reference` | in-process | invocation | calibration agent reply |

The invocation contains a session id, the task and context documents marked
`trust: external`. It never contains the probe's category, kind or the list
of protected values, so the target cannot special-case tests.

Outbound credentials per target: none, a bearer token from a named
environment variable (populated from the secret manager), or the platform's
own agent-identity-fabric credential obtained with the RFC 7523 jwt-bearer
grant using a projected service-account token.

### Independent traces

A target that executes a forbidden tool and leaves it out of its reply would
pass a self-reported check. When `trace_endpoint` is registered (for example
the MCP/A2A gateway's audit query API), the executor fetches
`GET <trace_endpoint>?session_id=<id>` and merges those tool calls before
judging. If the trace source is unavailable, the probe is an error, not a
pass.
