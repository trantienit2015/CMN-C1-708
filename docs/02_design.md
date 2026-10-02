# CMN-C1-708 GitLabWebhookAddAgent — Design Specification

## Position in AgentCore Architecture

- **Agent Class**: `GitLabWebhookAddGraph` (alias `Graph`), module `src.graph`
- **L1 Base**: `AgentBaseGraph` (L1 direct) — ToolCalling pattern (conceptual reference)
- **Category**: Cat 1 (single technical capability: NL → GitLab webhook creation), Industry CMN
- **Three-Layer Separation**:
  - State: flat TypedDict (`class State(AgentState)`); agent-specific fields all `NotRequired[...]`; primitives only (no Pydantic, no secrets, no `InvocationContext`)
  - Node: L1 inheritance (`FunctionNode`, override `execute(self, state) -> dict` only; `__call__` never overridden; no `_invoke_impl`)
  - Graph: composition (`register_nodes()` → `super()` + dict assignment of pre/main/post; `add_edges()` NOT overridden)

## Architecture Overview

Fixed 5-node backbone:

```
START → initialize → pre_process → main → {route} → post_process → finalize → END
```

The three domain slots realize the 5 logical workflow steps:

| Slot | Node class | Steps | Responsibility |
|---|---|---|---|
| `pre_process` | `InputValidateNode` | 1 | S-1 INTERNAL trust gate + S-2 deterministic credential/個人番号 reject; emit sanitized_input |
| `main` | `WebhookProvisionNode` | 2–4 | (2) InputParse deterministic resolution → (3) EndpointWhitelistCheck SSRF hard-block → (4) WebhookCreate + S-4 audit |
| `post_process` | `OutputFormatNode` | 5 | S-3 output gate; assemble confirmed-hook response (endpoint hash + alias, never raw URL) |

### Why 3 graph nodes (not 5)

Steps 1 and 5 are the framework S-1/S-2 and S-3 gates realized on the first/last nodes
via `_extra_security_gate_input()` / `_extra_security_gate_output()` — not separate graph
nodes. Step 3 `EndpointWhitelistCheck` is a deterministic in-node check (a `shared/tools`-style
helper `is_endpoint_allowed()`), not a standalone graph node. There is no separate
AuditLogNode — S-4 `emit_trace_event()` is inline in `WebhookProvisionNode.execute()`.
All IDEA functions are preserved across the 3 backbone nodes.

## State Schema (`src/schemas/state.py`)

`class State(AgentState)` adds (all `NotRequired`): `sanitized_input`, `project_id`,
`project_candidates`, `event_flags` (`{flag: True}`), `endpoint_url`, `endpoint_alias`,
`confidence_flags`, `allowlist_ok`, `hook_id`, `endpoint_hash` (SHA-256), `duplicate`,
`output`. **No credential-named fields** — the GitLab token and webhook secret are
accessed via `ctx.secrets.require()` and never stored in State (PB-2/PB-5).

`GitLabWebhookAddGraph._extra_initial_state()` injects a serializable `agent_config`
(SSRF allowlist, allowed event flags, GitLab base URL, timeout) into State so nodes read
runtime config without threading `InvocationContext` through the `(state) -> dict` interface.

### InputParse output schema (Step 2)

`{project_id*, event_flags{}*, endpoint_url*, endpoint_alias, project_candidates[], confidence_flags[]}`
(`*` required). Ambiguous project → `project_candidates[]` returned + stop (no guess). NL
events are validated against the fixed GitLab hook-event enum (`allowed_event_flags`) — invented
flags are never emitted.

> **Resolution core (deterministic) + optional LLM gap-fill.** The shipped resolver is
> deterministic (regex/keyword extraction of project path, event keywords → flags, endpoint
> URL/alias) and always produces a valid result on its own — either a resolved parse or a clean
> "no guess made" error. `WebhookProvisionNode._llm_refine()` (Azure OpenAI, `requires.secrets`
> in `config/agent.yaml`) additionally fills in **whatever the deterministic core left blank** —
> project reference, event flags, or endpoint alias — from the same NL text. It never overrides
> an already-resolved deterministic value, never invents an event flag outside
> `allowed_event_flags`, and never invents an endpoint outside the registered
> `allowed_endpoints` aliases. Any failure (no gap to fill, no secret provisioned, API error,
> malformed response) silently keeps the deterministic result, so the template stays fully
> testable and CI-green without the LLM configured (`AZURE_OPENAI_*` secrets are optional).

## Security Model (5-layer)

- **S-1** — every `FunctionNode` declares `required_trust_level` explicitly; the write path
  (all three nodes) is `TrustLevel.INTERNAL`. Agent default in `config/agent.yaml`.
- **S-2** — `InputValidateNode._extra_security_gate_input()` deterministically rejects embedded
  credentials (`glpat-`, JWT, Bearer, `sk-`, AKIA) and 個人番号 → `SecurityViolationError`
  (auto-reject). Project paths / endpoint aliases pass through.
- **SSRF gate** — `WebhookProvisionNode` calls `is_endpoint_allowed()` (https-pinned, exact or
  registered-prefix) **before any HTTP call**; not on allowlist → hard block + S-4 audit, no
  LLM override. Empty/unset allowlist → fail-fast (never default-allow). Conforms to the
  WebhookDispatch allowlist mandate (the developer guide).
- **S-3** — secrets via `ctx.secrets.require("gitlab_api_token" / "webhook_secret_token")`, and
  optionally `AZURE_OPENAI_API_KEY` / `AZURE_OPENAI_ENDPOINT` / `AZURE_OPENAI_DEPLOYMENT` for the
  LLM gap-fill step (all declared in `agent.yaml requires.secrets`; none in `config/config.yaml`);
  `OutputFormatNode._extra_security_gate_output()` strips any raw endpoint URL; response carries
  endpoint SHA-256 hash + alias only.
- **S-4** — `emit_trace_event()` in **every** node; the create step logs requester, project id,
  event flags, endpoint SHA-256 hash (never the raw URL), hook id.
- **S-5** — `gate-credential-scan` CI; no credentials in `src/`.

## Entry Point

`Graph().compile()` then `agent.invoke(user_input, ctx=ctx)` (never `.run()`).
`src/api/server.py` loads `config/agent.yaml`, constructs `Graph(config=...)`,
`provision_secrets(...)`, and invokes inside `bound_secrets(...)`.

## Error Propagation

Any node returning `status=AgentStatus.ERROR` routes to `finalize` (backbone `route()`).
Parse-fail, SSRF block, ambiguous project, and API error each produce a structured
`error_log` entry and terminate without creating a hook. Duplicate hook (same URL + events)
→ idempotent `SUCCESS` no-op returning the existing hook id.

## 1. Deployment entry points

The agent is reachable through two entry points, and both resolve their runtime inputs the same way.

| Entry point | File | Used by |
|---|---|---|
| Standalone HTTP | `src/api/server.py` | staging rehearsal, direct invocation |
| Marketplace one-shot Pod | `cli.py` | the platform runner (container `CMD`) — **see trust-ceiling limitation below** |

**Marketplace Pod trust ceiling.** The Marketplace one-shot Pod runtime
(AgentCore 1.0.3) stamps every invocation `caller_trust_level=VERIFIED_EXTERNAL`
unconditionally, with no elevation path. This template's `required_trust_level: INTERNAL`
(S-1 above, all three write-path nodes) therefore fails the S-1 gate on every Marketplace
invocation — the Pod starts but rejects all traffic (`status=error`, no usable output). This is a
confirmed platform contract gap, not a bug in this template; lowering `required_trust_level` to
force Marketplace compatibility widens a real write-authorization boundary and is out of scope for
a template-level change. **Marketplace registration is out of scope for this template pending a
platform-level resolution.** The Standalone HTTP entry point is unaffected — trust there is
established by upstream middleware / deployment credential (see "Caller authentication" below),
not hardcoded by the runtime — and remains this template's supported production path.

Both read runtime parameters from `config/config.yaml` — the manifest carries discovery metadata
only — and both scope secrets to the same location (`namespace=cmn`, `agent_name=cmn-c1-708`), so a
secret provisioned for one path resolves identically on the other.

**No LLM client is constructed at either entry point.** `WebhookProvisionNode` builds its own
`AzureOpenAIClient` lazily, per invocation, inside `_llm_refine()` — never at entry-point
startup, never cached on the node instance. A caller may still inject a test-double via the
node's `llm=` constructor parameter (production wiring in `register_nodes()` never passes one).

**Progress events.** Each pipeline stage emits a non-terminal progress event at its start, so a
caller sees the run advancing. Outside the Marketplace runtime the emitter resolves to a no-op, so
the same code is safe on every path. Terminal events belong to the platform runner and are never
emitted by this agent.

**Caller authentication at the standalone entry point.** A caller that no upstream middleware
vouched for stays anonymous unless it presents a deployment-level credential: the external bearer
token grants the verified-external level, and a separate staging-only runner credential is the only
way to reach the internal level. Trust established upstream is never changed.
