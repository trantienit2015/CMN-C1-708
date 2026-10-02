# CMN-C1-708 GitLabWebhookAddAgent — Test Specification

## Test Strategy

- Test types: Unit (per node + service helpers), Integration (full graph compile + invoke), Proof-of-Boundary.
- External GitLab API and secrets are fully mocked/stubbed — no live calls in the suite.
- The deterministic resolution core makes every path testable without an LLM dependency.

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Where |
|-------|------|----------------|-------|
| TC-01 | State is a flat TypedDict (no Pydantic/dataclass; no credential fields) | Pass | `tests/proof_of_boundary/test_state_safety.py` |
| TC-02 | `SecurityViolationError` fires on embedded credential / 個人番号 input | Raised | `test_pre_process_node.py::test_s2_*` |
| TC-03 | No JWT/API keys in `src/` | `gate-credential-scan` PASS | CI |
| TC-04 | Secrets accessed via `ctx.secrets.require()` (never state/os.environ) | Pass | `main_node` + integration (`bound_secrets`) |
| TC-04b | Optional Azure OpenAI secrets (`AZURE_OPENAI_API_KEY`/`_ENDPOINT`/`_DEPLOYMENT`) resolved via `InvocationContext.from_state(state).secrets.require()`, built fresh per invocation, never cached on the node | Pass | `test_main_node.py::TestWebhookProvisionNodeLLMRefine` (D-13–D-19) |
| TC-05 | `emit_trace_event()` called inside `execute()` of every node | Pass | all node tests / integration |
| TC-06 | `_extra_security_gate_input()` domain gate present + rejects | Pass | `test_pre_process_node.py` |
| TC-07 | `_extra_security_gate_output()` strips raw URL | Pass | `test_post_process_node.py::test_s3_gate_strips_raw_url` |
| TC-08 | Every `FunctionNode` declares `required_trust_level` (INTERNAL) | Pass | node `test_trust_level_is_internal` + `gate-trust-level-check` |

## Domain Test Cases

| ID | Node | Scenario | Expected |
|----|------|----------|----------|
| D-01 | InputValidate | valid NL request | SUCCESS + `sanitized_input` |
| D-02 | InputValidate | empty input | ERROR |
| D-03 | InputValidate | embedded `glpat-` / JWT / My Number | `SecurityViolationError` |
| D-04 | WebhookProvision | valid intent, endpoint on allowlist | SUCCESS, `hook_id`, `endpoint_hash`, `allowlist_ok=True` |
| D-05 | WebhookProvision | endpoint NOT on allowlist | ERROR, `allowlist_ok=False`, no create |
| D-06 | WebhookProvision | http:// scheme (not https) | ERROR (SSRF block) |
| D-07 | WebhookProvision | missing event flags | ERROR (no guess) |
| D-08 | WebhookProvision | duplicate hook (same URL+events) | SUCCESS, `duplicate=True`, existing hook id |
| D-09 | WebhookProvision | ambiguous project | ERROR + `project_candidates[]` |
| D-10 | OutputFormat | build response | hash-only, no `endpoint_url` |
| D-11 | service | `resolve_event_flags` never emits disallowed flag | dropped |
| D-12 | service | `is_endpoint_allowed` exact/prefix/https/empty | correct verdicts |
| D-13 | WebhookProvision | LLM fills missing event flags from NL text | SUCCESS; invented flag outside `allowed_event_flags` filtered out |
| D-14 | WebhookProvision | LLM fills missing endpoint by registered alias | SUCCESS; endpoint still passes `is_endpoint_allowed()` |
| D-15 | WebhookProvision | LLM response malformed / not JSON | falls back to deterministic result (same as D-07) |
| D-16 | WebhookProvision | LLM call raises (simulated API error) | falls back to deterministic result, never propagates |
| D-17 | WebhookProvision | deterministic parse already complete | LLM never invoked (`llm.calls == 0`) |
| D-18 | WebhookProvision | empty input | LLM never invoked, ERROR (no guess) |
| D-19 | WebhookProvision | no `llm=` injected, no Azure secret bound | falls back to deterministic result, no crash (real production shape) |

## Integration

| ID | Scenario | Expected |
|----|----------|----------|
| I-01 | full graph invoke, endpoint on allowlist | SUCCESS, hook created, backbone node_history complete |
| I-02 | full graph invoke, endpoint off allowlist | ERROR, no hook, SSRF blocked before API |

## Proof-of-Boundary (Mandatory)

| PB-ID | Test | File |
|-------|------|------|
| PB-2/5 | State safety (primitives only, no credential fields) | `test_state_safety.py` |
| PB-4 | Import isolation (no Level 0 import) | `test_import_isolation.py` |
| PB-6 | Invoke execution order S-1→node_start→S-2→execute→S-3→node_complete (per node) | `test_pb_invoke_order.py` |

## 1. Deployment path tests

### TC-DEP-01 Marketplace entry point identity — `tests/unit/test_cli_entry_point.py`

| Case | Expected |
|---|---|
| Identity is concrete | `agent_name` / `namespace` are non-empty and not the runner default |
| Identity matches the HTTP entry point | the values equal what `src/api/server.py` passes to `secrets_factory`; where that entry point provisions no secrets, they equal the manifest `namespace` and the lower-cased template id |
| The runner call uses the constants | `run_agent_marketplace` is called with the module constants, not inline literals |

### TC-DEP-02 Standalone entry point boundary — `tests/proof_of_boundary/test_server_llm_injection.py`

| Case | Expected |
|---|---|
| Boots with no credential provisioned | the module imports and the app/agent objects are constructed |
| External bearer never reaches the internal level | resolves to the verified-external level |
| Staging runner credential reaches the internal level | resolves to the internal level |
| Wrong or missing bearer while auth is enabled | rejected with 401 |
