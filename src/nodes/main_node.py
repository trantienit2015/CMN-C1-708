"""AgentCore Platform v1.0

WebhookProvisionNode - main slot. Realizes Steps 2-4 of the workflow:

  Step 2 InputParse            - resolve project + event flags + endpoint (deterministic
                                 core, always valid on its own; an optional LLM hook may
                                 additionally fill a gap the deterministic core left blank
                                 - never overrides a deterministic match, never invents an
                                 event flag or endpoint outside the configured sets)
  Step 3 EndpointWhitelistCheck - deterministic SSRF hard-block (https-pinned allowlist)
                                 BEFORE any HTTP call - not relaxed by the LLM hook
  Step 4 WebhookCreateAPI      - POST /projects/{id}/hooks via the service; secrets via
                                 ctx.secrets.require(); duplicate-hook idempotency; S-4
                                 audit with endpoint SHA-256 hash (never the raw URL)

Config (allowed_endpoints, allowed_event_flags, gitlab base_url, timeout) is read from
the parent config via config["configurable"], never from State.
"""

import re
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import current_secrets
from shared.services.llm.azure_openai_client import AzureOpenAIClient
from shared.utils.audit_logger import emit_trace_event
from shared.utils.llm_json import extract_json_object

from src.services.service import (
    GitLabWebhookService,
    hash_endpoint,
    is_endpoint_allowed,
    resolve_event_flags,
)

# Deterministic extractors for the parse step.
_URL_RE = re.compile(r"https?://[^\s\"'>)]+")
# GitLab project path: group/subgroup/name (2+ segments of path-safe chars).
_PROJECT_PATH_RE = re.compile(r"\b([A-Za-z0-9][\w.-]*(?:/[A-Za-z0-9][\w.-]*)+)\b")

_REFINE_SYSTEM_PROMPT = (
    "You resolve a natural-language GitLab webhook request into three fields. "
    "Given the request text, the allowed event flags, and the registered endpoint "
    "aliases, respond with a single JSON object only, no prose, no markdown fences: "
    '{"project_path": string|null, "event_flags": [string, ...], "endpoint_alias": '
    "string|null}. event_flags MUST be a subset of the given allowed list - never "
    "invent a flag outside it. endpoint_alias MUST be exactly one of the given "
    "aliases, or null if none plausibly matches - never invent one. project_path is "
    "your best-guess GitLab project reference (group/project path or name) taken "
    "from the text, or null if none is mentioned."
)


def _hook_id(hook: dict[str, Any]) -> int:
    """Return the hook identifier, refusing a response that carries none."""
    raw = hook.get("id")
    if raw is None:
        raise ValueError("webhook response carries no id")
    return int(raw)


class WebhookProvisionNode(FunctionNode):
    """Resolve intent, enforce the SSRF allowlist, then create the webhook."""

    # S-1 - privileged infrastructure write.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def __init__(self, llm: Any | None = None) -> None:
        super().__init__()
        # `llm` is a test-double seam only - register_nodes() never passes one in
        # production. The real client is built fresh per invocation in
        # _llm_refine() from ctx.secrets (all three Azure values are declared
        # secrets, none of it in config/config.yaml), never cached on self: node
        # instances are constructed once in register_nodes() (registry LRU cache,
        # shared across every invocation) before any request's secrets are
        # provisioned, and caching one caller's client would leave it visible to
        # the next caller.
        self._llm = llm

    def _config(self, state: dict[str, Any]) -> dict[str, Any]:
        """Return the agent runtime config (allowlist, event flags, gitlab base)."""
        return dict(state.get("agent_config", {}) or {})

    def _resolve(self, text: str, cfg: dict[str, Any]) -> dict[str, Any]:
        """Deterministic three-dimension resolution from the NL text.

        Returns {endpoint_url, endpoint_alias, event_flags, project_path,
        project_candidates, confidence_flags}. An optional LLM hook (cfg["llm"])
        may be wired later to disambiguate aliases; the deterministic core here
        never invents event flags (validated against the allowed set).
        """
        allowed_flags = list(cfg.get("allowed_event_flags", []))
        endpoints = list(cfg.get("allowed_endpoints", []))

        url_match = _URL_RE.search(text)
        endpoint_url = url_match.group(0) if url_match else ""
        endpoint_alias = ""
        confidence: list[str] = []

        # Alias resolution: if no literal URL, try to match a registered alias
        # token appearing in the text against the tail segment of an allowlist entry.
        if not endpoint_url and endpoints:
            for entry in endpoints:
                alias = entry.rstrip("/").rsplit("/", 1)[-1].lower()
                if alias and alias in text.lower():
                    endpoint_url = entry
                    endpoint_alias = alias
                    confidence.append("endpoint_resolved_by_alias")
                    break

        event_flags = resolve_event_flags(text, allowed_flags)
        if not event_flags:
            confidence.append("no_event_flags_resolved")

        pm = _PROJECT_PATH_RE.search(text)
        # Avoid matching the endpoint URL host/path as a project path.
        project_path = ""
        if pm and (not endpoint_url or pm.group(1) not in endpoint_url):
            project_path = pm.group(1)

        return {
            "endpoint_url": endpoint_url,
            "endpoint_alias": endpoint_alias,
            "event_flags": event_flags,
            "project_path": project_path,
            "confidence_flags": confidence,
        }

    def _llm_refine(
        self, text: str, cfg: dict[str, Any], parsed: dict[str, Any], state: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Optional LLM disambiguation for whatever the deterministic resolver left
        blank. Only ever supplies a missing field - never overrides an
        already-resolved deterministic value, and never relaxes the SSRF allowlist
        (any endpoint it resolves still passes through is_endpoint_allowed()
        afterward, same as a deterministic match). Any failure (nothing missing, no
        input, missing secret, API error, malformed/wrong-shape response) silently
        keeps the deterministic result - never raises.
        """
        if parsed["project_path"] and parsed["event_flags"] and parsed["endpoint_url"]:
            return None  # nothing missing - do not call the LLM at all
        if not text.strip():
            return None  # no input to reason over

        allowed_flags = list(cfg.get("allowed_event_flags", []))
        endpoints = list(cfg.get("allowed_endpoints", []))
        aliases = {e.rstrip("/").rsplit("/", 1)[-1].lower(): e for e in endpoints if e}
        if not allowed_flags and not aliases:
            return None  # nothing in the closed vocabulary to resolve against

        try:
            llm = self._llm
            if llm is None:
                ctx = InvocationContext.from_state(state)
                llm = AzureOpenAIClient(
                    {
                        "api_key": ctx.secrets.require("AZURE_OPENAI_API_KEY"),
                        "azure_endpoint": ctx.secrets.require("AZURE_OPENAI_ENDPOINT"),
                        "azure_deployment": ctx.secrets.require("AZURE_OPENAI_DEPLOYMENT"),
                    }
                )
            user_prompt = (
                f"Request: {text}\n"
                f"Allowed event flags: {sorted(allowed_flags)}\n"
                f"Registered endpoint aliases: {sorted(aliases)}"
            )
            response = llm.complete(
                [
                    {"role": "system", "content": _REFINE_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ]
            )
            raw = extract_json_object(response.get("content", ""))
            if not isinstance(raw, dict):
                return None

            refined: dict[str, Any] = {}

            candidate_path = raw.get("project_path")
            if not parsed["project_path"] and isinstance(candidate_path, str) and candidate_path.strip():
                refined["project_path"] = candidate_path.strip()

            candidate_flags = raw.get("event_flags")
            if not parsed["event_flags"] and isinstance(candidate_flags, list):
                valid = {f: True for f in candidate_flags if isinstance(f, str) and f in allowed_flags}
                if valid:
                    refined["event_flags"] = valid

            candidate_alias = raw.get("endpoint_alias")
            if not parsed["endpoint_url"] and isinstance(candidate_alias, str) and candidate_alias.lower() in aliases:
                refined["endpoint_url"] = aliases[candidate_alias.lower()]
                refined["endpoint_alias"] = candidate_alias.lower()

            return refined or None
        except Exception:
            return None

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Working on the request...",
            metadata={"step": "main"},
        )
        text = state.get("sanitized_input", state.get("user_input", "")) or ""
        cfg = self._config(state)

        # -- Step 2 - InputParse ----------------------------------------------
        parsed = self._resolve(text, cfg)
        refined = self._llm_refine(text, cfg, parsed, state)
        if refined:
            for key in ("project_path", "event_flags", "endpoint_url", "endpoint_alias"):
                if key in refined:
                    parsed[key] = refined[key]
            parsed["confidence_flags"] = list(parsed["confidence_flags"]) + [
                f"llm_refined_{k}" for k in ("project_path", "event_flags", "endpoint_url") if k in refined
            ]
        emit_trace_event(
            "webhook_parse",
            {
                "has_endpoint": bool(parsed["endpoint_url"]),
                "event_flags": sorted(parsed["event_flags"].keys()),
                "project_path": parsed["project_path"],
                "llm_refined": bool(refined),
            },
            state,
        )

        if not parsed["endpoint_url"] or not parsed["event_flags"] or not parsed["project_path"]:
            return {
                "endpoint_alias": parsed["endpoint_alias"],
                "event_flags": parsed["event_flags"],
                "confidence_flags": parsed["confidence_flags"],
                "status": AgentStatus.ERROR,
                "error_log": [
                    "WebhookProvisionNode: could not resolve required fields "
                    f"(project={bool(parsed['project_path'])}, "
                    f"endpoint={bool(parsed['endpoint_url'])}, "
                    f"events={bool(parsed['event_flags'])}) - no guess made"
                ],
            }

        # -- Step 3 - EndpointWhitelistCheck (SSRF hard-block) ----------------
        allowed = is_endpoint_allowed(parsed["endpoint_url"], list(cfg.get("allowed_endpoints", [])))
        endpoint_hash = hash_endpoint(parsed["endpoint_url"])
        emit_trace_event(
            "ssrf_allowlist_check",
            {"endpoint_hash": endpoint_hash, "allowed": allowed},
            state,
        )
        if not allowed:
            return {
                "allowlist_ok": False,
                "endpoint_hash": endpoint_hash,
                "endpoint_alias": parsed["endpoint_alias"],
                "event_flags": parsed["event_flags"],
                "status": AgentStatus.ERROR,
                "error_log": [
                    "WebhookProvisionNode: endpoint not on SSRF allowlist - hard blocked "
                    f"(endpoint_hash={endpoint_hash})"
                ],
            }

        # -- Step 4 - WebhookCreateAPI (+ S-4 audit) --------------------------
        secrets = current_secrets()
        api_token = secrets.require("gitlab_api_token")
        webhook_secret = secrets.require("webhook_secret_token")

        # Fail closed on an unset base URL. There is no sensible default: a
        # placeholder would aim the webhook creation at the wrong instance, and an
        # empty string only produces an unreadable transport error further down.
        base_url = cfg.get("gitlab_base_url")
        if not base_url:
            emit_trace_event(
                "webhook_config_error",
                {"correlation_id": state.get("correlation_id"), "reason": "gitlab_base_url_unset"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [
                    "WebhookCreate: gitlab_base_url is not configured "
                    "(supply it in this deployment's agent configuration)"
                ],
            }
        timeout = int(cfg.get("timeout_seconds", 30))
        svc = GitLabWebhookService(base_url=base_url, api_token=api_token, timeout=timeout)

        # Resolve project path -> id (deterministic post-check; ambiguous -> stop, no guess).
        candidates = svc.search_project(parsed["project_path"])
        exact = [c for c in candidates if c.get("path_with_namespace") == parsed["project_path"]]
        if len(exact) != 1:
            emit_trace_event(
                "project_resolution_ambiguous",
                {"query": parsed["project_path"], "candidate_count": len(candidates)},
                state,
            )
            return {
                "project_candidates": candidates,
                "endpoint_hash": endpoint_hash,
                "event_flags": parsed["event_flags"],
                "status": AgentStatus.ERROR,
                "error_log": [
                    "WebhookProvisionNode: project could not be uniquely resolved "
                    f"('{parsed['project_path']}' -> {len(candidates)} candidates) - no guess made"
                ],
            }
        project_id = int(exact[0]["id"])

        # Duplicate-hook idempotency: same URL + same event set already present -> no-op.
        existing = svc.list_hooks(project_id)
        for hook in existing:
            same_url = hook.get("url") == parsed["endpoint_url"]
            same_events = all(hook.get(flag) for flag in parsed["event_flags"])
            if same_url and same_events:
                emit_trace_event(
                    "webhook_create",
                    {
                        "requester": state.get("caller_id", ""),
                        "project_id": project_id,
                        "event_flags": sorted(parsed["event_flags"].keys()),
                        "endpoint_hash": endpoint_hash,
                        "hook_id": hook.get("id"),
                        "duplicate": True,
                    },
                    state,
                )
                return {
                    "project_id": project_id,
                    "allowlist_ok": True,
                    "hook_id": _hook_id(hook),
                    "endpoint_hash": endpoint_hash,
                    "endpoint_alias": parsed["endpoint_alias"],
                    "event_flags": parsed["event_flags"],
                    "duplicate": True,
                    "confidence_flags": parsed["confidence_flags"],
                    "status": AgentStatus.SUCCESS,
                }

        created = svc.create_hook(project_id, parsed["endpoint_url"], parsed["event_flags"], webhook_secret)
        hook_id = _hook_id(created)
        emit_trace_event(
            "webhook_create",
            {
                "requester": state.get("caller_id", ""),
                "project_id": project_id,
                "event_flags": sorted(parsed["event_flags"].keys()),
                "endpoint_hash": endpoint_hash,
                "hook_id": hook_id,
                "duplicate": False,
            },
            state,
        )

        return {
            "project_id": project_id,
            "allowlist_ok": True,
            "hook_id": hook_id,
            "endpoint_hash": endpoint_hash,
            "endpoint_alias": parsed["endpoint_alias"],
            "event_flags": parsed["event_flags"],
            "duplicate": False,
            "confidence_flags": parsed["confidence_flags"],
            "status": AgentStatus.SUCCESS,
        }
