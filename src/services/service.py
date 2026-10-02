"""AgentCore Platform v1.0

GitLab webhook service layer for GitLabWebhookAddAgent.

This module is the factored-out "Tool" the Agent wraps:
  - `hash_endpoint()`        - SHA-256 of an endpoint URL for audit (never log the raw URL)
  - `resolve_event_flags()`  - deterministic NL-event-phrase -> GitLab hook event-flag set
  - `is_endpoint_allowed()`  - deterministic SSRF allowlist check (https-pinned, exact/prefix)
  - `GitLabWebhookService`   - raw GitLab Webhooks API caller (project search + list + create hooks)

It contains NO business routing and NO credentials. The GitLab token is passed in
by the caller node (resolved via ctx.secrets.require() at the node level), never read
from os.environ and never stored in state.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# The fixed, valid GitLab project-hook event flags this agent may set.
# Source of truth is config/agent.yaml allowed_event_flags; this constant is the
# hard superset used for NL keyword resolution and flag validation.
GITLAB_HOOK_EVENT_FLAGS: tuple[str, ...] = (
    "push_events",
    "merge_requests_events",
    "issues_events",
    "confidential_issues_events",
    "tag_push_events",
    "note_events",
    "confidential_note_events",
    "pipeline_events",
    "job_events",
    "wiki_page_events",
    "deployment_events",
    "releases_events",
)

# Deterministic NL keyword -> event flag mapping (lowercased phrase match).
_EVENT_KEYWORDS: dict[str, str] = {
    "push": "push_events",
    "merge request": "merge_requests_events",
    "merge-request": "merge_requests_events",
    "mr": "merge_requests_events",
    "pull request": "merge_requests_events",
    "issue": "issues_events",
    "tag": "tag_push_events",
    "note": "note_events",
    "comment": "note_events",
    "pipeline": "pipeline_events",
    "ci": "pipeline_events",
    "job": "job_events",
    "wiki": "wiki_page_events",
    "deploy": "deployment_events",
    "deployment": "deployment_events",
    "release": "releases_events",
}


def hash_endpoint(url: str) -> str:
    """Return the SHA-256 hex digest of an endpoint URL (audit-safe reference)."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def resolve_event_flags(text: str, allowed_flags: list[str] | None = None) -> dict[str, bool]:
    """Deterministically map an NL event description to a GitLab event-flag set.

    Only flags in `allowed_flags` (if provided) are emitted; invented flags are
    never produced. Returns a dict of {flag: True} for every matched, allowed flag.
    """
    allowed = set(allowed_flags) if allowed_flags else set(GITLAB_HOOK_EVENT_FLAGS)
    lowered = (text or "").lower()
    flags: dict[str, bool] = {}
    for phrase, flag in _EVENT_KEYWORDS.items():
        if phrase in lowered and flag in allowed:
            flags[flag] = True
    return flags


def is_endpoint_allowed(url: str, allowed_endpoints: list[str]) -> bool:
    """Deterministic SSRF allowlist check.

    An endpoint passes only if:
      - the scheme is exactly https, AND
      - the URL exactly equals, or begins with, a registered allowlist entry.

    An empty/unset allowlist yields False (fail-fast - never default-allow).
    """
    if not url or not allowed_endpoints:
        return False
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return False
    for entry in allowed_endpoints:
        if not entry:
            continue
        if url == entry or url.startswith(entry.rstrip("/") + "/") or url.startswith(entry):
            return True
    return False


class GitLabWebhookService:
    """Raw GitLab Webhooks API caller (stdlib urllib; no external dependency)."""

    def __init__(self, base_url: str, api_token: str, timeout: int = 30) -> None:
        self._base = base_url.rstrip("/")
        self._token = api_token
        self._timeout = timeout

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        url = f"{self._base}/api/v4{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 (trusted GitLab base)
            raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else None

    def search_project(self, query: str) -> list[dict[str, Any]]:
        """Search projects by name/path; return candidate {id, path_with_namespace}."""
        q = urllib.parse.quote(query, safe="")
        results = self._request("GET", f"/projects?search={q}&per_page=20") or []
        return [{"id": p.get("id"), "path_with_namespace": p.get("path_with_namespace")} for p in results]

    def list_hooks(self, project_id: int) -> list[dict[str, Any]]:
        """Return existing hooks for a project (for duplicate detection)."""
        return self._request("GET", f"/projects/{project_id}/hooks") or []

    def create_hook(self, project_id: int, url: str, event_flags: dict[str, bool], secret_token: str) -> dict[str, Any]:
        """Create a webhook. Returns the created hook object (contains hook id)."""
        body: dict[str, Any] = {"url": url, "token": secret_token, **event_flags}
        created = self._request("POST", f"/projects/{project_id}/hooks", body=body)
        return created if isinstance(created, dict) else {}
