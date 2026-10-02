# CMN-C1-708 — Unit tests: WebhookProvisionNode (main: parse -> SSRF -> create + S-4)

import json

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
import src.nodes.main_node as main_node
from src.nodes.main_node import WebhookProvisionNode

ALLOWED = ["https://ci.example.com/trigger"]
CFG = {
    "allowed_endpoints": ALLOWED,
    "allowed_event_flags": ["push_events", "merge_requests_events"],
    "gitlab_base_url": "https://gitlab.test",
    "timeout_seconds": 30,
}


class _FakeSecrets:
    def require(self, key):
        return f"mock-{key}"


class _FakeLLM:
    """Test-double for AzureOpenAIClient - same `complete(messages) -> dict` contract."""

    def __init__(self, content: str):
        self._content = content
        self.calls = 0

    def complete(self, messages):
        self.calls += 1
        return {"content": self._content}


class _RaisingLLM:
    def complete(self, messages):
        raise RuntimeError("simulated Azure OpenAI outage")


class _FakeService:
    """Stub GitLabWebhookService — no network."""

    def __init__(self, *a, **k):
        self.created = None

    def search_project(self, query):
        return [{"id": 42, "path_with_namespace": "group/project"}]

    def list_hooks(self, project_id):
        return []

    def create_hook(self, project_id, url, event_flags, secret_token):
        self.created = (project_id, url, event_flags, secret_token)
        return {"id": 777}


def _patch(monkeypatch, service_cls=_FakeService):
    monkeypatch.setattr(main_node, "current_secrets", lambda: _FakeSecrets())
    monkeypatch.setattr(main_node, "GitLabWebhookService", service_cls)


def _state(text):
    return {
        "sanitized_input": text,
        "agent_config": CFG,
        "caller_id": "tester",
    }


class TestWebhookProvisionNode:
    def setup_method(self):
        self.node = WebhookProvisionNode()

    def test_trust_level_is_internal(self):
        assert WebhookProvisionNode.required_trust_level == TrustLevel.INTERNAL

    def test_success_create(self, monkeypatch):
        _patch(monkeypatch)
        st = _state("add webhook to group/project calling https://ci.example.com/trigger on push")
        result = self.node.execute(st)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["hook_id"] == 777
        assert result["allowlist_ok"] is True
        assert result["duplicate"] is False
        assert "push_events" in result["event_flags"]
        # audit-safe: endpoint hash present, raw URL not in the returned dict values
        assert result["endpoint_hash"] and len(result["endpoint_hash"]) == 64

    def test_ssrf_block_for_unlisted_endpoint(self, monkeypatch):
        _patch(monkeypatch)
        st = _state("add webhook to group/project calling https://evil.example/steal on push")
        result = self.node.execute(st)
        assert result["status"] == AgentStatus.ERROR
        assert result["allowlist_ok"] is False
        assert "allowlist" in result["error_log"][0].lower()

    def test_ssrf_block_for_http_scheme(self, monkeypatch):
        _patch(monkeypatch)
        # http (not https) must be blocked even if host matches
        st = _state("add webhook to group/project calling http://ci.example.com/trigger on push")
        result = self.node.execute(st)
        assert result["status"] == AgentStatus.ERROR
        assert result["allowlist_ok"] is False

    def test_parse_fail_missing_events(self, monkeypatch):
        _patch(monkeypatch)
        st = _state("add webhook to group/project calling https://ci.example.com/trigger")
        result = self.node.execute(st)
        assert result["status"] == AgentStatus.ERROR
        assert "resolve" in result["error_log"][0].lower()

    def test_duplicate_hook_is_idempotent(self, monkeypatch):
        class _DupService(_FakeService):
            def list_hooks(self, project_id):
                return [{"id": 999, "url": "https://ci.example.com/trigger", "push_events": True}]

        _patch(monkeypatch, _DupService)
        st = _state("add webhook to group/project calling https://ci.example.com/trigger on push")
        result = self.node.execute(st)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["duplicate"] is True
        assert result["hook_id"] == 999

    def test_ambiguous_project_stops(self, monkeypatch):
        class _AmbigService(_FakeService):
            def search_project(self, query):
                return [
                    {"id": 1, "path_with_namespace": "group/project-a"},
                    {"id": 2, "path_with_namespace": "group/project-b"},
                ]

        _patch(monkeypatch, _AmbigService)
        st = _state("add webhook to group/project calling https://ci.example.com/trigger on push")
        result = self.node.execute(st)
        assert result["status"] == AgentStatus.ERROR
        assert "candidates" in result["error_log"][0].lower() or "resolve" in result["error_log"][0].lower()
        assert result.get("project_candidates")


class TestWebhookProvisionNodeLLMRefine:
    """Step 8e: optional LLM gap-fill over the deterministic InputParse core.

    The LLM only ever fills a field the deterministic resolver left blank; it
    never overrides a resolved value, never invents an event flag outside the
    allowed set, and never invents an endpoint outside the registered aliases.
    Any failure keeps the deterministic result - the pipeline never hard-fails
    over an LLM outage.
    """

    def test_llm_fills_missing_event_flags(self, monkeypatch):
        _patch(monkeypatch)
        # "delete_events" is not in CFG's allowed_event_flags - must be filtered out.
        llm = _FakeLLM(json.dumps({
            "project_path": None,
            "event_flags": ["push_events", "delete_events"],
            "endpoint_alias": None,
        }))
        node = WebhookProvisionNode(llm=llm)
        st = _state("add webhook to group/project calling https://ci.example.com/trigger")
        result = node.execute(st)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["event_flags"] == {"push_events": True}
        assert llm.calls == 1

    def test_llm_fills_missing_endpoint_by_alias(self, monkeypatch):
        _patch(monkeypatch)
        llm = _FakeLLM(json.dumps({
            "project_path": None,
            "event_flags": [],
            "endpoint_alias": "trigger",  # tail segment of https://ci.example.com/trigger
        }))
        node = WebhookProvisionNode(llm=llm)
        st = _state("add webhook to group/project for our automated integration endpoint on push")
        result = node.execute(st)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["hook_id"] == 777

    def test_llm_malformed_response_falls_back_to_deterministic(self, monkeypatch):
        _patch(monkeypatch)
        llm = _FakeLLM("not json at all")
        node = WebhookProvisionNode(llm=llm)
        st = _state("add webhook to group/project calling https://ci.example.com/trigger")
        result = node.execute(st)
        assert result["status"] == AgentStatus.ERROR
        assert "resolve" in result["error_log"][0].lower()

    def test_llm_raising_falls_back_to_deterministic(self, monkeypatch):
        _patch(monkeypatch)
        node = WebhookProvisionNode(llm=_RaisingLLM())
        st = _state("add webhook to group/project calling https://ci.example.com/trigger")
        result = node.execute(st)
        assert result["status"] == AgentStatus.ERROR
        assert "resolve" in result["error_log"][0].lower()

    def test_llm_never_called_when_nothing_missing(self, monkeypatch):
        _patch(monkeypatch)
        llm = _FakeLLM(json.dumps({"project_path": None, "event_flags": [], "endpoint_alias": None}))
        node = WebhookProvisionNode(llm=llm)
        st = _state("add webhook to group/project calling https://ci.example.com/trigger on push")
        result = node.execute(st)
        assert result["status"] == AgentStatus.SUCCESS
        assert llm.calls == 0

    def test_llm_never_called_on_empty_input(self, monkeypatch):
        _patch(monkeypatch)
        llm = _FakeLLM(json.dumps({"project_path": None, "event_flags": [], "endpoint_alias": None}))
        node = WebhookProvisionNode(llm=llm)
        result = node.execute(_state(""))
        assert result["status"] == AgentStatus.ERROR
        assert llm.calls == 0

    def test_no_llm_injected_and_no_secret_bound_falls_back(self, monkeypatch):
        """Real production shape: no llm= injected. InvocationContext.from_state()
        has no bound secrets provider (and this hand-built state lacks the
        lifecycle fields a real Graph.invoke() seeds) -> raises -> caught -> the
        deterministic result stands, no crash."""
        _patch(monkeypatch)
        st = _state("add webhook to group/project calling https://ci.example.com/trigger")
        result = WebhookProvisionNode().execute(st)
        assert result["status"] == AgentStatus.ERROR
        assert "resolve" in result["error_log"][0].lower()
