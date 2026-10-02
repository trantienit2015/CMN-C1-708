# CMN-C1-708 — Integration test: full graph compile() + invoke()

import src.nodes.main_node as main_node
from framework.schemas.invocation_context import InvocationContext
from framework.secrets.context import bound_secrets
from shared.secrets.inmemory_provider import InMemoryProvider
from src.graph.graph import Graph

ALLOWED = ["https://ci.example.com/trigger"]
CONFIG = {
    "max_retry": 3,
    "timeout_seconds": 30,
    "allowed_endpoints": ALLOWED,
    "allowed_event_flags": ["push_events", "merge_requests_events"],
    "gitlab_base_url": "https://gitlab.test",
}


class _FakeService:
    def __init__(self, *a, **k):
        pass

    def search_project(self, query):
        return [{"id": 42, "path_with_namespace": "group/project"}]

    def list_hooks(self, project_id):
        return []

    def create_hook(self, project_id, url, event_flags, secret_token):
        return {"id": 777}


def _provider():
    return InMemoryProvider(
        {"gitlab_api_token": "mock-token", "webhook_secret_token": "mock-secret"}
    )


def _build():
    agent = Graph(config=CONFIG)
    agent.compile()
    return agent


class TestGraphIntegration:
    def test_full_invoke_success(self, monkeypatch):
        monkeypatch.setattr(main_node, "GitLabWebhookService", _FakeService)
        agent = _build()
        ctx = InvocationContext.for_internal(caller_id="bootstrap")
        with bound_secrets(_provider()):
            result = agent.invoke(
                "add webhook to group/project calling https://ci.example.com/trigger on push",
                ctx=ctx,
            )
        assert result["status"] in ("success", "SUCCESS")
        out = result["output"]
        assert out["hook_id"] == 777
        assert "push_events" in out["event_flags"]
        assert len(out["endpoint_hash"]) == 64
        assert "endpoint_url" not in out
        # backbone ran: initialize + pre/main/post + finalize
        assert set(result["node_history"]) >= {
            "InitializeNode",
            "InputValidateNode",
            "WebhookProvisionNode",
            "OutputFormatNode",
            "FinalizeNode",
        }

    def test_full_invoke_ssrf_blocked(self, monkeypatch):
        monkeypatch.setattr(main_node, "GitLabWebhookService", _FakeService)
        agent = _build()
        ctx = InvocationContext.for_internal(caller_id="bootstrap")
        with bound_secrets(_provider()):
            result = agent.invoke(
                "add webhook to group/project calling https://evil.example/steal on push",
                ctx=ctx,
            )
        assert result["status"] in ("error", "ERROR")
        # no hook created; endpoint hard-blocked before the API call. get_output()
        # nulls output on any non-success status (SDK 1.0.3 fail-closed conformance) -
        # no pre-gate payload should ever leak through on an error path.
        assert result.get("output") is None
