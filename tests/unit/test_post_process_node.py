# CMN-C1-708 — Unit tests: OutputFormatNode (post_process, S-3)

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.nodes.post_process_node import OutputFormatNode


class TestOutputFormatNode:
    def setup_method(self):
        self.node = OutputFormatNode()

    def test_trust_level_is_internal(self):
        assert OutputFormatNode.required_trust_level == TrustLevel.INTERNAL

    def test_builds_hash_only_response(self):
        state = {
            "project_id": 42,
            "hook_id": 777,
            "event_flags": {"push_events": True},
            "endpoint_hash": "a" * 64,
            "endpoint_alias": "ci",
            "duplicate": False,
            "confidence_flags": [],
        }
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        out = result["output"]
        assert out["hook_id"] == 777
        assert out["endpoint_hash"] == "a" * 64
        # raw URL must never appear in the output
        assert "endpoint_url" not in out

    def test_s3_gate_strips_raw_url(self):
        """S-3 defensive: any endpoint_url that slipped into output is stripped."""
        state = {"output": {"hook_id": 1, "endpoint_url": "https://secret/hook?token=x"}}
        self.node._extra_security_gate_output(state)
        assert "endpoint_url" not in state["output"]
