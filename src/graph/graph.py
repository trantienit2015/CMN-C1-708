"""AgentCore Platform v1.0

GitLabWebhookAddAgent - Cat 1, ToolCalling pattern, L1-direct.

Fixed 5-node backbone (START -> initialize -> pre_process -> main -> post_process ->
finalize -> END). The three domain slots realize the 5 workflow steps:

  pre_process  = InputValidateNode    (Step 1 - S-1 INTERNAL + S-2 credential/PII reject)
  main         = WebhookProvisionNode (Steps 2-4 - parse -> SSRF allowlist -> create + S-4 audit)
  post_process = OutputFormatNode     (Step 5 - S-3 output gate, endpoint hash not raw URL)
"""

from typing import Any

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.schemas.agent_status import AgentStatus

from src.nodes.main_node import WebhookProvisionNode
from src.nodes.post_process_node import OutputFormatNode
from src.nodes.pre_process_node import InputValidateNode
from src.schemas.state import State


class GitLabWebhookAddGraph(AgentBaseGraph):
    """Governed NL -> GitLab webhook creation with an SSRF endpoint allowlist."""

    @property
    def name(self) -> str:
        return "GitLabWebhookAddAgent"

    @property
    def state_schema(self) -> type:
        return State

    def _extra_initial_state(self) -> dict[str, Any]:
        """Inject runtime domain config (SSRF allowlist, event flags, GitLab base)
        into State so nodes can read it without threading InvocationContext through
        the (state) -> dict node interface. Secrets are NEVER injected here - they
        are accessed via ctx.secrets.require() at node level only."""
        return {
            "agent_config": {
                "allowed_endpoints": self.config.get("allowed_endpoints", []),
                "allowed_event_flags": self.config.get("allowed_event_flags", []),
                # No default: the instance to talk to is deployment-specific, so an
                # unset value must surface as a configuration error rather than
                # resolve to some other deployment's host.
                "gitlab_base_url": self.config.get("gitlab_base_url"),
                "timeout_seconds": self.config.get("timeout_seconds", 30),
            }
        }

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode
        self._nodes["pre_process"] = InputValidateNode()
        self._nodes["main"] = WebhookProvisionNode()
        self._nodes["post_process"] = OutputFormatNode()

    def get_output(self, state: dict[str, Any]) -> dict[str, Any]:
        # SDK 1.0.3 conformance: a raising post_process security gate can leave the
        # pre-gate `output` in state while `status` is already "error" - never surface
        # that stale payload. Null it on any non-success status.
        status = state.get("status")
        return {
            "output": state.get("output") if status == AgentStatus.SUCCESS else None,
            "status": status,
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }


# Stable alias for the standalone entry point import (src/api/server.py).
# `Graph` kept as the conventional scaffold handle used by src/api/server.py).
Graph = GitLabWebhookAddGraph
