"""AgentCore Platform v1.0

OutputFormatNode - post_process slot (Step 5).

S-3: domain output gate via _extra_security_gate_output() - ensures no raw
     endpoint URL (which may carry query/secret parts) leaks into the response;
     the framework @final S-3 gate additionally scans result strings for
     credential patterns. The response carries the endpoint SHA-256 hash + alias,
     never the raw URL.
"""

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event


class OutputFormatNode(FunctionNode):
    """Assemble the confirmed-hook response (hash-only, no raw URL)."""

    # S-1 - same INTERNAL trust boundary as the rest of the write path.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def _extra_security_gate_output(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-3 domain output gate - defensive: strip any raw endpoint URL that
        slipped into the output payload (should never happen; hash-only by design)."""
        output = state.get("output")
        if isinstance(output, dict) and "endpoint_url" in output:
            output.pop("endpoint_url", None)
        return state

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Preparing the result...",
            metadata={"step": "post_process"},
        )
        hook_id = state.get("hook_id")
        emit_trace_event("output_format", {"hook_id": hook_id, "duplicate": state.get("duplicate")}, state)

        # Build the confirmed-hook response - endpoint as hash + alias only, never raw URL.
        output = {
            "project_id": state.get("project_id"),
            "hook_id": hook_id,
            "event_flags": sorted((state.get("event_flags") or {}).keys()),
            "endpoint_hash": state.get("endpoint_hash", ""),
            "endpoint_alias": state.get("endpoint_alias", ""),
            "duplicate": bool(state.get("duplicate", False)),
            "confidence_flags": state.get("confidence_flags", []),
        }

        return {
            "output": output,
            "status": AgentStatus.SUCCESS,
        }
