"""AgentCore Platform v1.0

InputValidateNode - pre_process slot (Step 1).

S-1: required_trust_level = INTERNAL (this agent writes infrastructure).
S-2: deterministic credential / My Number (kojin bango) reject via _extra_security_gate_input()
     (auto-reject, not advisory). Legitimate payloads (project paths, endpoint
     aliases) pass through and are carried forward as sanitized_input.
"""

import re
from typing import Any, ClassVar

from framework.errors import SecurityViolationError
from shared.services.events import emitter
from shared.services.events.types import EventType
from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

# Embedded-credential patterns that must never reach the resolver/API.
_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),  # GitLab PAT
    re.compile(r"\beyJ[A-Za-z0-9._-]{10,}"),  # JWT
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{10,}", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style key
    re.compile(r"AKIA[A-Z0-9]{16}"),  # AWS access key
)

# My Number (kojin bango) (My Number) - 12 consecutive digits, allowing space/hyphen separators.
_MYNUMBER_PATTERN = re.compile(r"\b(?:\d[ -]?){11}\d\b")


class InputValidateNode(FunctionNode):
    """Validate the NL webhook request; reject embedded credentials / PII."""

    # S-1 - infrastructure-writing agent; explicit, not inherited.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def _extra_security_gate_input(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-2 domain input gate - deterministic auto-reject of secrets/PII."""
        text = state.get("user_input", "") or ""
        for pat in _CREDENTIAL_PATTERNS:
            if pat.search(text):
                raise SecurityViolationError(
                    "InputValidateNode", "no-embedded-credentials", "embedded-credential-detected"
                )
        if _MYNUMBER_PATTERN.search(text):
            raise SecurityViolationError("InputValidateNode", "no-personal-number", "my-number-detected")
        return state

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Progress (non-terminal) event for the caller. Outside the Marketplace runtime
        # this resolves to a no-op emitter, so it is safe on every entry path.
        emitter().emit_event(
            event_type=EventType.PROGRESS_UPDATE,
            message="Checking the request...",
            metadata={"step": "pre_process"},
        )
        user_input = (state.get("user_input", "") or "").strip()
        emit_trace_event("input_validate", {"has_input": bool(user_input)}, state)

        if not user_input:
            return {
                "status": AgentStatus.ERROR,
                "error_log": ["InputValidateNode: user_input is empty or missing"],
            }

        return {
            "sanitized_input": user_input,
            "status": AgentStatus.SUCCESS,
        }
