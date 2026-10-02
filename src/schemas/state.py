"""AgentCore Platform v1.0"""

# ADR-005: State must be a flat TypedDict - never Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects cause
# silent corruption. Extend AgentState with agent-specific fields only.
# Do NOT add credentials, secrets, or Pydantic models - the GitLab token and
# webhook secret are accessed via ctx.secrets.require() and never enter State.

from typing import Any, NotRequired

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """GitLabWebhookAddAgent state.

    Shared fields (user_input, status, session_id, node_history, error_log,
    caller_trust_level, correlation_id, etc.) are inherited from AgentState.
    Agent-specific fields are all optional (NotRequired) - they are populated
    as the 3-node pipeline progresses.
    """

    # Runtime domain config injected by the graph (_extra_initial_state):
    # SSRF allowlist, allowed event flags, GitLab base URL, timeout. Serializable only.
    agent_config: NotRequired[dict[str, Any]]

    # Sanitized NL request text produced by InputValidateNode
    sanitized_input: NotRequired[str]

    # InputParseNode resolution outputs (three-dimension)
    project_id: NotRequired[int]
    project_candidates: NotRequired[list[dict[str, Any]]]
    event_flags: NotRequired[dict[str, bool]]  # {flag_name: True}
    endpoint_url: NotRequired[str]
    endpoint_alias: NotRequired[str]
    confidence_flags: NotRequired[list[str]]

    # EndpointWhitelistCheckNode verdict
    allowlist_ok: NotRequired[bool]

    # WebhookCreateAPINode outputs
    hook_id: NotRequired[int]
    endpoint_hash: NotRequired[str]  # SHA-256 of endpoint_url (audit-safe)
    duplicate: NotRequired[bool]

    # OutputFormatNode result
    output: NotRequired[dict[str, Any]]
