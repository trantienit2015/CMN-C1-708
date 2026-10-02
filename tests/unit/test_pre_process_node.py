# CMN-C1-708 — Unit tests: InputValidateNode (pre_process, S-1/S-2)

import pytest

from framework.errors import SecurityViolationError
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.nodes.pre_process_node import InputValidateNode


class TestInputValidateNode:
    def setup_method(self):
        self.node = InputValidateNode()

    def test_trust_level_is_internal(self):
        """S-1: infrastructure-writing node must require INTERNAL trust."""
        assert InputValidateNode.required_trust_level == TrustLevel.INTERNAL

    def test_success_path(self):
        state = {"user_input": "Add a webhook to grp/proj calling https://ci.example/hook on push"}
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS
        assert result["sanitized_input"].startswith("Add a webhook")

    def test_empty_input_errors(self):
        result = self.node.execute({"user_input": "   "})
        assert result["status"] == AgentStatus.ERROR
        assert result["error_log"]

    def test_s2_rejects_gitlab_pat(self):
        """S-2: embedded GitLab PAT -> SecurityViolationError."""
        # The detector matches glpat-[A-Za-z0-9_-]{20,}. The fixture is assembled at
        # run time instead of committed as a literal: a GitLab token shape counts as
        # a finding even under tests/, so the literal would fail the credential scan.
        pat = "glpat-" + "abcdef1234567890ABCDEF"
        state = {"user_input": f"use token {pat} for the hook"}
        with pytest.raises(SecurityViolationError):
            self.node._extra_security_gate_input(state)

    def test_s2_rejects_jwt(self):
        state = {"user_input": "auth eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload here"}
        with pytest.raises(SecurityViolationError):
            self.node._extra_security_gate_input(state)

    def test_s2_rejects_mynumber(self):
        state = {"user_input": "requester my number 1234 5678 9012 create the hook"}
        with pytest.raises(SecurityViolationError):
            self.node._extra_security_gate_input(state)

    def test_s2_allows_legitimate_payload(self):
        """Project paths + endpoint aliases are the legitimate payload — must pass."""
        state = {"user_input": "add webhook to group/project calling https://ci.example/hook on push"}
        # Should not raise; hook returns the (unchanged) state per the framework contract.
        assert self.node._extra_security_gate_input(state) is state
