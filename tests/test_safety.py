"""Tests for SafetyPolicy."""

import pytest
from pathlib import Path
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.models import HackingToolDef, SafetyTier


@pytest.fixture
def safety():
    return SafetyPolicy(
        disabled_categories=["DDOS Attack", "Phishing Attack"],
        disabled_tools=["chrome-keylogger"],
        require_confirmation_categories=["SQL Injection", "Exploit Framework"],
        max_timeout_seconds=300,
        max_output_bytes=1_000_000,
        allowed_cidrs=["10.0.0.0/8", "192.168.1.0/24"],
        allowed_domains=["example.com", "*.test.local"],
    )


@pytest.fixture
def safe_tool():
    return HackingToolDef(
        name="nmap",
        title="Nmap",
        description="Network scanner",
        category="Information Gathering",
        safety_tier=SafetyTier.SAFE,
    )


@pytest.fixture
def caution_tool():
    return HackingToolDef(
        name="sqlmap",
        title="Sqlmap",
        description="SQL injection tool",
        category="SQL Injection",
        safety_tier=SafetyTier.CAUTION,
    )


@pytest.fixture
def dangerous_tool():
    return HackingToolDef(
        name="slowloris",
        title="SlowLoris",
        description="DOS tool",
        category="Web Attack",
        safety_tier=SafetyTier.DANGEROUS,
    )


class TestSafetyPolicy:
    def test_safe_tool_allowed(self, safety, safe_tool):
        allowed, reason = safety.check_tool(safe_tool)
        assert allowed
        assert reason == ""

    def test_dangerous_tier_blocked(self, safety, dangerous_tool):
        allowed, reason = safety.check_tool(dangerous_tool)
        assert not allowed
        assert "DANGEROUS" in reason

    def test_disabled_category_blocked(self, safety):
        tool = HackingToolDef(
            name="test",
            title="Test",
            description="Test",
            category="Phishing Attack",
            safety_tier=SafetyTier.SAFE,
        )
        allowed, reason = safety.check_tool(tool)
        assert not allowed
        assert "disabled" in reason.lower()

    def test_disabled_tool_blocked(self, safety):
        tool = HackingToolDef(
            name="chrome-keylogger",
            title="Chrome Keylogger",
            description="Keylogger",
            category="Post Exploitation",
            safety_tier=SafetyTier.SAFE,
        )
        allowed, reason = safety.check_tool(tool)
        assert not allowed

    def test_archived_tool_blocked(self, safety):
        tool = HackingToolDef(
            name="oldtool",
            title="Old Tool",
            description="Deprecated",
            category="Web Attack",
            safety_tier=SafetyTier.SAFE,
            archived=True,
            archived_reason="Python 2 only",
        )
        allowed, reason = safety.check_tool(tool)
        assert not allowed
        assert "archived" in reason.lower()

    def test_requires_confirmation(self, safety, safe_tool, caution_tool):
        assert not safety.requires_confirmation(safe_tool)
        assert safety.requires_confirmation(caution_tool)

    def test_validate_target_ip_in_scope(self, safety):
        ok, reason = safety.validate_target("10.0.0.1")
        assert ok
        assert reason == ""

    def test_validate_target_ip_out_of_scope(self, safety):
        ok, reason = safety.validate_target("8.8.8.8")
        assert not ok

    def test_validate_target_domain_in_scope(self, safety):
        ok, reason = safety.validate_target("example.com")
        assert ok

    def test_validate_target_wildcard_domain(self, safety):
        ok, reason = safety.validate_target("app.test.local")
        assert ok

    def test_validate_target_no_scope_allows_all(self):
        no_scope = SafetyPolicy()
        ok, reason = no_scope.validate_target("anything.example.com")
        assert ok

    def test_audit_logging(self, safety, safe_tool):
        safety.log_invocation("nmap", "10.0.0.1", ["-sV"], True)
        log = safety.get_audit_log()
        assert len(log) == 1
        assert log[0]["tool"] == "nmap"
        assert log[0]["allowed"] is True

    def test_policy_summary(self, safety):
        summary = safety.get_policy_summary()
        assert "DDOS Attack" in summary["disabled_categories"]
        assert "SQL Injection" in summary["confirmation_categories"]
        assert summary["max_timeout_seconds"] == 300
        assert summary["scope_active"] is True

    def test_load_from_yaml(self):
        path = Path("config/safety_policy.yaml")
        if path.exists():
            policy = SafetyPolicy.from_yaml(path)
            assert policy is not None
            assert len(policy.disabled_categories) > 0
