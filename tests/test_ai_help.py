"""Tests for AI-facing tool usage guidance."""

from hacking_mcp.ai_help import build_ai_help, format_ai_help
from hacking_mcp.registry import ToolRegistry


def test_ai_help_for_safe_recon_tool():
    registry = ToolRegistry()
    tool = registry.get_tool("nmap")

    help_doc = build_ai_help(tool)

    assert help_doc.endpoint == "security_run_recon"
    assert "IP address" in help_doc.target_hint
    assert "security_run_recon" in help_doc.safe_example
    assert "nmap" in help_doc.safe_example


def test_ai_help_for_caution_tool_has_authorization_warning():
    registry = ToolRegistry()
    tool = registry.get_tool("sqlmap")

    rendered = format_ai_help(tool)

    assert "security_run_exploit" in rendered
    assert "Requires explicit authorization" in rendered


def test_ai_help_for_dangerous_archived_tool_not_exposed():
    registry = ToolRegistry()
    tool = registry.get_tool("instabrute")

    rendered = format_ai_help(tool)

    assert "not exposed" in rendered
    assert "Dangerous tool" in rendered
    assert "Archived catalog entry" in rendered
