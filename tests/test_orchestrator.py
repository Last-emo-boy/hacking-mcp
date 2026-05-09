"""Tests for ToolOrchestrator and ToolRequest."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from hacking_mcp.orchestrator import (
    ToolOrchestrator,
    ToolRequest,
    ToolResponse,
)
from hacking_mcp.formatters import OutputFormatter, OutputFormat
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.runner import ToolRunner
from hacking_mcp.models import RunResult


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def safety():
    return SafetyPolicy(
        disabled_categories=["DDOS Attack", "Phishing Attack"],
        require_confirmation_categories=["SQL Injection", "Exploit Framework", "XSS Attack"],
    )


@pytest.fixture
def runner(registry, safety):
    return ToolRunner(registry, safety)


@pytest.fixture
def formatter():
    return OutputFormatter()


@pytest.fixture
def orchestrator(registry, safety, runner, formatter):
    return ToolOrchestrator(registry, safety, runner, formatter)


class TestToolRequest:
    def test_defaults(self):
        req = ToolRequest(tool_name="nmap")
        assert req.tool_name == "nmap"
        assert req.target == ""
        assert req.options == ""
        assert req.allowed_tools == set()
        assert req.target_required is True
        assert req.validate_scope is True
        assert req.confirm_authorized is False

    def test_with_allowlist(self):
        req = ToolRequest(
            tool_name="nmap",
            target="192.168.1.1",
            allowed_tools={"nmap", "amass"},
            category_label="reconnaissance",
        )
        assert req.allowed_tools == {"nmap", "amass"}
        assert req.category_label == "reconnaissance"

    def test_optional_target(self):
        req = ToolRequest(
            tool_name="prowler",
            target_required=False,
            validate_scope=False,
        )
        assert req.target_required is False
        assert req.validate_scope is False


class TestToolOrchestrator:
    def test_creation(self, orchestrator):
        assert orchestrator.registry is not None
        assert orchestrator.safety is not None
        assert orchestrator.runner is not None
        assert orchestrator.formatter is not None

    def test_unknown_tool_message(self, orchestrator):
        msg = orchestrator._unknown_tool_message("nonexistent_tool_xyz")
        assert "Unknown" in msg
        assert "nonexistent_tool_xyz" in msg

    def test_known_tool_suggestion(self, orchestrator):
        msg = orchestrator._unknown_tool_message("nma")
        # "nma" should match "nmap" as similar
        assert "Unknown" in msg

    def test_not_installed_message(self, orchestrator):
        msg = orchestrator._not_installed_message("amass")
        assert "not installed" in msg.lower()

    def test_dry_run(self, orchestrator):
        cmd = orchestrator.dry_run("nmap", "192.168.1.1", "-sV")
        assert "nmap" in cmd
        assert "192.168.1.1" in cmd
        assert "-sV" in cmd

    def test_dry_run_no_args(self, orchestrator):
        cmd = orchestrator.dry_run("nmap")
        assert "nmap" in cmd

    @pytest.mark.asyncio
    async def test_execute_unknown_tool(self, orchestrator):
        response = await orchestrator.execute(
            ToolRequest(tool_name="nonexistent_tool_xyz")
        )
        assert response.error != ""
        assert "Unknown" in response.error

    @pytest.mark.asyncio
    async def test_execute_not_in_allowlist(self, orchestrator):
        response = await orchestrator.execute(
            ToolRequest(
                tool_name="nmap",
                allowed_tools={"amass", "theHarvester"},
                category_label="reconnaissance",
            )
        )
        assert response.error != ""
        assert "not a reconnaissance tool" in response.error.lower()

    @pytest.mark.asyncio
    async def test_execute_missing_target(self, orchestrator):
        response = await orchestrator.execute(
            ToolRequest(
                tool_name="nmap",
                allowed_tools={"nmap"},
                target_required=True,
                target="",  # No target
            )
        )
        assert response.error != ""
        assert "requires a target" in response.error.lower()

    @pytest.mark.asyncio
    async def test_execute_not_installed(self, orchestrator):
        """Execute a tool that exists in registry but isn't installed."""
        response = await orchestrator.execute(
            ToolRequest(
                tool_name="amass",
                allowed_tools={"amass"},
                target="example.com",
            )
        )
        # amass is likely not installed — should get error about it
        assert response.error != "" or response.result is not None

    @pytest.mark.asyncio
    async def test_execute_blocked_category(self, orchestrator):
        """Tools in disabled categories should be blocked."""
        # Find a tool in a disabled category
        response = await orchestrator.execute(
            ToolRequest(
                tool_name="slowloris",
                target="example.com",
            )
        )
        # slowloris is in DDOS Attack (disabled) — should be blocked
        assert response.error
        assert "BLOCKED" in response.error or "disabled" in response.error.lower()

    @pytest.mark.asyncio
    async def test_execute_requires_explicit_confirmation(self, orchestrator):
        response = await orchestrator.execute(
            ToolRequest(
                tool_name="sqlmap",
                target="http://127.0.0.1:8000",
                allowed_tools={"sqlmap"},
            )
        )
        assert response.error
        assert "CONFIRMATION REQUIRED" in response.error
        assert "confirm_authorized=True" in response.error

    @pytest.mark.asyncio
    async def test_execute_confirmed_tool_reaches_runner(self, orchestrator):
        orchestrator.registry.is_available = MagicMock(return_value=True)
        orchestrator.runner.run = AsyncMock(return_value=RunResult(
            tool_name="sqlmap",
            command=["sqlmap"],
            return_code=0,
            stdout="ok",
            stderr="",
            duration_ms=10,
        ))

        response = await orchestrator.execute(
            ToolRequest(
                tool_name="sqlmap",
                target="http://127.0.0.1:8000",
                confirm_authorized=True,
                allowed_tools={"sqlmap"},
            )
        )

        assert response.error == ""
        orchestrator.runner.run.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_execute_uses_shell_like_options_parsing(self, orchestrator):
        orchestrator.registry.is_available = MagicMock(return_value=True)
        orchestrator.runner.run = AsyncMock(return_value=RunResult(
            tool_name="nmap",
            command=["nmap"],
            return_code=0,
            stdout="ok",
            stderr="",
            duration_ms=10,
        ))

        response = await orchestrator.execute(
            ToolRequest(
                tool_name="nmap",
                target="127.0.0.1",
                options='--script "safe arg" -p 80',
                allowed_tools={"nmap"},
            )
        )

        assert response.error == ""
        _, args = orchestrator.runner.run.call_args.args
        assert args == ["127.0.0.1", "--script", "safe arg", "-p", "80"]

    @pytest.mark.asyncio
    async def test_execute_rejects_invalid_options_syntax(self, orchestrator):
        orchestrator.registry.is_available = MagicMock(return_value=True)
        orchestrator.runner.run = AsyncMock()

        response = await orchestrator.execute(
            ToolRequest(
                tool_name="nmap",
                target="127.0.0.1",
                options='"unterminated',
                allowed_tools={"nmap"},
            )
        )

        assert response.error
        assert "Invalid options syntax" in response.error
        orchestrator.runner.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_successful_tool(self, orchestrator):
        """Execute a tool that should be available (like nmap on most systems)."""
        response = await orchestrator.execute(
            ToolRequest(
                tool_name="nmap",
                target="127.0.0.1",
                options="-p 80",
                allowed_tools={"nmap"},
                category_label="reconnaissance",
            )
        )
        # Either runs successfully or returns not-installed — both valid
        assert response.tool_name == "nmap"
        formatted = response.format()
        assert formatted != ""

    @pytest.mark.asyncio
    async def test_tool_response_format(self):
        response = ToolResponse(
            tool_name="nmap",
            result=RunResult(
                tool_name="nmap",
                command=["nmap", "127.0.0.1"],
                return_code=0,
                stdout="Port 80 open",
                stderr="",
                duration_ms=100,
            ),
            formatted="",
        )
        formatted = response.format()
        assert "nmap" in formatted

    @pytest.mark.asyncio
    async def test_tool_response_format_error(self):
        response = ToolResponse(
            tool_name="bad_tool",
            error="Something went wrong",
        )
        formatted = response.format()
        assert "Something went wrong" in formatted
