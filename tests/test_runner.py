"""Tests for ToolRunner."""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from hacking_mcp.runner import ToolRunner
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.models import HackingToolDef, SafetyTier, RunResult


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def safety():
    return SafetyPolicy(
        disabled_categories=["DDOS Attack", "Phishing Attack"],
    )


@pytest.fixture
def runner(registry, safety):
    return ToolRunner(registry, safety)


class TestToolRunner:
    def test_dry_run_returns_command(self, runner):
        cmd = runner.dry_run("nmap", ["-sV", "10.0.0.1"])
        assert "nmap" in cmd
        assert "-sV" in cmd

    def test_dry_run_unknown_tool(self, runner):
        cmd = runner.dry_run("nonexistent")
        assert "Unknown" in cmd

    def test_get_install_instructions(self, runner):
        cmds = runner.get_install_instructions("nmap")
        assert len(cmds) > 0

    @pytest.mark.asyncio
    async def test_run_unknown_tool(self, runner):
        result = await runner.run("nonexistent_tool")
        assert result.was_blocked
        assert result.return_code == -1

    @pytest.mark.asyncio
    async def test_run_blocked_tool(self, runner):
        """Running a DANGEROUS-tier tool should be blocked."""
        result = await runner.run("mythic")
        assert result.was_blocked

    @pytest.mark.asyncio
    async def test_run_tool_not_installed(self, runner):
        """Running a tool not on PATH should return an informative error."""
        result = await runner.run("rustscan", ["127.0.0.1"])
        # rustscan is unlikely to be installed; the runner should diagnose this
        assert result.return_code == -1
        assert (
            "not installed" in result.stderr.lower()
            or "not found" in result.stderr.lower()
            or "cannot run" in result.stderr.lower()
        )

    @pytest.mark.asyncio
    async def test_run_result_structure(self, runner):
        """RunResult should have all expected fields."""
        result = await runner.run("host2ip", ["localhost"])
        assert isinstance(result, RunResult)
        assert result.tool_name == "host2ip"
        assert isinstance(result.command, list)
        assert isinstance(result.return_code, int)
        assert isinstance(result.duration_ms, int)

    @pytest.mark.asyncio
    async def test_run_with_timeout(self, runner):
        """Run with a short timeout should not hang."""
        import time
        start = time.monotonic()
        result = await runner.run("host2ip", ["localhost"], timeout=10)
        elapsed = time.monotonic() - start
        assert elapsed < 15  # Should complete quickly
