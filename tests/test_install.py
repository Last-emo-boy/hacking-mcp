"""Tests for InstallManager and InstallCommandParser."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from hacking_mcp.install import (
    InstallManager,
    InstallCommandParser,
    InstallStep,
)
from hacking_mcp.models import HackingToolDef, InstallRecord, SafetyTier
from hacking_mcp.environment import get_tools_dir
from hacking_mcp.safety import SafetyPolicy


@pytest.fixture
def mock_runner():
    runner = MagicMock()
    runner.run_raw = AsyncMock()
    runner.env = MagicMock()
    runner.env.backend = MagicMock()
    runner.env.backend.value = "native"
    return runner


@pytest.fixture
def mock_registry():
    from hacking_mcp.registry import ToolRegistry
    return ToolRegistry()


@pytest.fixture
def install_mgr(mock_runner, mock_registry):
    mgr = InstallManager(mock_runner, mock_registry)
    mgr._state = {}  # Clear any loaded state
    return mgr


class TestInstallCommandParser:
    def test_git_clone_simple(self):
        from pathlib import Path
        tools_dir = str(Path("/tmp/tools"))
        steps = InstallCommandParser.parse(
            "git clone https://github.com/user/repo.git",
            tools_dir,
        )
        assert len(steps) == 1
        assert steps[0].method == "git_clone"
        assert steps[0].clone_url == "https://github.com/user/repo.git"
        assert steps[0].clone_dir.endswith("repo")

    def test_git_clone_custom_dir(self):
        steps = InstallCommandParser.parse(
            "git clone https://github.com/user/repo.git mydir",
            "/tmp/tools",
        )
        assert len(steps) == 1
        assert "mydir" in steps[0].clone_dir

    def test_pip_install(self):
        steps = InstallCommandParser.parse(
            "pip install --user requests",
            "/tmp/tools",
        )
        assert len(steps) == 1
        assert steps[0].method == "pip"
        assert "requests" in steps[0].command

    def test_apt_install(self):
        steps = InstallCommandParser.parse(
            "sudo apt-get install -y nmap",
            "/tmp/tools",
        )
        assert len(steps) == 1
        assert steps[0].method == "apt"
        assert steps[0].requires_sudo is True

    def test_go_install(self):
        steps = InstallCommandParser.parse(
            "go install github.com/project/cmd@latest",
            "/tmp/tools",
        )
        assert len(steps) == 1
        assert steps[0].method == "go"

    def test_gem_install(self):
        steps = InstallCommandParser.parse(
            "gem install evil-winrm",
            "/tmp/tools",
        )
        assert len(steps) == 1
        assert steps[0].method == "gem"

    def test_curl_pipe_sh(self):
        steps = InstallCommandParser.parse(
            "curl -sSf https://example.com/install | sh",
            "/tmp/tools",
        )
        assert len(steps) == 1
        assert steps[0].method == "curl_pipe_sh"
        assert steps[0].is_piped is True

    def test_chained_commands(self):
        from pathlib import Path
        steps = InstallCommandParser.parse(
            "cd mydir && pip install --user .",
            str(Path("/tmp/tools")),
        )
        assert len(steps) == 1
        assert steps[0].method == "pip"
        assert str(Path("/tmp/tools/mydir")) == steps[0].cwd

    def test_multi_step_git_clone_and_pip(self):
        from pathlib import Path
        tools_dir = str(Path("/tmp/tools"))
        steps = InstallCommandParser.parse(
            "git clone https://github.com/X/Y.git && cd Y && pip install --user -r requirements.txt",
            tools_dir,
        )
        assert len(steps) == 2
        assert steps[0].method == "git_clone"
        assert steps[1].method == "pip"
        # cd Y sets cwd to tools_dir/Y
        assert str(Path(tools_dir) / "Y") == steps[1].cwd

    def test_shell_chmod(self):
        steps = InstallCommandParser.parse(
            "chmod +x script.sh",
            "/tmp/tools",
        )
        assert len(steps) == 1
        assert steps[0].method == "shell"

    def test_empty_command(self):
        steps = InstallCommandParser.parse("", "/tmp/tools")
        assert len(steps) == 0

    def test_cd_only(self):
        steps = InstallCommandParser.parse("cd mydir", "/tmp/tools")
        assert len(steps) == 0  # cd is just a context setter

    def test_all_tool_install_commands_are_parseable(self, mock_registry):
        """Every declared install command should produce executable install steps."""
        failures = []
        for tool in mock_registry.list_all_tools():
            for cmd in tool.install_commands:
                steps = InstallCommandParser.parse(cmd, str(get_tools_dir()))
                if cmd.strip() and not steps:
                    failures.append((tool.name, cmd))
        assert failures == []

    def test_active_tools_have_install_commands(self, mock_registry):
        """Non-archived tools should have an automatic install path."""
        missing = [
            tool.name
            for tool in mock_registry.list_all_tools()
            if not tool.archived and not tool.install_commands
        ]
        assert missing == []

    def test_active_tools_have_run_commands(self, mock_registry):
        """Non-archived tools should expose a runnable command template."""
        missing = [
            tool.name
            for tool in mock_registry.list_all_tools()
            if not tool.archived and not tool.run_command
        ]
        assert missing == []


class TestInstallManager:
    @pytest.mark.asyncio
    async def test_install_unknown_tool(self, install_mgr):
        record = await install_mgr.install_tool("nonexistent_xyz")
        assert record.installed is False
        assert "Unknown" in record.error

    @pytest.mark.asyncio
    async def test_install_no_commands(self, install_mgr):
        install_mgr._registry._tools["no-install-test"] = HackingToolDef(
            name="no-install-test",
            title="No Install Test",
            description="Test-only tool with no install commands.",
            category="Information Gathering",
            run_command="echo ok",
            safety_tier=SafetyTier.SAFE,
        )
        record = await install_mgr.install_tool("no-install-test")
        assert record.installed is False
        assert "No install commands" in record.error

    @pytest.mark.asyncio
    async def test_get_install_status_default(self, install_mgr):
        record = install_mgr.get_install_status("nmap")
        assert record.installed is False
        assert record.tool_name == "nmap"

    @pytest.mark.asyncio
    async def test_install_success(self, install_mgr, mock_runner):
        """Test successful install with a mock runner."""
        mock_runner.run_raw.return_value = MagicMock(
            return_code=0,
            stdout="Installed successfully",
            stderr="",
            duration_ms=100,
        )

        # nmap's install_commands: ["git clone ...", "sudo chmod ... && cd nmap && ..."]
        # First step is git_clone
        record = await install_mgr.install_tool("nmap")

        assert record.installed is True
        assert record.method == "git_clone"  # Primary method from first step
        assert record.steps_completed == record.steps_total

    @pytest.mark.asyncio
    async def test_install_step_failure(self, install_mgr, mock_runner):
        """Test that install failure is reported correctly."""
        mock_runner.run_raw.return_value = MagicMock(
            return_code=1,
            stdout="",
            stderr="Package not found",
            duration_ms=100,
        )

        record = await install_mgr.install_tool("nmap")

        assert record.installed is False
        assert record.steps_completed < record.steps_total

    @pytest.mark.asyncio
    async def test_already_installed(self, install_mgr):
        """Already installed tools should return immediately."""
        install_mgr._state["nmap"] = {
            "tool_name": "nmap",
            "installed": True,
            "method": "apt",
            "installed_at": "2026-01-01T00:00:00Z",
            "error": "",
            "steps_completed": 1,
            "steps_total": 1,
        }
        record = await install_mgr.install_tool("nmap")
        assert record.installed is True

    @pytest.mark.asyncio
    async def test_uninstall(self, install_mgr):
        install_mgr._state["nmap"] = {
            "tool_name": "nmap",
            "installed": True,
            "method": "apt",
            "installed_at": "2026-01-01T00:00:00Z",
            "error": "",
            "steps_completed": 1,
            "steps_total": 1,
        }
        success = await install_mgr.uninstall_tool("nmap")
        assert success is True
        assert install_mgr.get_install_status("nmap").installed is False

    @pytest.mark.asyncio
    async def test_uninstall_not_installed(self, install_mgr):
        success = await install_mgr.uninstall_tool("nonexistent")
        assert success is False

    @pytest.mark.asyncio
    async def test_install_blocked_by_safety_policy(self, mock_runner, mock_registry):
        safety = SafetyPolicy(disabled_categories=["DDOS Attack"])
        mgr = InstallManager(mock_runner, mock_registry, safety=safety)
        mgr._state = {}

        record = await mgr.install_tool("slowloris")

        assert record.installed is False
        assert "blocked by safety policy" in record.error
        mock_runner.run_raw.assert_not_called()
