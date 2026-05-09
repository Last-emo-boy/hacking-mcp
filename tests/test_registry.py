"""Tests for ToolRegistry."""

import pytest
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.environment import Environment, ExecBackend


@pytest.fixture
def registry():
    return ToolRegistry()


class TestToolRegistry:
    def test_loads_all_tools(self, registry):
        """Registry should load 100+ tools from all categories."""
        names = registry.get_tool_names()
        assert len(names) > 100

    def test_loads_all_categories(self, registry):
        """Registry should have 20 categories (all hackingtool categories)."""
        cats = registry.list_categories()
        assert len(cats) == 20

    def test_get_tool_by_name(self, registry):
        """Should find tool by exact name."""
        tool = registry.get_tool("nmap")
        assert tool is not None
        assert tool.name == "nmap"
        assert tool.category == "Information Gathering"

    def test_get_tool_not_found(self, registry):
        """Should return None for unknown tool."""
        assert registry.get_tool("nonexistent_tool") is None

    def test_get_category_tools(self, registry):
        """Should return tools for a valid category."""
        tools = registry.get_category_tools("Information Gathering")
        assert len(tools) > 20
        assert all(t.category == "Information Gathering" for t in tools)

    def test_search_tools_by_name(self, registry):
        """Should find tools by partial name match."""
        results = registry.search_tools("nmap")
        assert any(t.name == "nmap" for t in results)

    def test_search_tools_case_insensitive(self, registry):
        """Search should be case insensitive."""
        results = registry.search_tools("NMAP")
        assert any(t.name == "nmap" for t in results)

    def test_search_by_description(self, registry):
        """Search should match descriptions."""
        results = registry.search_tools("subdomain")
        assert len(results) > 0

    def test_search_by_tag(self, registry):
        """Search should match tags."""
        results = registry.search_tools("osint")
        assert len(results) > 0

    def test_search_by_tag_dedicated(self, registry):
        """search_by_tag should find tagged tools."""
        results = registry.search_by_tag("osint")
        assert len(results) > 0
        assert all("osint" in t.tags for t in results)

    def test_get_all_tags(self, registry):
        """Should return sorted unique tags."""
        tags = registry.get_all_tags()
        assert len(tags) > 100
        assert "osint" in tags
        assert "web" in tags
        assert tags == sorted(tags)

    def test_availability_tracking(self, registry):
        """Every tool should have availability status."""
        for name in registry.get_tool_names():
            avail = registry.get_availability(name)
            assert avail is not None
            assert avail.tool_name == name

    def test_is_available(self, registry):
        """is_available should return bool."""
        assert isinstance(registry.is_available("nmap"), bool)

    def test_install_commands(self, registry):
        """Tools with install commands should return them."""
        cmds = registry.get_install_commands("nmap")
        assert len(cmds) > 0

    def test_install_commands_for_runtime_dependency_tool(self, registry):
        """Built-in helpers should still declare their runtime dependency install path."""
        cmds = registry.get_install_commands("host2ip")
        assert cmds == ["sudo apt-get install -y python3"]

    def test_list_categories_structure(self, registry):
        """Each category info should have required fields."""
        cats = registry.list_categories()
        for cat in cats:
            assert "name" in cat
            assert "description" in cat
            assert "tool_count" in cat
            assert "available_count" in cat
            assert cat["tool_count"] > 0

    def test_refresh_does_not_crash(self, registry):
        """refresh() should not raise."""
        registry.refresh()

    def test_windows_wsl_checks_tools_that_also_support_windows(self, monkeypatch):
        """WSL2 availability should cover Linux tools even if they also support Windows."""
        import hacking_mcp.registry as registry_mod

        registry_mod._wsl_commands_cache = ({"python3"}, {"python3": "wsl:/usr/bin/python3"})
        monkeypatch.setattr(registry_mod.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            registry_mod,
            "detect_environment",
            lambda: Environment(
                system="windows",
                backend=ExecBackend.WSL2,
                wsl_available=True,
                wsl_distro="Ubuntu",
            ),
        )
        monkeypatch.setattr(registry_mod.shutil, "which", lambda exe: None)

        reg = ToolRegistry()
        avail = reg.get_availability("host2ip")

        assert avail.available is True
        assert avail.path == "wsl:/usr/bin/python3"

    def test_windows_wsl_requires_tool_directory_for_chdir_commands(self, monkeypatch):
        """Interpreter-backed repo tools require the cloned directory too."""
        import hacking_mcp.registry as registry_mod

        registry_mod._wsl_commands_cache = ({"python3"}, {"python3": "wsl:/usr/bin/python3"})
        monkeypatch.setattr(registry_mod.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            registry_mod,
            "detect_environment",
            lambda: Environment(
                system="windows",
                backend=ExecBackend.WSL2,
                wsl_available=True,
                wsl_distro="Ubuntu",
            ),
        )
        monkeypatch.setattr(registry_mod.shutil, "which", lambda exe: None)

        reg = ToolRegistry()
        avail = reg.get_availability("checkurl")

        assert avail.available is False

    def test_windows_wsl_chdir_tool_available_when_directory_exists(self, monkeypatch):
        """Repository-backed tools become available when interpreter and repo dir exist."""
        import hacking_mcp.registry as registry_mod

        monkeypatch.setattr(registry_mod.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            registry_mod,
            "detect_environment",
            lambda: Environment(
                system="windows",
                backend=ExecBackend.WSL2,
                wsl_available=True,
                wsl_distro="Ubuntu",
            ),
        )
        monkeypatch.setattr(registry_mod.shutil, "which", lambda exe: None)
        monkeypatch.setattr(
            registry_mod,
            "get_tools_dir",
            lambda: registry_mod.Path("C:/Users/test/.hacking-mcp/tools"),
        )
        registry_mod._wsl_commands_cache = (
            {"python3", "dir=/mnt/c/Users/test/.hacking-mcp/tools/checkURL"},
            {
                "python3": "wsl:/usr/bin/python3",
                "dir=/mnt/c/Users/test/.hacking-mcp/tools/checkURL": (
                    "wsl:/mnt/c/Users/test/.hacking-mcp/tools/checkURL"
                ),
            },
        )

        reg = ToolRegistry()
        avail = reg.get_availability("checkurl")

        assert avail.available is True
        assert avail.path == "wsl:/mnt/c/Users/test/.hacking-mcp/tools/checkURL"

    def test_windows_wsl_requires_python_module_for_module_commands(self, monkeypatch):
        """python -m tools require the Python module to be importable."""
        import hacking_mcp.registry as registry_mod

        registry_mod._wsl_commands_cache = ({"python3"}, {"python3": "wsl:/usr/bin/python3"})
        monkeypatch.setattr(registry_mod.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            registry_mod,
            "detect_environment",
            lambda: Environment(
                system="windows",
                backend=ExecBackend.WSL2,
                wsl_available=True,
                wsl_distro="Ubuntu",
            ),
        )
        monkeypatch.setattr(registry_mod.shutil, "which", lambda exe: None)

        reg = ToolRegistry()
        avail = reg.get_availability("nosqlmap")

        assert avail.available is False

    def test_windows_wsl_module_tool_available_when_module_exists(self, monkeypatch):
        """python -m tools become available when the module is importable."""
        import hacking_mcp.registry as registry_mod

        registry_mod._wsl_commands_cache = (
            {"python3", "py=python3:nosqlmap"},
            {
                "python3": "wsl:/usr/bin/python3",
                "py=python3:nosqlmap": "wsl:nosqlmap",
            },
        )
        monkeypatch.setattr(registry_mod.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            registry_mod,
            "detect_environment",
            lambda: Environment(
                system="windows",
                backend=ExecBackend.WSL2,
                wsl_available=True,
                wsl_distro="Ubuntu",
            ),
        )
        monkeypatch.setattr(registry_mod.shutil, "which", lambda exe: None)

        reg = ToolRegistry()
        avail = reg.get_availability("nosqlmap")

        assert avail.available is True

    def test_wsl_batch_scan_uses_stdout_even_with_nonzero_exit(self, monkeypatch):
        """Batch WSL scanning should not drop valid stdout because one command is missing."""
        import subprocess
        import hacking_mcp.registry as registry_mod

        registry_mod._wsl_commands_cache = None
        monkeypatch.setattr(registry_mod.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            registry_mod,
            "detect_environment",
            lambda: Environment(
                system="windows",
                backend=ExecBackend.WSL2,
                wsl_available=True,
                wsl_distro="Ubuntu",
            ),
        )
        monkeypatch.setattr(registry_mod.shutil, "which", lambda exe: None)

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=1,
                stdout=(
                    b"python3:/usr/bin/python3\n"
                    b"dir=/mnt/c/Users/test/.hacking-mcp/tools/checkURL:"
                    b"/mnt/c/Users/test/.hacking-mcp/tools/checkURL\n"
                ),
                stderr=b"",
            )

        monkeypatch.setattr(registry_mod.subprocess, "run", fake_run)

        reg = ToolRegistry()
        avail = reg.get_availability("host2ip")

        assert avail.available is True
        assert avail.path == "wsl:/usr/bin/python3"
