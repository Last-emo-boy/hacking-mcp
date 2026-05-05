"""Tests for ToolRegistry."""

import pytest
from hacking_mcp.registry import ToolRegistry


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

    def test_install_commands_none(self, registry):
        """Tools without install commands should return empty list."""
        cmds = registry.get_install_commands("host2ip")
        assert cmds == []

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
