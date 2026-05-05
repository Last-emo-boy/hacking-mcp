"""Tool providers — extensible sources of tool definitions.

The ToolProvider ABC allows adding new tool sources beyond the built-in
hackingtool catalog: Docker-based tools, API-based tools, custom user
tools from YAML/JSON config, etc.
"""

from abc import ABC, abstractmethod

from hacking_mcp.models import HackingToolDef


class ToolProvider(ABC):
    """Abstract source of tool definitions.

    Subclass to add new tool sources: Docker containers, API wrappers,
    custom user tools, etc.
    """

    name: str = "base"

    @abstractmethod
    def get_tools(self) -> list[HackingToolDef]:
        """Return all tool definitions from this provider."""
        ...

    @abstractmethod
    def get_categories(self) -> list[dict]:
        """Return category metadata: name, description, tool_count."""
        ...

    def get_category_description(self, category: str) -> str:
        """Return the description for a category."""
        return ""


class HackingtoolProvider(ToolProvider):
    """Provider wrapping the built-in hackingtool catalog (182 tools, 20 categories).

    This is the default provider. It reads from the existing ALL_CATEGORIES
    and CATEGORY_DESCRIPTIONS in registry.py.
    """

    name = "hackingtool"

    def __init__(
        self,
        all_categories: dict[str, list[HackingToolDef]],
        category_descriptions: dict[str, str],
    ):
        self._all_categories = all_categories
        self._category_descriptions = category_descriptions

    def get_tools(self) -> list[HackingToolDef]:
        tools: list[HackingToolDef] = []
        for tool_list in self._all_categories.values():
            tools.extend(tool_list)
        return tools

    def get_categories(self) -> list[dict]:
        return [
            {
                "name": cat,
                "description": self._category_descriptions.get(cat, ""),
                "tool_count": len(tools),
            }
            for cat, tools in self._all_categories.items()
        ]

    def get_category_description(self, category: str) -> str:
        return self._category_descriptions.get(category, "")

    def get_category_tools(self, category: str) -> list[HackingToolDef]:
        return self._all_categories.get(category, [])
