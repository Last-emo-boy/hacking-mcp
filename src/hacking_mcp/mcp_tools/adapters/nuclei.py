"""Dedicated adapter metadata for Nuclei."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("severity", str, "", "Comma-separated severities, for example critical,high."),
        AdapterParameterSpec("tags", str, "", "Comma-separated nuclei template tags."),
        AdapterParameterSpec("template_path", str, "", "Template file or directory path."),
        AdapterParameterSpec("rate_limit", int, 0, "Maximum requests per second; 0 leaves default."),
        AdapterParameterSpec("proxy", str, "", "Optional HTTP proxy URL."),
        AdapterParameterSpec("workflows", str, "", "Nuclei workflow file or directory."),
        AdapterParameterSpec("exclude_templates", str, "", "Comma-separated templates to exclude."),
        AdapterParameterSpec("headless", bool, False, "Enable headless browser templates."),
        AdapterParameterSpec("interactsh", bool, False, "Enable interactsh/OAST interaction support."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "severity", "-severity")
    add_value(tokens, kwargs, "tags", "-tags")
    add_value(tokens, kwargs, "template_path", "-t")
    add_value(tokens, kwargs, "rate_limit", "-rate-limit")
    add_value(tokens, kwargs, "proxy", "-proxy")
    add_value(tokens, kwargs, "workflows", "-w")
    add_value(tokens, kwargs, "exclude_templates", "-exclude-templates")
    add_bool(tokens, kwargs, "headless", "-headless")
    add_bool(tokens, kwargs, "interactsh", "-interactsh-server")
    return tokens
