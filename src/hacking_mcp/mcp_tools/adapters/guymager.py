"""Dedicated adapter metadata for Guymager."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_assignment


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("log_file", str, "", "Alternative Guymager log file (log=...)."),
        AdapterParameterSpec("config_file", str, "", "Alternative Guymager configuration file (cfg=...)."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_assignment(tokens, kwargs, "log_file", "log")
    add_assignment(tokens, kwargs, "config_file", "cfg")
    return tokens
