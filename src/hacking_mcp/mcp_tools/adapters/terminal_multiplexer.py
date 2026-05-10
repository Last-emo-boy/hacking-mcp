"""Registry-derived adapter metadata for Terminal Multiplexer."""

from hacking_mcp.mcp_tools.adapters.generic import build_options_for, parameters_for


TOOL_NAME = 'terminal-multiplexer'


def parameters():
    return parameters_for(TOOL_NAME)


def build_options(kwargs: dict) -> list[str]:
    return build_options_for(TOOL_NAME, kwargs)
