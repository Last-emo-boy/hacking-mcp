"""Dedicated adapter metadata for Sliver."""

import shlex
from typing import Any

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("command", str, "console", "Sliver client command such as console, import, mcp, or version."),
        AdapterParameterSpec("rc_script", str, "", "Path to an rc script for the client console."),
        AdapterParameterSpec("enable_wg", bool, False, "Use WireGuard wrapper settings from the operator config."),
        AdapterParameterSpec("config_files", str, "", "Semicolon-separated client config files for the import command."),
        AdapterParameterSpec("mcp_config", str, "", "Client config file path or name for the mcp command."),
        AdapterParameterSpec("version", bool, False, "Run the Sliver client version command."),
        AdapterParameterSpec("help", bool, False, "Show help for the selected client command."),
    ]


def build_options(kwargs: dict) -> list[str]:
    if kwargs.get("version"):
        return ["version"]

    tokens: list[str] = []
    add_bool(tokens, kwargs, "enable_wg", "--enable-wg")

    command = str(kwargs.get("command") or "console").strip() or "console"
    tokens.append(command)

    if command == "console":
        add_value(tokens, kwargs, "rc_script", "--rc")
    elif command == "import":
        tokens.extend(_split_values(kwargs.get("config_files")))
    elif command == "mcp":
        add_value(tokens, kwargs, "mcp_config", "--config")

    if kwargs.get("help"):
        tokens.append("--help")
    return tokens


def _split_values(value: Any) -> list[str]:
    if value in (None, "", 0, False):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "", 0, False)]
    raw = str(value).replace("\n", ";")
    parts = [item.strip() for item in raw.split(";") if item.strip()]
    if len(parts) > 1:
        return parts
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()
