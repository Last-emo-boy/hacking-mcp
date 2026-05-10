"""Dedicated adapter metadata for Mythic."""

import shlex
from typing import Any

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("command", str, "start", "Mythic CLI command: start, stop, restart, or status."),
        AdapterParameterSpec("service_names", str, "", "Container/service names for start, stop, or restart."),
        AdapterParameterSpec("keep_volume", bool, False, "Keep existing container volumes for start or stop."),
        AdapterParameterSpec("verbose", bool, False, "Show verbose status output."),
        AdapterParameterSpec("help", bool, False, "Show help for the selected Mythic CLI command."),
    ]


def build_options(kwargs: dict) -> list[str]:
    command = str(kwargs.get("command") or "start").strip() or "start"
    tokens = [command]

    if command in {"start", "stop"}:
        add_bool(tokens, kwargs, "keep_volume", "--keep-volume")
        tokens.extend(_split_values(kwargs.get("service_names")))
    elif command == "restart":
        tokens.extend(_split_values(kwargs.get("service_names")))
    elif command == "status":
        add_bool(tokens, kwargs, "verbose", "--verbose")

    if kwargs.get("help"):
        tokens.append("--help")
    return tokens


def _split_values(value: Any) -> list[str]:
    if value in (None, "", 0, False):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "", 0, False)]
    raw = str(value).replace(",", " ")
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()
