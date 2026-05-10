"""Dedicated adapter metadata for RouterSploit."""

import shlex
from typing import Any

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("module", str, "", "Module path for non-interactive execution, passed with -m."),
        AdapterParameterSpec("set_options", str, "", "Semicolon-separated option assignments passed as repeated -s values."),
        AdapterParameterSpec("interactive", bool, True, "Start the RouterSploit console when module is empty."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "module", "-m")
    target = str(kwargs.get("target") or "").strip()
    if target:
        tokens.extend(["-s", f"target {target}"])
    for assignment in _split_assignments(kwargs.get("set_options")):
        tokens.extend(["-s", assignment])
    return tokens


def _split_assignments(value: Any) -> list[str]:
    if value in (None, "", 0, False):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "", 0, False)]
    raw = str(value).replace("\n", ";")
    parts = [item.strip() for item in raw.split(";") if item.strip()]
    if parts:
        return parts
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()
