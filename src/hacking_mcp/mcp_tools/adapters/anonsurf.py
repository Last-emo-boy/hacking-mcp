"""Dedicated adapter metadata for Anonsurf."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "action",
            str,
            "start",
            "Anonsurf action: start, stop, restart, change, status, starti2p, or stopi2p.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    action = str(kwargs.get("action") or "start").strip()
    return [action] if action else []
