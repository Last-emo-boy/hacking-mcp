"""Dedicated adapter metadata for EvilTwin fakeap."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "action",
            str,
            "",
            "Optional fakeap action; use stop to map to --stop, empty starts interactive flow.",
        ),
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "fakeap starts an interactive Evil Twin setup flow.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    action = str(kwargs.get("action") or "").strip().lower()
    if action == "stop":
        return ["--stop"]
    return []
