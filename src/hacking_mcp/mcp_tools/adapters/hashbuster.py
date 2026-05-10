"""Dedicated adapter metadata for Hashbuster."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "input_type",
            str,
            "single",
            "Input type for the target: single (-s), file (-f), or directory (-d).",
        ),
        AdapterParameterSpec("threads", int, 0, "Number of worker threads (-t); 0 leaves default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    input_type = str(kwargs.get("input_type") or "single").strip().lower()
    flag = {
        "single": "-s",
        "hash": "-s",
        "file": "-f",
        "directory": "-d",
        "dir": "-d",
    }.get(input_type, "-s")
    add_value(tokens, kwargs, "threads", "-t")
    tokens.append(flag)
    return tokens
