"""Dedicated adapter metadata for Knockmail."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("email", str, "", "Single email address to verify (--email)."),
        AdapterParameterSpec("input_file", str, "", "File containing email addresses to verify (-f/--file)."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    if str(kwargs.get("input_file") or "").strip():
        add_value(tokens, kwargs, "input_file", "-f")
        return tokens

    email = str(kwargs.get("email") or kwargs.get("target") or "").strip()
    if email:
        tokens.extend(["--email", email])
    return tokens
