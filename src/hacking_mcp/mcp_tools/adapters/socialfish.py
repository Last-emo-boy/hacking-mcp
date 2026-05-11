"""Dedicated adapter metadata for SocialFish."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("username", str, "", "SocialFish admin username positional argument."),
        AdapterParameterSpec(
            "password",
            str,
            "",
            "SocialFish admin password positional argument; may be present in process/audit logs.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    for key in ("username", "password"):
        value = str(kwargs.get(key) or "").strip()
        if value:
            tokens.append(value)
    return tokens
