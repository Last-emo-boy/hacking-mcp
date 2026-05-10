"""Dedicated adapter metadata for Vegile."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("action", str, "", "Vegile action: inject or unlimited."),
        AdapterParameterSpec("backdoor_path", str, "", "Backdoor/rootkit file path used by the selected action."),
        AdapterParameterSpec("help", bool, False, "Show Vegile help."),
    ]


def build_options(kwargs: dict) -> list[str]:
    if kwargs.get("help"):
        return ["--help"]

    action = _action_flag(str(kwargs.get("action") or "").strip().lower())
    if not action:
        return []

    tokens = [action]
    backdoor_path = kwargs.get("backdoor_path")
    if backdoor_path not in (None, "", 0, False):
        tokens.append(str(backdoor_path))
    return tokens


def _action_flag(action: str) -> str:
    if action in {"inject", "i", "--inject", "--i"}:
        return "--inject"
    if action in {"unlimited", "u", "--unlimited", "--u"}:
        return "--unlimited"
    return ""
