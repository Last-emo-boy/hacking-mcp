"""Dedicated adapter metadata for Fastssh."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "mode",
            str,
            "scan",
            "Fastssh mode: scan or bruteforcer.",
        ),
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Fastssh reads ranges, ports, thread counts, and wordlists interactively.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    mode = str(kwargs.get("mode") or "scan").strip().lower()
    if mode in {"brute", "bruteforce", "bruteforcer"}:
        return ["--bruteforcer"]
    return ["--scan"]
