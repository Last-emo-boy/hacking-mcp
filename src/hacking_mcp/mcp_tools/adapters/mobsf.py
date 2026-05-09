"""Dedicated adapter metadata for MobSF."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("bind_host", str, "", "MobSF web server bind IP; empty uses run.sh default."),
        AdapterParameterSpec("bind_port", int, 0, "MobSF web server bind port; 0 uses run.sh default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    host = str(kwargs.get("bind_host") or "").strip()
    port = _int_value(kwargs, "bind_port")
    if host and port:
        return [f"{host}:{port}"]
    if host:
        return [f"{host}:8000"]
    if port:
        return [f"0.0.0.0:{port}"]
    return []


def _int_value(kwargs: dict, key: str) -> int:
    try:
        return int(kwargs.get(key) or 0)
    except (TypeError, ValueError):
        return 0
