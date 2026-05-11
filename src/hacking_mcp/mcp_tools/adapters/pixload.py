"""Dedicated adapter metadata for Pixload."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("tool", str, "png", "Pixload image tool: bmp, gif, jpg, png, or webp."),
        AdapterParameterSpec("payload", str, "", "Payload string for injection (-P/--payload)."),
        AdapterParameterSpec("pixel_width", int, 0, "Pixel width for GIF/PNG where supported; 0 leaves default."),
        AdapterParameterSpec("pixel_height", int, 0, "Pixel height for GIF/PNG where supported; 0 leaves default."),
        AdapterParameterSpec("section", str, "", "JPEG section for payload injection: com or dqt."),
        AdapterParameterSpec("help", bool, False, "Show selected pixload tool help."),
        AdapterParameterSpec("version", bool, False, "Show selected pixload tool version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tool = str(kwargs.get("tool") or "png").strip().lower().replace("pixload-", "")
    if tool not in {"bmp", "gif", "jpg", "png", "webp"}:
        tool = "png"

    tokens: list[str] = [f"pixload-{tool}"]
    add_value(tokens, kwargs, "section", "-S")
    add_value(tokens, kwargs, "pixel_width", "-W")
    add_value(tokens, kwargs, "pixel_height", "-H")
    add_value(tokens, kwargs, "payload", "-P")
    add_bool(tokens, kwargs, "version", "-v")
    add_bool(tokens, kwargs, "help", "-h")
    return tokens
