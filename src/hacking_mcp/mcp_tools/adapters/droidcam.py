"""Dedicated adapter metadata for DroidCam/WishFish."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "WishFish starts an interactive camera-capture phishing tunnel flow.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
