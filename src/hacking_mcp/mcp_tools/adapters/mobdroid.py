"""Dedicated adapter metadata for Mob-Droid."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_assignment, add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("payload_type", str, "", "Payload identifier when supported."),
        AdapterParameterSpec("platform", str, "", "Target platform when supported."),
        AdapterParameterSpec("architecture", str, "", "Target architecture when supported."),
        AdapterParameterSpec("lhost", str, "", "Listener host for authorized lab use."),
        AdapterParameterSpec("lport", int, 0, "Listener port when supported; 0 leaves default."),
        AdapterParameterSpec("format", str, "", "Output format when supported."),
        AdapterParameterSpec("encoder", str, "", "Encoder when supported."),
        AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
        AdapterParameterSpec("apk_path", str, "", "APK path when supported."),
        AdapterParameterSpec("package_name", str, "", "Android package name when supported."),
        AdapterParameterSpec("stager", str, "", "Stager/profile selector when supported."),
        AdapterParameterSpec("listener_name", str, "", "Listener/profile name when supported."),
        AdapterParameterSpec("apk_name", str, "", "APK/app output name when supported."),
        AdapterParameterSpec("bundle_id", str, "", "Mobile bundle/package id when supported."),
        AdapterParameterSpec("sign_apk", bool, False, "Sign APK output when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "payload_type", "-p")
    add_value(tokens, kwargs, "platform", "--platform")
    add_value(tokens, kwargs, "architecture", "-a")
    add_assignment(tokens, kwargs, "lhost", "LHOST")
    add_assignment(tokens, kwargs, "lport", "LPORT")
    add_value(tokens, kwargs, "format", "-f")
    add_value(tokens, kwargs, "encoder", "-e")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "apk_path", "--apk")
    add_value(tokens, kwargs, "package_name", "--package")
    add_assignment(tokens, kwargs, "lhost", "LHOST")
    add_assignment(tokens, kwargs, "lport", "LPORT")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "stager", "--stager")
    add_value(tokens, kwargs, "listener_name", "--listener")
    add_value(tokens, kwargs, "apk_name", "--apk-name")
    add_value(tokens, kwargs, "bundle_id", "--bundle-id")
    add_bool(tokens, kwargs, "sign_apk", "--sign")
    return tokens
