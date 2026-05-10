"""Dedicated adapter metadata for Havoc."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("command", str, "server", "Havoc subcommand: server or client."),
        AdapterParameterSpec("profile", str, "", "Teamserver profile path for the server command."),
        AdapterParameterSpec("default_profile", bool, False, "Use the bundled default teamserver profile."),
        AdapterParameterSpec("debug", bool, False, "Enable teamserver debug logging."),
        AdapterParameterSpec("debug_dev", bool, False, "Compile agents with developer debug mode enabled."),
        AdapterParameterSpec("send_logs", bool, False, "Have agents send logs over HTTP(S) to the teamserver."),
        AdapterParameterSpec("verbose", bool, False, "Show verbose teamserver messages."),
        AdapterParameterSpec("help", bool, False, "Show help for the selected Havoc command."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    command = str(kwargs.get("command") or "server").strip() or "server"
    tokens.append(command)

    if command == "server":
        if kwargs.get("default_profile"):
            tokens.append("--default")
        else:
            add_value(tokens, kwargs, "profile", "--profile")
        add_bool(tokens, kwargs, "debug", "--debug")
        add_bool(tokens, kwargs, "debug_dev", "--debug-dev")
        add_bool(tokens, kwargs, "send_logs", "--send-logs")
        add_bool(tokens, kwargs, "verbose", "--verbose")

    if kwargs.get("help"):
        tokens.append("--help")
    return tokens
