"""Dedicated adapter metadata for pspy."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("procevents", bool, True, "Print new processes to stdout."),
        AdapterParameterSpec("fsevents", bool, False, "Print file system events to stdout."),
        AdapterParameterSpec("recursive_dirs", str, "", "Comma-separated directories to watch recursively."),
        AdapterParameterSpec("dirs", str, "", "Comma-separated directories to watch non-recursively."),
        AdapterParameterSpec("interval", int, 0, "Procfs scan interval in milliseconds; 0 leaves default."),
        AdapterParameterSpec("color", bool, True, "Color printed process events."),
        AdapterParameterSpec("debug", bool, False, "Print detailed error messages."),
        AdapterParameterSpec("ppid", bool, False, "Record process parent PIDs."),
        AdapterParameterSpec("truncate", int, 0, "Maximum process command length; 0 leaves default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    _add_default_true_bool(tokens, kwargs, "procevents", "--procevents")
    add_bool(tokens, kwargs, "fsevents", "--fsevents")
    _add_repeated_values(tokens, kwargs, "recursive_dirs", "--recursive_dirs")
    _add_repeated_values(tokens, kwargs, "dirs", "--dirs")
    add_value(tokens, kwargs, "interval", "--interval")
    _add_default_true_bool(tokens, kwargs, "color", "--color")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "ppid", "--ppid")
    add_value(tokens, kwargs, "truncate", "--truncate")
    return tokens


def _add_default_true_bool(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    if kwargs.get(key) is False:
        tokens.append(f"{flag}=false")


def _add_repeated_values(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    values = str(kwargs.get(key) or "")
    for value in (item.strip() for item in values.split(",")):
        if value:
            tokens.extend([flag, value])
