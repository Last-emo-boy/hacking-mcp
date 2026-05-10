"""Dedicated adapter metadata for Explo."""

import shlex

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "extra_files",
            str,
            "",
            "Additional testcase YAML files to process after the target file, separated by spaces or commas.",
        ),
        AdapterParameterSpec("verbose", bool, False, "Enable upstream -v/--verbose output."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    _add_extra_files(tokens, kwargs)
    add_bool(tokens, kwargs, "verbose", "--verbose")
    return tokens


def _add_extra_files(tokens: list[str], kwargs: dict) -> None:
    value = kwargs.get("extra_files")
    if value in (None, "", False):
        return
    raw = str(value).replace(",", " ")
    try:
        tokens.extend(shlex.split(raw))
    except ValueError:
        tokens.extend(raw.split())
