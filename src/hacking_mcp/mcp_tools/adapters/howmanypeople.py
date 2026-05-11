"""Dedicated adapter metadata for howmanypeoplearearound."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters():
    return [
        AdapterParameterSpec("adapter", str, "", "WiFi adapter to use."),
        AdapterParameterSpec("analyze", str, "", "Analyze a saved capture/data file."),
        AdapterParameterSpec("scantime", int, 0, "Scan time in seconds; 0 leaves upstream default."),
        AdapterParameterSpec("output_file", str, "", "Write cellphone data to file."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose mode."),
        AdapterParameterSpec("number", bool, False, "Only print the estimated number."),
        AdapterParameterSpec("json_output", bool, False, "Print JSON cellphone data."),
        AdapterParameterSpec("nearby", bool, False, "Only quantify nearby signals."),
        AdapterParameterSpec("nocorrection", bool, False, "Disable count correction."),
        AdapterParameterSpec("loop", bool, False, "Loop forever."),
        AdapterParameterSpec("sort", bool, False, "Sort cellphone data by RSSI distance."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "adapter", "--adapter")
    add_value(tokens, kwargs, "analyze", "--analyze")
    add_value(tokens, kwargs, "scantime", "--scantime")
    add_value(tokens, kwargs, "output_file", "--out")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "number", "--number")
    add_bool(tokens, kwargs, "json_output", "--jsonprint")
    add_bool(tokens, kwargs, "nearby", "--nearby")
    add_bool(tokens, kwargs, "nocorrection", "--nocorrection")
    add_bool(tokens, kwargs, "loop", "--loop")
    add_bool(tokens, kwargs, "sort", "--sort")
    return tokens
