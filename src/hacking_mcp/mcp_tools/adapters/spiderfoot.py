"""Dedicated adapter metadata for SpiderFoot."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("debug", bool, False, "Enable debug output."),
        AdapterParameterSpec("listen", str, "", "IP:port for the web UI listener."),
        AdapterParameterSpec("modules", str, "", "Comma-separated modules to enable."),
        AdapterParameterSpec("list_modules", bool, False, "List available modules."),
        AdapterParameterSpec("correlate", str, "", "Run correlation rules against a scan ID."),
        AdapterParameterSpec("event_types", str, "", "Comma-separated event types to collect."),
        AdapterParameterSpec("use_case", str, "", "Automatic module use case: all, footprint, investigate, or passive."),
        AdapterParameterSpec("list_types", bool, False, "List available event types."),
        AdapterParameterSpec("output_format", str, "", "Output format: tab, csv, or json."),
        AdapterParameterSpec("no_headers", bool, False, "Do not print field headers."),
        AdapterParameterSpec("strip_newlines", bool, False, "Strip newlines from output data."),
        AdapterParameterSpec("include_source", bool, False, "Include source data in tab/csv output."),
        AdapterParameterSpec("max_data_length", int, 0, "Maximum data length to display; 0 leaves default."),
        AdapterParameterSpec("delimiter", str, "", "CSV delimiter."),
        AdapterParameterSpec("filter", bool, False, "Filter out event types not requested with -t."),
        AdapterParameterSpec("show_event_types", str, "", "Only show these event types, comma-separated."),
        AdapterParameterSpec("strict_mode", bool, False, "Enable strict mode for directly consuming modules."),
        AdapterParameterSpec("quiet", bool, False, "Disable logging."),
        AdapterParameterSpec("version", bool, False, "Display SpiderFoot version and exit."),
        AdapterParameterSpec("max_threads", int, 0, "Maximum modules to run concurrently; 0 leaves default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "debug", "--debug")
    add_value(tokens, kwargs, "listen", "-l")
    add_value(tokens, kwargs, "modules", "-m")
    add_bool(tokens, kwargs, "list_modules", "--modules")
    add_value(tokens, kwargs, "correlate", "--correlate")
    add_value(tokens, kwargs, "event_types", "-t")
    add_value(tokens, kwargs, "use_case", "-u")
    add_bool(tokens, kwargs, "list_types", "--types")
    add_value(tokens, kwargs, "output_format", "-o")
    add_bool(tokens, kwargs, "no_headers", "-H")
    add_bool(tokens, kwargs, "strip_newlines", "-n")
    add_bool(tokens, kwargs, "include_source", "-r")
    add_value(tokens, kwargs, "max_data_length", "-S")
    add_value(tokens, kwargs, "delimiter", "-D")
    add_bool(tokens, kwargs, "filter", "-f")
    add_value(tokens, kwargs, "show_event_types", "-F")
    add_bool(tokens, kwargs, "strict_mode", "-x")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_bool(tokens, kwargs, "version", "--version")
    add_value(tokens, kwargs, "max_threads", "-max-threads")
    return tokens
