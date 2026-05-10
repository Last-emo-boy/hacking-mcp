"""Dedicated adapter metadata for masscan."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("ports", str, "", "Ports or ranges to scan, for example 80,8000-8100."),
        AdapterParameterSpec("rate", int, 0, "Transmit rate in packets per second; 0 leaves default."),
        AdapterParameterSpec("config_file", str, "", "Masscan configuration file."),
        AdapterParameterSpec("echo", bool, False, "Dump current configuration and exit."),
        AdapterParameterSpec("banners", bool, False, "Grab simple banner information where supported."),
        AdapterParameterSpec("source_ip", str, "", "Source IP address for banner checks."),
        AdapterParameterSpec("source_port", int, 0, "Source port for banner checks; 0 leaves default."),
        AdapterParameterSpec("exclude_file", str, "", "File containing excluded IP ranges."),
        AdapterParameterSpec("include_file", str, "", "File containing included IP ranges."),
        AdapterParameterSpec("output_xml", str, "", "XML output file path."),
        AdapterParameterSpec("output_json", str, "", "JSON output file path."),
        AdapterParameterSpec("output_list", str, "", "List output file path."),
        AdapterParameterSpec("output_grepable", str, "", "Grepable output file path."),
        AdapterParameterSpec("output_format", str, "", "Output format, for example xml, json, list, grepable."),
        AdapterParameterSpec("output_filename", str, "", "Output filename when using output_format."),
        AdapterParameterSpec("readscan", str, "", "Read binary scan results from file."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "ports", "-p")
    add_value(tokens, kwargs, "rate", "--rate")
    add_value(tokens, kwargs, "config_file", "-c")
    add_bool(tokens, kwargs, "echo", "--echo")
    add_bool(tokens, kwargs, "banners", "--banners")
    add_value(tokens, kwargs, "source_ip", "--source-ip")
    add_value(tokens, kwargs, "source_port", "--source-port")
    add_value(tokens, kwargs, "exclude_file", "--excludefile")
    add_value(tokens, kwargs, "include_file", "--includefile")
    add_value(tokens, kwargs, "output_xml", "-oX")
    add_value(tokens, kwargs, "output_json", "-oJ")
    add_value(tokens, kwargs, "output_list", "-oL")
    add_value(tokens, kwargs, "output_grepable", "-oG")
    add_value(tokens, kwargs, "output_format", "--output-format")
    add_value(tokens, kwargs, "output_filename", "--output-filename")
    add_value(tokens, kwargs, "readscan", "--readscan")
    return tokens
