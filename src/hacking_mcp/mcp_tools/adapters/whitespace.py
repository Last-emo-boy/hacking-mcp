"""Dedicated adapter metadata for snow whitespace steganography."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("compress", bool, False, "Compress when concealing or uncompress when extracting."),
        AdapterParameterSpec("quiet", bool, False, "Suppress statistics output."),
        AdapterParameterSpec("space_report", bool, False, "Report approximate hidden-message capacity."),
        AdapterParameterSpec("password", str, "", "Password for ICE encryption/decryption."),
        AdapterParameterSpec("line_length", int, 0, "Maximum line length for appended whitespace."),
        AdapterParameterSpec("message_file", str, "", "File containing the message to conceal."),
        AdapterParameterSpec("message", str, "", "Message string to conceal."),
        AdapterParameterSpec("input_file", str, "", "Input text/stego file."),
        AdapterParameterSpec("output_file", str, "", "Output file for conceal/extract result."),
        AdapterParameterSpec("version", bool, False, "Show snow version/usage information."),
        AdapterParameterSpec("help", bool, False, "Show snow help/usage information."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "compress", "-C")
    add_bool(tokens, kwargs, "quiet", "-Q")
    add_bool(tokens, kwargs, "space_report", "-S")
    add_bool(tokens, kwargs, "version", "-V")
    add_bool(tokens, kwargs, "help", "-h")
    add_value(tokens, kwargs, "password", "-p")
    add_value(tokens, kwargs, "line_length", "-l")
    add_value(tokens, kwargs, "message_file", "-f")
    add_value(tokens, kwargs, "message", "-m")
    for key in ("input_file", "output_file"):
        value = kwargs.get(key)
        if value not in (None, "", 0, False):
            tokens.append(str(value))
    return tokens
