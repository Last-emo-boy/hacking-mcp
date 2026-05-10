"""Dedicated adapter metadata for StegoCracker."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_image", str, "", "Image file path for --input."),
        AdapterParameterSpec("output_image", str, "", "Encoded/output image path for --output."),
        AdapterParameterSpec("message", str, "", "Message to encode."),
        AdapterParameterSpec("read_from", str, "", "Image path to read/decode a message from."),
        AdapterParameterSpec("encode", bool, False, "Enable encoding mode."),
        AdapterParameterSpec("decode", bool, False, "Enable decoding mode."),
        AdapterParameterSpec("music_file", str, "", "Audio file path for encoding, decoding, or conversion."),
        AdapterParameterSpec("output_music", str, "", "Output audio file path."),
        AdapterParameterSpec("convert", bool, False, "Convert an MP3 file to WAV."),
        AdapterParameterSpec("version", bool, False, "Show version."),
        AdapterParameterSpec("update", bool, False, "Update StegoCracker."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    target = kwargs.get("target")
    if kwargs.get("input_image"):
        add_value(tokens, kwargs, "input_image", "--input")
    elif target and kwargs.get("encode") and not kwargs.get("music_file"):
        tokens.extend(["--input", str(target)])
    add_value(tokens, kwargs, "output_image", "--output")
    add_value(tokens, kwargs, "message", "--message")
    if kwargs.get("read_from"):
        add_value(tokens, kwargs, "read_from", "--read")
    elif target and kwargs.get("decode") and not kwargs.get("music_file"):
        tokens.extend(["--read", str(target)])
    add_bool(tokens, kwargs, "encode", "--encode")
    add_bool(tokens, kwargs, "decode", "--decode")
    if kwargs.get("music_file"):
        add_value(tokens, kwargs, "music_file", "--file")
    elif target and kwargs.get("convert"):
        tokens.extend(["--file", str(target)])
    add_value(tokens, kwargs, "output_music", "--outfile")
    add_bool(tokens, kwargs, "convert", "--convert")
    add_bool(tokens, kwargs, "version", "--version")
    add_bool(tokens, kwargs, "update", "--update")
    return tokens
