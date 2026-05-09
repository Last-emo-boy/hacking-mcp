"""Dedicated adapter metadata for steghide."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("command", str, "", "Steghide command: embed, extract, info, encinfo, version, license, or help."),
        AdapterParameterSpec("extract", bool, False, "Backward-compatible shortcut for command=extract."),
        AdapterParameterSpec("embed_file", str, "", "File containing secret data to embed."),
        AdapterParameterSpec("cover_file", str, "", "Cover file used for embedding or info."),
        AdapterParameterSpec("stego_file", str, "", "Stego file to create or extract from."),
        AdapterParameterSpec("extract_file", str, "", "Output file for extracted data."),
        AdapterParameterSpec("output_file", str, "", "Backward-compatible alias for extract_file."),
        AdapterParameterSpec("encryption", str, "", "Encryption algorithm or mode, for example rijndael-128 or none."),
        AdapterParameterSpec("compression_level", int, 0, "Compression level 1-9; 0 leaves default."),
        AdapterParameterSpec("no_compress", bool, False, "Do not compress secret data before embedding."),
        AdapterParameterSpec("no_checksum", bool, False, "Do not embed a CRC32 checksum."),
        AdapterParameterSpec("no_embed_name", bool, False, "Do not embed the original secret filename."),
        AdapterParameterSpec("passphrase", str, "", "Passphrase for embed, extract, or info."),
        AdapterParameterSpec("verbose", bool, False, "Display detailed operation status."),
        AdapterParameterSpec("quiet", bool, False, "Suppress information messages."),
        AdapterParameterSpec("force", bool, False, "Overwrite existing files."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = [_command(kwargs)]
    target = str(kwargs.get("target") or "")

    embed_file = kwargs.get("embed_file")
    cover_file = kwargs.get("cover_file")
    stego_file = kwargs.get("stego_file")

    command = tokens[0]
    if target:
        if command == "info" and not cover_file and not stego_file:
            tokens.append(target)
        elif command == "extract" and not stego_file:
            stego_file = target
        elif command == "embed" and not cover_file:
            cover_file = target

    _add_direct_value(tokens, embed_file, "--embedfile")
    _add_direct_value(tokens, cover_file, "--coverfile")
    _add_direct_value(tokens, stego_file, "--stegofile")
    add_value(tokens, kwargs, "extract_file", "--extractfile")
    if not kwargs.get("extract_file"):
        add_value(tokens, kwargs, "output_file", "--extractfile")
    add_value(tokens, kwargs, "encryption", "--encryption")
    add_value(tokens, kwargs, "compression_level", "--compress")
    add_bool(tokens, kwargs, "no_compress", "--dontcompress")
    add_bool(tokens, kwargs, "no_checksum", "--nochecksum")
    add_bool(tokens, kwargs, "no_embed_name", "--dontembedname")
    add_value(tokens, kwargs, "passphrase", "--passphrase")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_bool(tokens, kwargs, "force", "--force")
    return tokens


def _command(kwargs: dict) -> str:
    command = str(kwargs.get("command") or "").strip()
    if command:
        return command
    if kwargs.get("extract"):
        return "extract"
    return "info"


def _add_direct_value(tokens: list[str], value: object, flag: str) -> None:
    if value in (None, "", 0, False):
        return
    tokens.extend([flag, str(value)])
