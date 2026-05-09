"""Dedicated adapter metadata for StegCracker."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "", "Password wordlist path; empty uses the tool default."),
        AdapterParameterSpec("output_file", str, "", "Output file for extracted data after a successful crack."),
        AdapterParameterSpec("threads", int, 0, "Concurrent cracking threads; 0 leaves default."),
        AdapterParameterSpec("chunk_size", int, 0, "Passwords loaded per thread cycle; 0 leaves default."),
        AdapterParameterSpec("quiet", bool, False, "Suppress status updates and non-password output."),
        AdapterParameterSpec("version", bool, False, "Print version and exit."),
        AdapterParameterSpec("verbose", bool, False, "Print additional debugging information."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    wordlist = kwargs.get("wordlist")
    if wordlist:
        tokens.append(str(wordlist))
    add_value(tokens, kwargs, "output_file", "--output")
    add_value(tokens, kwargs, "threads", "--threads")
    add_value(tokens, kwargs, "chunk_size", "--chunk-size")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_bool(tokens, kwargs, "version", "--version")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    return tokens
