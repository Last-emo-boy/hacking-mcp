"""Dedicated adapter metadata for Cupp."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("interactive", bool, False, "Run interactive password profiling mode (-i)."),
        AdapterParameterSpec("improve_file", str, "", "Improve an existing dictionary with -w FILENAME."),
        AdapterParameterSpec("download_wordlist", bool, False, "Download wordlists from the configured repository (-l)."),
        AdapterParameterSpec("alecto", bool, False, "Parse default usernames and passwords from Alecto DB (-a)."),
        AdapterParameterSpec("version", bool, False, "Show CUPP version (-v)."),
        AdapterParameterSpec("quiet", bool, False, "Suppress the banner (-q)."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "quiet", "-q")
    add_bool(tokens, kwargs, "interactive", "-i")
    add_value(tokens, kwargs, "improve_file", "-w")
    add_bool(tokens, kwargs, "download_wordlist", "-l")
    add_bool(tokens, kwargs, "alecto", "-a")
    add_bool(tokens, kwargs, "version", "-v")
    return tokens
