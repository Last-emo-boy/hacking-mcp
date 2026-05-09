"""Dedicated adapter metadata for Binwalk."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("list_signatures", bool, False, "List supported signatures and extractors."),
        AdapterParameterSpec("stdin", bool, False, "Read data from standard input."),
        AdapterParameterSpec("quiet", bool, False, "Suppress normal stdout output."),
        AdapterParameterSpec("verbose", bool, False, "Show all results during recursive extraction."),
        AdapterParameterSpec("extract", bool, False, "Automatically extract known file types."),
        AdapterParameterSpec("carve", bool, False, "Carve known and unknown file contents to disk."),
        AdapterParameterSpec("matryoshka", bool, False, "Recursively scan extracted files."),
        AdapterParameterSpec("search_all", bool, False, "Search for all signatures at all offsets."),
        AdapterParameterSpec("entropy", bool, False, "Generate an entropy graph."),
        AdapterParameterSpec("png_output", str, "", "PNG output path for the entropy graph."),
        AdapterParameterSpec("log_file", str, "", "JSON log output file, or '-' for stdout."),
        AdapterParameterSpec("threads", int, 0, "Number of worker threads; 0 leaves default."),
        AdapterParameterSpec("exclude", str, "", "Comma-separated signatures to skip."),
        AdapterParameterSpec("include", str, "", "Comma-separated signatures to scan for."),
        AdapterParameterSpec("output_dir", str, "", "Custom extraction directory."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "list_signatures", "--list")
    add_bool(tokens, kwargs, "stdin", "--stdin")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "extract", "--extract")
    add_bool(tokens, kwargs, "carve", "--carve")
    add_bool(tokens, kwargs, "matryoshka", "--matryoshka")
    add_bool(tokens, kwargs, "search_all", "--search-all")
    add_bool(tokens, kwargs, "entropy", "--entropy")
    add_value(tokens, kwargs, "png_output", "--png")
    add_value(tokens, kwargs, "log_file", "--log")
    add_value(tokens, kwargs, "threads", "--threads")
    add_value(tokens, kwargs, "exclude", "--exclude")
    add_value(tokens, kwargs, "include", "--include")
    add_value(tokens, kwargs, "output_dir", "--directory")
    return tokens
