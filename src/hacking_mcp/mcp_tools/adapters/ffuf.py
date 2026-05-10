"""Dedicated adapter metadata for ffuf."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "", "Wordlist path for discovery or fuzzing tools."),
        AdapterParameterSpec("threads", int, 0, "Worker/thread count when supported; 0 leaves default."),
        AdapterParameterSpec("extensions", str, "", "Comma-separated extensions such as php,js,txt."),
        AdapterParameterSpec("match_codes", str, "", "HTTP status codes to match or include."),
        AdapterParameterSpec("recursive", bool, False, "Enable recursive discovery when supported."),
        AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects when supported."),
        AdapterParameterSpec("proxy", str, "", "Optional HTTP proxy URL."),
        AdapterParameterSpec("fuzz_keyword", str, "", "Fuzz marker keyword when supported, for example FUZZ."),
        AdapterParameterSpec("host_header", str, "", "Host header for vhost fuzzing when supported."),
        AdapterParameterSpec("recursion_depth", int, 0, "Recursive discovery depth when supported; 0 leaves default."),
        AdapterParameterSpec("filter_codes", str, "", "HTTP status codes to filter out."),
        AdapterParameterSpec("filter_size", str, "", "Response size filter when supported."),
        AdapterParameterSpec("filter_words", str, "", "Word-count filter when supported."),
        AdapterParameterSpec("add_slash", bool, False, "Append trailing slash to discovered paths when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "wordlist", "-w")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "extensions", "-e")
    add_value(tokens, kwargs, "match_codes", "-mc")
    add_bool(tokens, kwargs, "recursive", "-recursion")
    add_bool(tokens, kwargs, "follow_redirects", "-r")
    add_value(tokens, kwargs, "proxy", "-proxy")
    add_value(tokens, kwargs, "host_header", "-H")
    add_value(tokens, kwargs, "recursion_depth", "-recursion-depth")
    add_value(tokens, kwargs, "filter_codes", "-fc")
    add_value(tokens, kwargs, "filter_size", "-fs")
    add_value(tokens, kwargs, "filter_words", "-fw")
    add_bool(tokens, kwargs, "add_slash", "--add-slash")
    return tokens
