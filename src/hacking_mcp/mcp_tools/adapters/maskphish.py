"""Dedicated adapter metadata for Maskphish."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value
from hacking_mcp.mcp_tools.adapters.phishing_common import phishing_options, phishing_parameters


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "", "Wordlist path for discovery or fuzzing tools."),
        AdapterParameterSpec("threads", int, 0, "Worker/thread count when supported; 0 leaves default."),
        AdapterParameterSpec("extensions", str, "", "Comma-separated extensions such as php,js,txt."),
        AdapterParameterSpec("match_codes", str, "", "HTTP status codes to match or include."),
        AdapterParameterSpec("recursive", bool, False, "Enable recursive discovery when supported."),
        AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects when supported."),
        AdapterParameterSpec("proxy", str, "", "Optional HTTP proxy URL."),
        *phishing_parameters(),
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
    tokens.extend(phishing_options(kwargs))
    return tokens
