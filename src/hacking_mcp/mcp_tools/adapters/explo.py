"""Dedicated adapter metadata for Explo."""

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
        AdapterParameterSpec("data", str, "", "Optional POST body or data string."),
        AdapterParameterSpec("dbms", str, "", "Force DBMS fingerprint, for example MySQL or PostgreSQL."),
        AdapterParameterSpec("risk", int, 0, "Risk level 1-3 when supported; 0 leaves default."),
        AdapterParameterSpec("level", int, 0, "Test level 1-5 when supported; 0 leaves default."),
        AdapterParameterSpec("enumerate_databases", bool, False, "Request database enumeration when supported."),
        AdapterParameterSpec("parameter", str, "", "Parameter to test when supported."),
        AdapterParameterSpec("method", str, "", "HTTP method when supported."),
        AdapterParameterSpec("delay", int, 0, "Time delay for blind testing when supported; 0 leaves default."),
        AdapterParameterSpec("os_shell", bool, False, "Request OS shell mode when supported."),
        AdapterParameterSpec("batch", bool, True, "Non-interactive/batch mode when supported."),
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
    add_value(tokens, kwargs, "data", "--data")
    add_value(tokens, kwargs, "dbms", "--dbms")
    add_value(tokens, kwargs, "risk", "--risk")
    add_value(tokens, kwargs, "level", "--level")
    add_bool(tokens, kwargs, "enumerate_databases", "--dbs")
    add_value(tokens, kwargs, "parameter", "-p")
    add_value(tokens, kwargs, "method", "--method")
    add_value(tokens, kwargs, "delay", "--time-sec")
    add_bool(tokens, kwargs, "os_shell", "--os-shell")
    if kwargs.get("batch", True):
        tokens.append("--batch")
    return tokens
