"""Dedicated adapter metadata for WebSploit."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_assignment, add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "", "Wordlist path for discovery or fuzzing tools."),
        AdapterParameterSpec("threads", int, 0, "Worker/thread count when supported; 0 leaves default."),
        AdapterParameterSpec("extensions", str, "", "Comma-separated extensions such as php,js,txt."),
        AdapterParameterSpec("match_codes", str, "", "HTTP status codes to match or include."),
        AdapterParameterSpec("recursive", bool, False, "Enable recursive discovery when supported."),
        AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects when supported."),
        AdapterParameterSpec("proxy", str, "", "Optional HTTP proxy URL."),
        AdapterParameterSpec("module", str, "", "Exploit/module path when supported."),
        AdapterParameterSpec("rhost", str, "", "Remote host when supported."),
        AdapterParameterSpec("rport", int, 0, "Remote port when supported; 0 leaves default."),
        AdapterParameterSpec("username", str, "", "Username for authorized lab use."),
        AdapterParameterSpec(
            "password",
            str,
            "",
            "Password for lab/authorized use; may be present in process/audit logs.",
        ),
        AdapterParameterSpec("payload", str, "", "Payload/profile selector when supported."),
        AdapterParameterSpec("set_options", str, "", "Comma/semicolon-separated framework option assignments."),
        AdapterParameterSpec("check_only", bool, False, "Check vulnerability without exploitation when supported."),
        AdapterParameterSpec("resource_file", str, "", "Resource/script file when supported."),
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
    add_value(tokens, kwargs, "module", "--module")
    add_assignment(tokens, kwargs, "rhost", "RHOST")
    add_assignment(tokens, kwargs, "rport", "RPORT")
    add_value(tokens, kwargs, "username", "-u")
    add_value(tokens, kwargs, "password", "-p")
    add_value(tokens, kwargs, "payload", "--payload")
    add_value(tokens, kwargs, "set_options", "--set")
    add_bool(tokens, kwargs, "check_only", "--check")
    add_value(tokens, kwargs, "resource_file", "-r")
    return tokens
