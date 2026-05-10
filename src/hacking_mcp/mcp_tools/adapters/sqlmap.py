"""Dedicated adapter metadata for sqlmap."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_assignment, add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("data", str, "", "Optional POST body or data string."),
        AdapterParameterSpec("dbms", str, "", "Force DBMS fingerprint, for example MySQL or PostgreSQL."),
        AdapterParameterSpec("risk", int, 0, "Risk level 1-3 when supported; 0 leaves default."),
        AdapterParameterSpec("level", int, 0, "Test level 1-5 when supported; 0 leaves default."),
        AdapterParameterSpec("enumerate_databases", bool, False, "Request database enumeration when supported."),
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
        AdapterParameterSpec("cookie", str, "", "Cookie header for authorized testing."),
        AdapterParameterSpec("headers", str, "", "Additional HTTP headers, newline or semicolon separated."),
        AdapterParameterSpec("tamper", str, "", "Comma-separated sqlmap tamper scripts."),
        AdapterParameterSpec("technique", str, "", "SQLi techniques, for example BEUSTQ."),
        AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
        AdapterParameterSpec("random_agent", bool, False, "Use a random User-Agent."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "data", "--data")
    add_value(tokens, kwargs, "dbms", "--dbms")
    add_value(tokens, kwargs, "risk", "--risk")
    add_value(tokens, kwargs, "level", "--level")
    add_bool(tokens, kwargs, "enumerate_databases", "--dbs")
    add_value(tokens, kwargs, "module", "--module")
    add_assignment(tokens, kwargs, "rhost", "RHOST")
    add_assignment(tokens, kwargs, "rport", "RPORT")
    add_value(tokens, kwargs, "username", "-u")
    add_value(tokens, kwargs, "password", "-p")
    add_value(tokens, kwargs, "payload", "--payload")
    add_value(tokens, kwargs, "cookie", "--cookie")
    add_value(tokens, kwargs, "headers", "--headers")
    add_value(tokens, kwargs, "tamper", "--tamper")
    add_value(tokens, kwargs, "technique", "--technique")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_bool(tokens, kwargs, "random_agent", "--random-agent")
    return tokens
