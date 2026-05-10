"""Dedicated adapter metadata for sqlmap."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("data", str, "", "Optional POST body or data string."),
        AdapterParameterSpec("method", str, "", "Force HTTP method, for example PUT."),
        AdapterParameterSpec("cookie", str, "", "HTTP Cookie header value."),
        AdapterParameterSpec("headers", str, "", "Extra HTTP headers."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent header value."),
        AdapterParameterSpec("referer", str, "", "HTTP Referer header value."),
        AdapterParameterSpec("auth_type", str, "", "HTTP authentication type."),
        AdapterParameterSpec("auth_cred", str, "", "HTTP authentication credentials."),
        AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
        AdapterParameterSpec("delay", str, "", "Delay in seconds between HTTP requests."),
        AdapterParameterSpec("timeout", str, "", "Connection timeout in seconds."),
        AdapterParameterSpec("retries", int, 0, "Connection retry count; 0 leaves default."),
        AdapterParameterSpec("csrf_token", str, "", "Anti-CSRF token parameter name."),
        AdapterParameterSpec("random_agent", bool, False, "Use a random User-Agent."),
        AdapterParameterSpec("parameter", str, "", "Testable parameter or parameters."),
        AdapterParameterSpec("skip", str, "", "Parameter or parameters to skip."),
        AdapterParameterSpec("dbms", str, "", "Force DBMS fingerprint, for example MySQL or PostgreSQL."),
        AdapterParameterSpec("dbms_cred", str, "", "DBMS authentication credentials."),
        AdapterParameterSpec("risk", int, 0, "Risk level 1-3 when supported; 0 leaves default."),
        AdapterParameterSpec("level", int, 0, "Test level 1-5 when supported; 0 leaves default."),
        AdapterParameterSpec("tamper", str, "", "Comma-separated sqlmap tamper scripts."),
        AdapterParameterSpec("technique", str, "", "SQLi techniques, for example BEUSTQ."),
        AdapterParameterSpec("enumerate_databases", bool, False, "Enumerate DBMS databases."),
        AdapterParameterSpec("tables", bool, False, "Enumerate DBMS database tables."),
        AdapterParameterSpec("columns", bool, False, "Enumerate DBMS database columns."),
        AdapterParameterSpec("dump", bool, False, "Dump DBMS database table entries."),
        AdapterParameterSpec("os_cmd", str, "", "Execute an operating system command."),
        AdapterParameterSpec("os_shell", bool, False, "Prompt for an interactive OS shell."),
        AdapterParameterSpec("threads", int, 0, "Max concurrent HTTP requests; 0 leaves default."),
        AdapterParameterSpec("forms", bool, False, "Parse and test forms on target URL."),
        AdapterParameterSpec("crawl", int, 0, "Crawl depth; 0 disables."),
        AdapterParameterSpec("flush_session", bool, False, "Flush local session files for target."),
        AdapterParameterSpec("output_dir", str, "", "Custom output directory path."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "data", "--data")
    add_value(tokens, kwargs, "method", "--method")
    add_value(tokens, kwargs, "cookie", "--cookie")
    add_value(tokens, kwargs, "headers", "--headers")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_value(tokens, kwargs, "referer", "--referer")
    add_value(tokens, kwargs, "auth_type", "--auth-type")
    add_value(tokens, kwargs, "auth_cred", "--auth-cred")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_value(tokens, kwargs, "delay", "--delay")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "retries", "--retries")
    add_value(tokens, kwargs, "csrf_token", "--csrf-token")
    add_value(tokens, kwargs, "parameter", "-p")
    add_value(tokens, kwargs, "skip", "--skip")
    add_value(tokens, kwargs, "dbms", "--dbms")
    add_value(tokens, kwargs, "dbms_cred", "--dbms-cred")
    add_value(tokens, kwargs, "risk", "--risk")
    add_value(tokens, kwargs, "level", "--level")
    add_value(tokens, kwargs, "tamper", "--tamper")
    add_value(tokens, kwargs, "technique", "--technique")
    add_bool(tokens, kwargs, "random_agent", "--random-agent")
    add_bool(tokens, kwargs, "enumerate_databases", "--dbs")
    add_bool(tokens, kwargs, "tables", "--tables")
    add_bool(tokens, kwargs, "columns", "--columns")
    add_bool(tokens, kwargs, "dump", "--dump")
    add_value(tokens, kwargs, "os_cmd", "--os-cmd")
    add_bool(tokens, kwargs, "os_shell", "--os-shell")
    add_value(tokens, kwargs, "threads", "--threads")
    add_bool(tokens, kwargs, "forms", "--forms")
    add_value(tokens, kwargs, "crawl", "--crawl")
    add_bool(tokens, kwargs, "flush_session", "--flush-session")
    add_value(tokens, kwargs, "output_dir", "--output-dir")
    return tokens
