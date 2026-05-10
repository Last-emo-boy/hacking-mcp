"""Dedicated adapter metadata for Commix."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("batch", bool, True, "Use upstream --batch mode to avoid interactive prompts."),
        AdapterParameterSpec("answers", str, "", "Predefined answers, for example quit=N,follow=N."),
        AdapterParameterSpec("check_internet", bool, False, "Check internet connectivity before assessment."),
        AdapterParameterSpec("crawl", int, 0, "Crawl depth from the target URL; 0 disables."),
        AdapterParameterSpec("crawl_exclude", str, "", "Regex for pages to exclude during crawl."),
        AdapterParameterSpec("method", str, "", "Force a specific HTTP method, for example PUT or POST."),
        AdapterParameterSpec("data", str, "", "POST data string."),
        AdapterParameterSpec("host", str, "", "HTTP Host header."),
        AdapterParameterSpec("referer", str, "", "HTTP Referer header."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent header."),
        AdapterParameterSpec("random_agent", bool, False, "Use a random HTTP User-Agent."),
        AdapterParameterSpec("cookie", str, "", "HTTP Cookie header."),
        AdapterParameterSpec("headers", str, "", "Extra headers, for example Accept: */*."),
        AdapterParameterSpec("proxy", str, "", "Proxy URL."),
        AdapterParameterSpec("tor", bool, False, "Use the Tor network."),
        AdapterParameterSpec("tor_port", str, "", "Tor proxy port."),
        AdapterParameterSpec("auth_url", str, "", "Login panel URL."),
        AdapterParameterSpec("auth_data", str, "", "Login form parameters and data."),
        AdapterParameterSpec("auth_type", str, "", "HTTP authentication type: Basic, Digest, or Bearer."),
        AdapterParameterSpec("auth_cred", str, "", "HTTP authentication credentials."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("retries", int, 0, "HTTP retry count; 0 leaves default."),
        AdapterParameterSpec("parameter", str, "", "Testable parameter(s) for upstream -p."),
        AdapterParameterSpec("skip", str, "", "Parameter(s) to skip."),
        AdapterParameterSpec("prefix", str, "", "Injection payload prefix."),
        AdapterParameterSpec("suffix", str, "", "Injection payload suffix."),
        AdapterParameterSpec("technique", str, "", "Injection technique(s) to use."),
        AdapterParameterSpec("skip_technique", str, "", "Injection technique(s) to skip."),
        AdapterParameterSpec("delay", int, 0, "Delay between HTTP requests in seconds; 0 leaves default."),
        AdapterParameterSpec("time_sec", str, "", "Seconds to delay the OS response for time-based checks."),
        AdapterParameterSpec("tmp_path", str, "", "Absolute path of the web server temp directory."),
        AdapterParameterSpec("web_root", str, "", "Web server document root directory."),
        AdapterParameterSpec("alter_shell", str, "", "Alternative os-shell, for example Python."),
        AdapterParameterSpec("os_cmd", str, "", "Execute a single operating system command."),
        AdapterParameterSpec("os", str, "", "Force backend OS, for example Windows or Unix."),
        AdapterParameterSpec("tamper", str, "", "Tamper script(s) for injection data."),
        AdapterParameterSpec("level", int, 0, "Detection test level 1-3; 0 leaves default."),
        AdapterParameterSpec("skip_calc", bool, False, "Skip mathematical calculation during detection."),
        AdapterParameterSpec("skip_empty", bool, False, "Skip parameters with empty values."),
        AdapterParameterSpec("failed_tries", int, 0, "Failed injection tries for file-based technique; 0 leaves default."),
        AdapterParameterSpec("smart", bool, False, "Run thorough tests only after positive heuristics."),
        AdapterParameterSpec("ignore_dependencies", bool, False, "Ignore third-party dependency checks."),
        AdapterParameterSpec("list_tampers", bool, False, "List available tamper scripts."),
        AdapterParameterSpec("no_logging", bool, False, "Disable logging to file."),
        AdapterParameterSpec("purge", bool, False, "Safely remove Commix data directory content."),
        AdapterParameterSpec("skip_waf", bool, False, "Skip WAF/IPS heuristic detection."),
        AdapterParameterSpec("mobile", bool, False, "Imitate smartphone User-Agent."),
        AdapterParameterSpec("offline", bool, False, "Work in offline mode."),
        AdapterParameterSpec("wizard", bool, False, "Use beginner wizard interface."),
        AdapterParameterSpec("disable_coloring", bool, False, "Disable console output coloring."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    if kwargs.get("batch", True):
        tokens.append("--batch")
    add_value(tokens, kwargs, "answers", "--answers")
    add_bool(tokens, kwargs, "check_internet", "--check-internet")
    add_value(tokens, kwargs, "crawl", "--crawl")
    add_value(tokens, kwargs, "crawl_exclude", "--crawl-exclude")
    add_value(tokens, kwargs, "method", "--method")
    add_value(tokens, kwargs, "data", "--data")
    add_value(tokens, kwargs, "host", "--host")
    add_value(tokens, kwargs, "referer", "--referer")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_bool(tokens, kwargs, "random_agent", "--random-agent")
    add_value(tokens, kwargs, "cookie", "--cookie")
    add_value(tokens, kwargs, "headers", "--headers")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_bool(tokens, kwargs, "tor", "--tor")
    add_value(tokens, kwargs, "tor_port", "--tor-port")
    add_value(tokens, kwargs, "auth_url", "--auth-url")
    add_value(tokens, kwargs, "auth_data", "--auth-data")
    add_value(tokens, kwargs, "auth_type", "--auth-type")
    add_value(tokens, kwargs, "auth_cred", "--auth-cred")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "retries", "--retries")
    add_value(tokens, kwargs, "parameter", "-p")
    add_value(tokens, kwargs, "skip", "--skip")
    add_value(tokens, kwargs, "prefix", "--prefix")
    add_value(tokens, kwargs, "suffix", "--suffix")
    add_value(tokens, kwargs, "technique", "--technique")
    add_value(tokens, kwargs, "skip_technique", "--skip-technique")
    add_value(tokens, kwargs, "delay", "--delay")
    add_value(tokens, kwargs, "time_sec", "--time-sec")
    add_value(tokens, kwargs, "tmp_path", "--tmp-path")
    add_value(tokens, kwargs, "web_root", "--web-root")
    add_value(tokens, kwargs, "alter_shell", "--alter-shell")
    add_value(tokens, kwargs, "os_cmd", "--os-cmd")
    add_value(tokens, kwargs, "os", "--os")
    add_value(tokens, kwargs, "tamper", "--tamper")
    add_value(tokens, kwargs, "level", "--level")
    add_bool(tokens, kwargs, "skip_calc", "--skip-calc")
    add_bool(tokens, kwargs, "skip_empty", "--skip-empty")
    add_value(tokens, kwargs, "failed_tries", "--failed-tries")
    add_bool(tokens, kwargs, "smart", "--smart")
    add_bool(tokens, kwargs, "ignore_dependencies", "--ignore-dependencies")
    add_bool(tokens, kwargs, "list_tampers", "--list-tampers")
    add_bool(tokens, kwargs, "no_logging", "--no-logging")
    add_bool(tokens, kwargs, "purge", "--purge")
    add_bool(tokens, kwargs, "skip_waf", "--skip-waf")
    add_bool(tokens, kwargs, "mobile", "--mobile")
    add_bool(tokens, kwargs, "offline", "--offline")
    add_bool(tokens, kwargs, "wizard", "--wizard")
    add_bool(tokens, kwargs, "disable_coloring", "--disable-coloring")
    return tokens
