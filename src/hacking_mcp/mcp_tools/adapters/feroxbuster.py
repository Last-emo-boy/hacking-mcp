"""Dedicated adapter metadata for Feroxbuster."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "", "Wordlist path or URL."),
        AdapterParameterSpec("extensions", str, "", "File extensions to search for."),
        AdapterParameterSpec("methods", str, "", "HTTP methods to send."),
        AdapterParameterSpec("data", str, "", "Request body data."),
        AdapterParameterSpec("headers", str, "", "Custom HTTP header."),
        AdapterParameterSpec("cookies", str, "", "HTTP cookies."),
        AdapterParameterSpec("query", str, "", "URL query parameter."),
        AdapterParameterSpec("add_slash", bool, False, "Append slash to request URLs."),
        AdapterParameterSpec("protocol", str, "", "Protocol for request-file/domain-only targets."),
        AdapterParameterSpec("dont_scan", str, "", "URL or regex pattern to exclude from scanning."),
        AdapterParameterSpec("scope", str, "", "Additional in-scope URL or domain."),
        AdapterParameterSpec("filter_size", str, "", "Filter responses by size."),
        AdapterParameterSpec("filter_regex", str, "", "Filter responses by regex."),
        AdapterParameterSpec("filter_words", str, "", "Filter responses by word count."),
        AdapterParameterSpec("filter_lines", str, "", "Filter responses by line count."),
        AdapterParameterSpec("filter_codes", str, "", "Filter/deny-list status codes."),
        AdapterParameterSpec("status_codes", str, "", "Allow-list status codes."),
        AdapterParameterSpec("unique", bool, False, "Only show unique responses."),
        AdapterParameterSpec("timeout", int, 0, "Client timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects."),
        AdapterParameterSpec("insecure", bool, False, "Disable TLS certificate validation."),
        AdapterParameterSpec("threads", int, 0, "Number of concurrent threads; 0 leaves default."),
        AdapterParameterSpec("no_recursion", bool, False, "Disable recursive scanning."),
        AdapterParameterSpec("depth", int, 0, "Maximum recursion depth; 0 leaves default."),
        AdapterParameterSpec("force_recursion", bool, False, "Force recursion attempts."),
        AdapterParameterSpec("dont_extract_links", bool, False, "Disable link extraction from responses."),
        AdapterParameterSpec("scan_limit", int, 0, "Total concurrent scans; 0 leaves default."),
        AdapterParameterSpec("parallelism", int, 0, "Parallel feroxbuster child scans; 0 leaves default."),
        AdapterParameterSpec("rate_limit", int, 0, "Requests per second per directory; 0 leaves default."),
        AdapterParameterSpec("response_size_limit", str, "", "Limit response body read size."),
        AdapterParameterSpec("time_limit", str, "", "Total runtime limit, for example 10m."),
        AdapterParameterSpec("auto_tune", bool, False, "Automatically lower scan rate on errors."),
        AdapterParameterSpec("auto_bail", bool, False, "Stop scanning on excessive errors."),
        AdapterParameterSpec("dont_filter", bool, False, "Disable auto-filtering wildcard responses."),
        AdapterParameterSpec("collect_extensions", bool, False, "Discover and add extensions dynamically."),
        AdapterParameterSpec("collect_backups", str, "", "Backup extensions to request."),
        AdapterParameterSpec("collect_words", bool, False, "Discover words from responses."),
        AdapterParameterSpec("dont_collect", str, "", "Extensions to ignore during collection."),
        AdapterParameterSpec("verbosity", int, 0, "Verbosity level 1-3; 0 leaves default."),
        AdapterParameterSpec("silent", bool, False, "Only print URLs or JSON output."),
        AdapterParameterSpec("quiet", bool, False, "Hide progress bars and banner."),
        AdapterParameterSpec("json_output", bool, False, "Emit JSON logs."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("debug_log", str, "", "Debug log output path."),
        AdapterParameterSpec("no_state", bool, False, "Disable state output file."),
        AdapterParameterSpec("limit_bars", int, 0, "Maximum directory scan bars; 0 leaves default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "wordlist", "-w")
    add_value(tokens, kwargs, "extensions", "-x")
    add_value(tokens, kwargs, "methods", "-m")
    add_value(tokens, kwargs, "data", "--data")
    add_value(tokens, kwargs, "headers", "-H")
    add_value(tokens, kwargs, "cookies", "-b")
    add_value(tokens, kwargs, "query", "-Q")
    add_bool(tokens, kwargs, "add_slash", "-f")
    add_value(tokens, kwargs, "protocol", "--protocol")
    add_value(tokens, kwargs, "dont_scan", "--dont-scan")
    add_value(tokens, kwargs, "scope", "--scope")
    add_value(tokens, kwargs, "filter_size", "-S")
    add_value(tokens, kwargs, "filter_regex", "-X")
    add_value(tokens, kwargs, "filter_words", "-W")
    add_value(tokens, kwargs, "filter_lines", "-N")
    add_value(tokens, kwargs, "filter_codes", "-C")
    add_value(tokens, kwargs, "status_codes", "-s")
    add_bool(tokens, kwargs, "unique", "--unique")
    add_value(tokens, kwargs, "timeout", "-T")
    add_bool(tokens, kwargs, "follow_redirects", "-r")
    add_bool(tokens, kwargs, "insecure", "-k")
    add_value(tokens, kwargs, "threads", "-t")
    add_bool(tokens, kwargs, "no_recursion", "-n")
    add_value(tokens, kwargs, "depth", "-d")
    add_bool(tokens, kwargs, "force_recursion", "--force-recursion")
    add_bool(tokens, kwargs, "dont_extract_links", "--dont-extract-links")
    add_value(tokens, kwargs, "scan_limit", "-L")
    add_value(tokens, kwargs, "parallelism", "--parallel")
    add_value(tokens, kwargs, "rate_limit", "--rate-limit")
    add_value(tokens, kwargs, "response_size_limit", "--response-size-limit")
    add_value(tokens, kwargs, "time_limit", "--time-limit")
    add_bool(tokens, kwargs, "auto_tune", "--auto-tune")
    add_bool(tokens, kwargs, "auto_bail", "--auto-bail")
    add_bool(tokens, kwargs, "dont_filter", "-D")
    add_bool(tokens, kwargs, "collect_extensions", "-E")
    add_value(tokens, kwargs, "collect_backups", "-B")
    add_bool(tokens, kwargs, "collect_words", "-g")
    add_value(tokens, kwargs, "dont_collect", "-I")
    verbosity = int_value(kwargs, "verbosity")
    if verbosity:
        tokens.append("-" + ("v" * min(verbosity, 3)))
    add_bool(tokens, kwargs, "silent", "--silent")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_bool(tokens, kwargs, "json_output", "--json")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "debug_log", "--debug-log")
    add_bool(tokens, kwargs, "no_state", "--no-state")
    add_value(tokens, kwargs, "limit_bars", "--limit-bars")
    return tokens
