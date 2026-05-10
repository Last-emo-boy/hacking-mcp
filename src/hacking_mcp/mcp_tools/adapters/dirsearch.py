"""Dedicated adapter metadata for dirsearch."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "", "Wordlist path."),
        AdapterParameterSpec("extensions", str, "", "Comma-separated extensions."),
        AdapterParameterSpec("include_status", str, "", "Status codes to include."),
        AdapterParameterSpec("exclude_status", str, "", "Status codes to exclude."),
        AdapterParameterSpec("exclude_sizes", str, "", "Response sizes to exclude."),
        AdapterParameterSpec("exclude_text", str, "", "Text to exclude from responses."),
        AdapterParameterSpec("exclude_regex", str, "", "Regex to exclude from responses."),
        AdapterParameterSpec("prefixes", str, "", "Prefixes to add to paths."),
        AdapterParameterSpec("suffixes", str, "", "Suffixes to add to paths."),
        AdapterParameterSpec("threads", int, 0, "Number of threads; 0 leaves default."),
        AdapterParameterSpec("recursive", bool, False, "Enable recursive scanning."),
        AdapterParameterSpec("deep_recursive", bool, False, "Enable deep recursive scanning."),
        AdapterParameterSpec("force_recursive", bool, False, "Force recursive scanning."),
        AdapterParameterSpec("recursion_depth", int, 0, "Maximum recursion depth; 0 leaves default."),
        AdapterParameterSpec("recursion_status", str, "", "Status codes that trigger recursion."),
        AdapterParameterSpec("subdirs", str, "", "Subdirectories to scan."),
        AdapterParameterSpec("exclude_subdirs", str, "", "Subdirectories to exclude."),
        AdapterParameterSpec("method", str, "", "HTTP method."),
        AdapterParameterSpec("data", str, "", "HTTP request body."),
        AdapterParameterSpec("headers", str, "", "Custom HTTP header."),
        AdapterParameterSpec("header_list", str, "", "File containing headers."),
        AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects."),
        AdapterParameterSpec("random_agent", bool, False, "Use a random User-Agent."),
        AdapterParameterSpec("user_agent", str, "", "Custom HTTP User-Agent."),
        AdapterParameterSpec("cookies", str, "", "Cookie header value."),
        AdapterParameterSpec("proxy", str, "", "Proxy URL."),
        AdapterParameterSpec("proxy_list", str, "", "File containing proxies."),
        AdapterParameterSpec("timeout", int, 0, "Connection timeout; 0 leaves default."),
        AdapterParameterSpec("delay", str, "", "Delay between requests."),
        AdapterParameterSpec("max_rate", int, 0, "Maximum requests per second; 0 leaves default."),
        AdapterParameterSpec("retries", int, 0, "Number of retries; 0 leaves default."),
        AdapterParameterSpec("format", str, "", "Report format."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("json_report", str, "", "JSON report output path."),
        AdapterParameterSpec("plain_text_report", str, "", "Plain text report output path."),
        AdapterParameterSpec("csv_report", str, "", "CSV report output path."),
        AdapterParameterSpec("markdown_report", str, "", "Markdown report output path."),
        AdapterParameterSpec("xml_report", str, "", "XML report output path."),
        AdapterParameterSpec("sqlite_report", str, "", "SQLite report output path."),
        AdapterParameterSpec("quiet", bool, False, "Quiet mode."),
        AdapterParameterSpec("full_url", bool, False, "Show full URLs in output."),
        AdapterParameterSpec("no_color", bool, False, "Disable colored output."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "wordlist", "-w")
    add_value(tokens, kwargs, "extensions", "-e")
    add_value(tokens, kwargs, "include_status", "-i")
    add_value(tokens, kwargs, "exclude_status", "-x")
    add_value(tokens, kwargs, "exclude_sizes", "-X")
    add_value(tokens, kwargs, "exclude_text", "--exclude-text")
    add_value(tokens, kwargs, "exclude_regex", "--exclude-regex")
    add_value(tokens, kwargs, "prefixes", "--prefixes")
    add_value(tokens, kwargs, "suffixes", "--suffixes")
    add_value(tokens, kwargs, "threads", "-t")
    add_bool(tokens, kwargs, "recursive", "-r")
    add_bool(tokens, kwargs, "deep_recursive", "--deep-recursive")
    add_bool(tokens, kwargs, "force_recursive", "--force-recursive")
    add_value(tokens, kwargs, "recursion_depth", "-R")
    add_value(tokens, kwargs, "recursion_status", "--recursion-status")
    add_value(tokens, kwargs, "subdirs", "--subdirs")
    add_value(tokens, kwargs, "exclude_subdirs", "--exclude-subdirs")
    add_value(tokens, kwargs, "method", "-m")
    add_value(tokens, kwargs, "data", "-d")
    add_value(tokens, kwargs, "headers", "-H")
    add_value(tokens, kwargs, "header_list", "--header-list")
    add_bool(tokens, kwargs, "follow_redirects", "-F")
    add_bool(tokens, kwargs, "random_agent", "--random-agent")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_value(tokens, kwargs, "cookies", "--cookie")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_value(tokens, kwargs, "proxy_list", "--proxy-list")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "delay", "--delay")
    add_value(tokens, kwargs, "max_rate", "--max-rate")
    add_value(tokens, kwargs, "retries", "--retries")
    add_value(tokens, kwargs, "format", "--format")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "json_report", "--json-report")
    add_value(tokens, kwargs, "plain_text_report", "--plain-text-report")
    add_value(tokens, kwargs, "csv_report", "--csv-report")
    add_value(tokens, kwargs, "markdown_report", "--md-report")
    add_value(tokens, kwargs, "xml_report", "--xml-report")
    add_value(tokens, kwargs, "sqlite_report", "--sqlite-report")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_bool(tokens, kwargs, "full_url", "--full-url")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    return tokens
