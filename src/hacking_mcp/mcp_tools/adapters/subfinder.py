"""Dedicated adapter metadata for Subfinder."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_file", str, "", "File containing domains to enumerate."),
        AdapterParameterSpec("sources", str, "", "Comma-separated sources to use."),
        AdapterParameterSpec("exclude_sources", str, "", "Comma-separated sources to exclude."),
        AdapterParameterSpec("all_sources", bool, False, "Use all sources for enumeration."),
        AdapterParameterSpec("recursive", bool, False, "Use only sources that can handle subdomains recursively."),
        AdapterParameterSpec("active", bool, False, "Display active sources in the result."),
        AdapterParameterSpec("match", str, "", "Subdomain or list to match."),
        AdapterParameterSpec("filter", str, "", "Subdomain or list to filter."),
        AdapterParameterSpec("resolvers", str, "", "Comma-separated resolver addresses."),
        AdapterParameterSpec("resolver_file", str, "", "File containing resolver addresses."),
        AdapterParameterSpec("rate_limit", int, 0, "Maximum HTTP requests per second; 0 leaves default."),
        AdapterParameterSpec("rate_limits", str, "", "Per-provider rate limits, for example shodan=10/s."),
        AdapterParameterSpec("threads", int, 0, "Number of concurrent goroutines; 0 leaves default."),
        AdapterParameterSpec("timeout", int, 0, "Seconds before subfinder timeout; 0 leaves default."),
        AdapterParameterSpec("max_time", int, 0, "Minutes to wait for enumeration; 0 leaves default."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("json_output", bool, False, "Write JSONL output."),
        AdapterParameterSpec("output_dir", str, "", "Directory for per-host JSON output."),
        AdapterParameterSpec("collect_sources", bool, False, "Include all sources in JSON output."),
        AdapterParameterSpec("include_ip", bool, False, "Include host IPs in output."),
        AdapterParameterSpec("exclude_ip", bool, False, "Exclude IPs from JSON output."),
        AdapterParameterSpec("config_file", str, "", "Subfinder config file path."),
        AdapterParameterSpec("provider_config", str, "", "Provider config file path."),
        AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
        AdapterParameterSpec("silent", bool, False, "Show only subdomains in output."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "input_file", "-dL")
    add_value(tokens, kwargs, "sources", "-s")
    add_value(tokens, kwargs, "exclude_sources", "-es")
    add_bool(tokens, kwargs, "all_sources", "-all")
    add_bool(tokens, kwargs, "recursive", "-recursive")
    add_bool(tokens, kwargs, "active", "-active")
    add_value(tokens, kwargs, "match", "-m")
    add_value(tokens, kwargs, "filter", "-f")
    add_value(tokens, kwargs, "resolvers", "-r")
    add_value(tokens, kwargs, "resolver_file", "-rL")
    add_value(tokens, kwargs, "rate_limit", "-rl")
    add_value(tokens, kwargs, "rate_limits", "-rls")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "timeout", "-timeout")
    add_value(tokens, kwargs, "max_time", "-max-time")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "json_output", "-oJ")
    add_value(tokens, kwargs, "output_dir", "-oD")
    add_bool(tokens, kwargs, "collect_sources", "-cs")
    add_bool(tokens, kwargs, "include_ip", "-oI")
    add_bool(tokens, kwargs, "exclude_ip", "-ei")
    add_value(tokens, kwargs, "config_file", "-config")
    add_value(tokens, kwargs, "provider_config", "-pc")
    add_value(tokens, kwargs, "proxy", "-proxy")
    add_bool(tokens, kwargs, "silent", "-silent")
    add_bool(tokens, kwargs, "verbose", "-v")
    return tokens
