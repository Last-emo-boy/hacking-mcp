"""Dedicated adapter metadata for theHarvester."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("sources", str, "", "Comma-separated source list, or all."),
        AdapterParameterSpec("limit", int, 0, "Maximum search results; 0 leaves default."),
        AdapterParameterSpec("start", int, 0, "Start offset; 0 leaves default."),
        AdapterParameterSpec("proxies", bool, False, "Use proxies from proxies.yaml."),
        AdapterParameterSpec("shodan", bool, False, "Use Shodan to query discovered hosts."),
        AdapterParameterSpec("screenshot", str, "", "Directory for screenshots of resolved domains."),
        AdapterParameterSpec("dns_server", str, "", "DNS server to use for lookups."),
        AdapterParameterSpec("takeover", bool, False, "Check discovered hosts for takeover candidates."),
        AdapterParameterSpec("dns_resolve", str, "", "Resolver list path or comma-separated resolver IPs."),
        AdapterParameterSpec("dns_lookup", bool, False, "Enable DNS server lookup."),
        AdapterParameterSpec("dns_brute", bool, False, "Perform DNS brute force for the domain."),
        AdapterParameterSpec("filename", str, "", "Base filename for XML and JSON reports."),
        AdapterParameterSpec("wordlist", str, "", "Wordlist for API endpoint scanning."),
        AdapterParameterSpec("api_scan", bool, False, "Scan for API endpoints."),
        AdapterParameterSpec("quiet", bool, False, "Suppress missing API key warnings."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "sources", "-b")
    add_value(tokens, kwargs, "limit", "-l")
    add_value(tokens, kwargs, "start", "-S")
    add_bool(tokens, kwargs, "proxies", "-p")
    add_bool(tokens, kwargs, "shodan", "-s")
    add_value(tokens, kwargs, "screenshot", "--screenshot")
    add_value(tokens, kwargs, "dns_server", "-e")
    add_bool(tokens, kwargs, "takeover", "-t")
    add_value(tokens, kwargs, "dns_resolve", "-r")
    add_bool(tokens, kwargs, "dns_lookup", "-n")
    add_bool(tokens, kwargs, "dns_brute", "-c")
    add_value(tokens, kwargs, "filename", "-f")
    add_value(tokens, kwargs, "wordlist", "-w")
    add_bool(tokens, kwargs, "api_scan", "-a")
    add_bool(tokens, kwargs, "quiet", "-q")
    return tokens
