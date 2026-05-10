"""Dedicated adapter metadata for OWASP Amass."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("config_file", str, "", "Path to Amass YAML configuration file."),
        AdapterParameterSpec("output_dir", str, "", "Directory containing the graph database and output files."),
        AdapterParameterSpec("no_color", bool, False, "Disable colorized output."),
        AdapterParameterSpec("silent", bool, False, "Disable all output during execution."),
        AdapterParameterSpec("active", bool, False, "Enable active reconnaissance methods."),
        AdapterParameterSpec("passive", bool, False, "Run purely passive enumeration."),
        AdapterParameterSpec("alts", bool, False, "Enable altered-name generation."),
        AdapterParameterSpec("alteration_wordlist", str, "", "Wordlist file for alterations."),
        AdapterParameterSpec("alteration_masks", str, "", "Hashcat-style masks for name alterations."),
        AdapterParameterSpec("blacklist", str, "", "Blacklisted subdomain names."),
        AdapterParameterSpec("blacklist_file", str, "", "File containing blacklisted subdomains."),
        AdapterParameterSpec("brute", bool, False, "Perform brute-force subdomain enumeration."),
        AdapterParameterSpec("domain_file", str, "", "File providing root domain names."),
        AdapterParameterSpec("exclude_sources", str, "", "Data sources to exclude."),
        AdapterParameterSpec("exclude_file", str, "", "File containing data sources to exclude."),
        AdapterParameterSpec("include_sources", str, "", "Data sources to include."),
        AdapterParameterSpec("include_file", str, "", "File containing data sources to include."),
        AdapterParameterSpec("interface", str, "", "Network interface to send traffic through."),
        AdapterParameterSpec("include_ip", bool, False, "Show IP addresses for discovered names."),
        AdapterParameterSpec("ipv4", bool, False, "Show IPv4 addresses for discovered names."),
        AdapterParameterSpec("ipv6", bool, False, "Show IPv6 addresses for discovered names."),
        AdapterParameterSpec("list_sources", bool, False, "Print available data sources."),
        AdapterParameterSpec("log_file", str, "", "Path to log file for errors."),
        AdapterParameterSpec("max_depth", int, 0, "Maximum subdomain labels for brute forcing; 0 leaves default."),
        AdapterParameterSpec("min_for_recursive", int, 0, "Discoveries before recursive brute forcing; 0 leaves default."),
        AdapterParameterSpec("known_names_file", str, "", "File providing already known subdomain names."),
        AdapterParameterSpec("no_recursive", bool, False, "Turn off recursive brute forcing."),
        AdapterParameterSpec("output_file", str, "", "Text output file path."),
        AdapterParameterSpec("output_prefix", str, "", "Path prefix for all output files."),
        AdapterParameterSpec("ports", str, "", "Ports for active certificate/crawl checks."),
        AdapterParameterSpec("resolvers", str, "", "Untrusted DNS resolver IPs."),
        AdapterParameterSpec("resolver_file", str, "", "File containing untrusted DNS resolvers."),
        AdapterParameterSpec("dns_qps", int, 0, "Maximum DNS queries per second; 0 leaves default."),
        AdapterParameterSpec("resolver_qps", int, 0, "Maximum queries per untrusted resolver; 0 leaves default."),
        AdapterParameterSpec("scripts_dir", str, "", "Directory containing ADS scripts."),
        AdapterParameterSpec("timeout", int, 0, "Minutes to execute enumeration; 0 leaves default."),
        AdapterParameterSpec("trusted_resolvers", str, "", "Trusted DNS resolver IPs."),
        AdapterParameterSpec("trusted_resolver_file", str, "", "File containing trusted DNS resolvers."),
        AdapterParameterSpec("trusted_qps", int, 0, "Maximum queries per trusted resolver; 0 leaves default."),
        AdapterParameterSpec("verbose", bool, False, "Output status, debug, and troubleshooting info."),
        AdapterParameterSpec("wordlist", str, "", "Wordlist file for brute forcing."),
        AdapterParameterSpec("wordlist_masks", str, "", "Hashcat-style masks for DNS brute forcing."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "config_file", "-config")
    add_value(tokens, kwargs, "output_dir", "-dir")
    add_bool(tokens, kwargs, "no_color", "-nocolor")
    add_bool(tokens, kwargs, "silent", "-silent")
    add_bool(tokens, kwargs, "active", "-active")
    add_bool(tokens, kwargs, "passive", "-passive")
    add_bool(tokens, kwargs, "alts", "-alts")
    add_value(tokens, kwargs, "alteration_wordlist", "-aw")
    add_value(tokens, kwargs, "alteration_masks", "-awm")
    add_value(tokens, kwargs, "blacklist", "-bl")
    add_value(tokens, kwargs, "blacklist_file", "-blf")
    add_bool(tokens, kwargs, "brute", "-brute")
    add_value(tokens, kwargs, "domain_file", "-df")
    add_value(tokens, kwargs, "exclude_sources", "-exclude")
    add_value(tokens, kwargs, "exclude_file", "-ef")
    add_value(tokens, kwargs, "include_sources", "-include")
    add_value(tokens, kwargs, "include_file", "-if")
    add_value(tokens, kwargs, "interface", "-iface")
    add_bool(tokens, kwargs, "include_ip", "-ip")
    add_bool(tokens, kwargs, "ipv4", "-ipv4")
    add_bool(tokens, kwargs, "ipv6", "-ipv6")
    add_bool(tokens, kwargs, "list_sources", "-list")
    add_value(tokens, kwargs, "log_file", "-log")
    add_value(tokens, kwargs, "max_depth", "-max-depth")
    add_value(tokens, kwargs, "min_for_recursive", "-min-for-recursive")
    add_value(tokens, kwargs, "known_names_file", "-nf")
    add_bool(tokens, kwargs, "no_recursive", "-norecursive")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "output_prefix", "-oA")
    add_value(tokens, kwargs, "ports", "-p")
    add_value(tokens, kwargs, "resolvers", "-r")
    add_value(tokens, kwargs, "resolver_file", "-rf")
    add_value(tokens, kwargs, "dns_qps", "-dns-qps")
    add_value(tokens, kwargs, "resolver_qps", "-rqps")
    add_value(tokens, kwargs, "scripts_dir", "-scripts")
    add_value(tokens, kwargs, "timeout", "-timeout")
    add_value(tokens, kwargs, "trusted_resolvers", "-tr")
    add_value(tokens, kwargs, "trusted_resolver_file", "-trf")
    add_value(tokens, kwargs, "trusted_qps", "-trqps")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_value(tokens, kwargs, "wordlist", "-w")
    add_value(tokens, kwargs, "wordlist_masks", "-wm")
    return tokens
