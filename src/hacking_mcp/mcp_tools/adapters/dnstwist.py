"""Dedicated adapter metadata for dnstwist."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("all_records", bool, False, "Show all DNS records."),
        AdapterParameterSpec("banners", bool, False, "Determine HTTP and SMTP service banners."),
        AdapterParameterSpec("dictionary", str, "", "Dictionary file for additional domain permutations."),
        AdapterParameterSpec("output_format", str, "", "Output format: cli, csv, json, or list."),
        AdapterParameterSpec("fuzzers", str, "", "Comma-separated fuzzers to use."),
        AdapterParameterSpec("geoip", bool, False, "Lookup GeoIP location."),
        AdapterParameterSpec("lsh", str, "", "Compare HTML similarity with ssdeep or tlsh."),
        AdapterParameterSpec("lsh_url", str, "", "URL to fetch for locality-sensitive hash comparison."),
        AdapterParameterSpec("mxcheck", bool, False, "Check whether MX hosts can be used to intercept mail."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("registered", bool, False, "Show only registered domain names."),
        AdapterParameterSpec("unregistered", bool, False, "Show only unregistered domain names."),
        AdapterParameterSpec("phash", bool, False, "Evaluate perceptual hashes of web page screenshots."),
        AdapterParameterSpec("phash_url", str, "", "URL to fetch for perceptual hash comparison."),
        AdapterParameterSpec("screenshots", str, "", "Directory for saving web page screenshots."),
        AdapterParameterSpec("threads", int, 0, "Number of threads; 0 leaves default."),
        AdapterParameterSpec("whois", bool, False, "Lookup WHOIS creation and update dates."),
        AdapterParameterSpec("tld", str, "", "TLD dictionary file."),
        AdapterParameterSpec("nameservers", str, "", "Comma-separated nameservers to query."),
        AdapterParameterSpec("user_agent", str, "", "Custom HTTP User-Agent string."),
        AdapterParameterSpec("version", bool, False, "Show dnstwist version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "all_records", "--all")
    add_bool(tokens, kwargs, "banners", "--banners")
    add_value(tokens, kwargs, "dictionary", "--dictionary")
    add_value(tokens, kwargs, "output_format", "--format")
    add_value(tokens, kwargs, "fuzzers", "--fuzzers")
    add_bool(tokens, kwargs, "geoip", "--geoip")
    add_value(tokens, kwargs, "lsh", "--lsh")
    add_value(tokens, kwargs, "lsh_url", "--lsh-url")
    add_bool(tokens, kwargs, "mxcheck", "--mxcheck")
    add_value(tokens, kwargs, "output_file", "--output")
    add_bool(tokens, kwargs, "registered", "--registered")
    add_bool(tokens, kwargs, "unregistered", "--unregistered")
    add_bool(tokens, kwargs, "phash", "--phash")
    add_value(tokens, kwargs, "phash_url", "--phash-url")
    add_value(tokens, kwargs, "screenshots", "--screenshots")
    add_value(tokens, kwargs, "threads", "--threads")
    add_bool(tokens, kwargs, "whois", "--whois")
    add_value(tokens, kwargs, "tld", "--tld")
    add_value(tokens, kwargs, "nameservers", "--nameservers")
    add_value(tokens, kwargs, "user_agent", "--useragent")
    add_bool(tokens, kwargs, "version", "--version")
    return tokens
