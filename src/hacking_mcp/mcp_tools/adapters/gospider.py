"""Dedicated adapter metadata for GoSpider."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("site", str, "", "Site URL for -s/--site; used as target when target is empty."),
        AdapterParameterSpec("output_dir", str, "", "Output folder for -o/--output."),
        AdapterParameterSpec("proxy", str, "", "Proxy URL for -p/--proxy."),
        AdapterParameterSpec("user_agent", str, "", "User-Agent value for -u/--user-agent."),
        AdapterParameterSpec("cookie", str, "", "Cookie header value for --cookie."),
        AdapterParameterSpec("header", str, "", "One custom header for -H/--header."),
        AdapterParameterSpec("burp_request", str, "", "Burp raw HTTP request file for --burp."),
        AdapterParameterSpec("blacklist", str, "", "Blacklist URL regex for --blacklist."),
        AdapterParameterSpec("whitelist", str, "", "Whitelist URL regex for --whitelist."),
        AdapterParameterSpec("whitelist_domain", str, "", "Whitelist domain for --whitelist-domain."),
        AdapterParameterSpec("threads", int, 0, "Parallel site worker count for -t/--threads."),
        AdapterParameterSpec("concurrent", int, 0, "Concurrent requests per matching domain for -c/--concurrent."),
        AdapterParameterSpec("depth", int, 0, "Maximum crawl depth for -d/--depth; 0 leaves the GoSpider default."),
        AdapterParameterSpec("delay", int, 0, "Delay between requests in seconds for -k/--delay."),
        AdapterParameterSpec("random_delay", int, 0, "Extra randomized delay in seconds for -K/--random-delay."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds for -m/--timeout."),
        AdapterParameterSpec("base", bool, False, "Disable all and only use HTML content with -B/--base."),
        AdapterParameterSpec("js", bool, False, "Enable JavaScript link finder with --js."),
        AdapterParameterSpec("subs", bool, False, "Include subdomains with --subs."),
        AdapterParameterSpec("sitemap", bool, False, "Try to crawl sitemap.xml with --sitemap."),
        AdapterParameterSpec("robots", bool, False, "Try to crawl robots.txt with --robots."),
        AdapterParameterSpec("other_source", bool, False, "Find URLs from third-party sources with -a/--other-source."),
        AdapterParameterSpec("include_subs", bool, False, "Include third-party subdomains with -w/--include-subs."),
        AdapterParameterSpec("include_other_source", bool, False, "Include and request other-source URLs with -r/--include-other-source."),
        AdapterParameterSpec("debug", bool, False, "Turn on debug mode with --debug."),
        AdapterParameterSpec("json_output", bool, False, "Enable JSON output with --json."),
        AdapterParameterSpec("verbose", bool, False, "Turn on verbose output with -v/--verbose."),
        AdapterParameterSpec("length", bool, False, "Show response length with -l/--length."),
        AdapterParameterSpec("filter_length", str, "", "Filter by response lengths with -L/--filter-length."),
        AdapterParameterSpec("raw", bool, False, "Turn on raw output with -R/--raw."),
        AdapterParameterSpec("quiet", bool, False, "Only show URLs with -q/--quiet."),
        AdapterParameterSpec("no_redirect", bool, False, "Disable redirects with --no-redirect."),
        AdapterParameterSpec("version", bool, False, "Show GoSpider version with --version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "output_dir", "-o")
    add_value(tokens, kwargs, "proxy", "-p")
    add_value(tokens, kwargs, "user_agent", "-u")
    add_value(tokens, kwargs, "cookie", "--cookie")
    add_value(tokens, kwargs, "header", "-H")
    add_value(tokens, kwargs, "burp_request", "--burp")
    add_value(tokens, kwargs, "blacklist", "--blacklist")
    add_value(tokens, kwargs, "whitelist", "--whitelist")
    add_value(tokens, kwargs, "whitelist_domain", "--whitelist-domain")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "concurrent", "-c")
    add_value(tokens, kwargs, "depth", "-d")
    add_value(tokens, kwargs, "delay", "-k")
    add_value(tokens, kwargs, "random_delay", "-K")
    add_value(tokens, kwargs, "timeout", "-m")
    add_bool(tokens, kwargs, "base", "-B")
    add_bool(tokens, kwargs, "js", "--js")
    add_bool(tokens, kwargs, "subs", "--subs")
    add_bool(tokens, kwargs, "sitemap", "--sitemap")
    add_bool(tokens, kwargs, "robots", "--robots")
    add_bool(tokens, kwargs, "other_source", "-a")
    add_bool(tokens, kwargs, "include_subs", "-w")
    add_bool(tokens, kwargs, "include_other_source", "-r")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "json_output", "--json")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_bool(tokens, kwargs, "length", "-l")
    add_value(tokens, kwargs, "filter_length", "-L")
    add_bool(tokens, kwargs, "raw", "-R")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_bool(tokens, kwargs, "no_redirect", "--no-redirect")
    add_bool(tokens, kwargs, "version", "--version")
    return tokens
