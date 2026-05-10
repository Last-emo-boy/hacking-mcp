"""Dedicated adapter metadata for Skipfish."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("output_dir", str, "skipfish_out", "Mandatory output directory for -o."),
        AdapterParameterSpec("write_wordlist", str, "", "Writable wordlist for -W."),
        AdapterParameterSpec("read_wordlist", str, "", "Read-only wordlist for -S."),
        AdapterParameterSpec("auth", str, "", "HTTP authentication username:password for -A."),
        AdapterParameterSpec("host_ip", str, "", "Bind host to IP mapping for -F."),
        AdapterParameterSpec("cookie", str, "", "Cookie to set with -C."),
        AdapterParameterSpec("header", str, "", "Custom HTTP header for -H."),
        AdapterParameterSpec("browser", str, "", "Browser profile for -b."),
        AdapterParameterSpec("no_new_cookies", bool, False, "Reject new cookies with -N."),
        AdapterParameterSpec("max_depth", int, 0, "Maximum crawl depth for -d; 0 leaves default."),
        AdapterParameterSpec("max_children", int, 0, "Maximum children per node for -c; 0 leaves default."),
        AdapterParameterSpec("max_descendants", int, 0, "Maximum descendants per branch for -x; 0 leaves default."),
        AdapterParameterSpec("request_limit", int, 0, "Total request limit for -r; 0 leaves default."),
        AdapterParameterSpec("crawl_probability", int, 0, "Node crawl probability percentage for -p; 0 leaves default."),
        AdapterParameterSpec("seed", int, 0, "Random seed for -q; 0 leaves default."),
        AdapterParameterSpec("include_url", str, "", "Only crawl matching URLs with -I."),
        AdapterParameterSpec("exclude_url", str, "", "Do not crawl matching URLs with -X."),
        AdapterParameterSpec("skip_param", str, "", "Do not fuzz matching parameters with -K."),
        AdapterParameterSpec("crawl_domain", str, "", "Crawl another trusted domain with -D."),
        AdapterParameterSpec("trust_domain", str, "", "Trust but do not crawl matching domain with -B."),
        AdapterParameterSpec("skip_5xx", bool, False, "Do not report HTTP 5xx errors with -Z."),
        AdapterParameterSpec("no_forms", bool, False, "Do not submit forms with -O."),
        AdapterParameterSpec("no_html_parse", bool, False, "Do not parse HTML with -P."),
        AdapterParameterSpec("log_mixed_content", bool, False, "Log mixed content warnings with -M."),
        AdapterParameterSpec("log_cache_mismatches", bool, False, "Log cache mismatches with -E."),
        AdapterParameterSpec("log_external_urls", bool, False, "Log external URLs with -U."),
        AdapterParameterSpec("suppress_duplicates", bool, False, "Suppress duplicate nodes with -Q."),
        AdapterParameterSpec("quiet", bool, False, "Quiet mode with -u."),
        AdapterParameterSpec("verbose", bool, False, "Verbose mode with -v."),
        AdapterParameterSpec("no_autolearn", bool, False, "Disable auto-learning with -L."),
        AdapterParameterSpec("no_extension_fuzzing", bool, False, "Disable extension fuzzing with -Y."),
        AdapterParameterSpec("purge_age", int, 0, "Purge old hits after age with -R; 0 leaves default."),
        AdapterParameterSpec("form_autofill", str, "", "Form autofill rule for -T."),
        AdapterParameterSpec("max_guesses", int, 0, "Maximum guessed URLs per node for -G; 0 leaves default."),
        AdapterParameterSpec("signatures", str, "", "Signature file for -z."),
        AdapterParameterSpec("max_connections", int, 0, "Global max connections for -g; 0 leaves default."),
        AdapterParameterSpec("host_connections", int, 0, "Per-host max connections for -m; 0 leaves default."),
        AdapterParameterSpec("max_failures", int, 0, "Maximum consecutive failures for -f; 0 leaves default."),
        AdapterParameterSpec("request_timeout", int, 0, "Request timeout for -t; 0 leaves default."),
        AdapterParameterSpec("io_timeout", int, 0, "Network I/O timeout for -w; 0 leaves default."),
        AdapterParameterSpec("idle_timeout", int, 0, "Idle HTTP connection timeout for -i; 0 leaves default."),
        AdapterParameterSpec("response_size_limit", int, 0, "Response size limit for -s; 0 leaves default."),
        AdapterParameterSpec("drop_binary_responses", bool, False, "Drop binary responses with -e."),
        AdapterParameterSpec("max_requests_per_second", int, 0, "Max requests per second for -l; 0 leaves default."),
        AdapterParameterSpec("stop_after", int, 0, "Stop after this time with -k; 0 leaves default."),
        AdapterParameterSpec("config_file", str, "", "Load options from file with --config."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "output_dir", "-o")
    add_value(tokens, kwargs, "write_wordlist", "-W")
    add_value(tokens, kwargs, "read_wordlist", "-S")
    add_value(tokens, kwargs, "auth", "-A")
    add_value(tokens, kwargs, "host_ip", "-F")
    add_value(tokens, kwargs, "cookie", "-C")
    add_value(tokens, kwargs, "header", "-H")
    add_value(tokens, kwargs, "browser", "-b")
    add_bool(tokens, kwargs, "no_new_cookies", "-N")
    add_value(tokens, kwargs, "max_depth", "-d")
    add_value(tokens, kwargs, "max_children", "-c")
    add_value(tokens, kwargs, "max_descendants", "-x")
    add_value(tokens, kwargs, "request_limit", "-r")
    add_value(tokens, kwargs, "crawl_probability", "-p")
    add_value(tokens, kwargs, "seed", "-q")
    add_value(tokens, kwargs, "include_url", "-I")
    add_value(tokens, kwargs, "exclude_url", "-X")
    add_value(tokens, kwargs, "skip_param", "-K")
    add_value(tokens, kwargs, "crawl_domain", "-D")
    add_value(tokens, kwargs, "trust_domain", "-B")
    add_bool(tokens, kwargs, "skip_5xx", "-Z")
    add_bool(tokens, kwargs, "no_forms", "-O")
    add_bool(tokens, kwargs, "no_html_parse", "-P")
    add_bool(tokens, kwargs, "log_mixed_content", "-M")
    add_bool(tokens, kwargs, "log_cache_mismatches", "-E")
    add_bool(tokens, kwargs, "log_external_urls", "-U")
    add_bool(tokens, kwargs, "suppress_duplicates", "-Q")
    add_bool(tokens, kwargs, "quiet", "-u")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_bool(tokens, kwargs, "no_autolearn", "-L")
    add_bool(tokens, kwargs, "no_extension_fuzzing", "-Y")
    add_value(tokens, kwargs, "purge_age", "-R")
    add_value(tokens, kwargs, "form_autofill", "-T")
    add_value(tokens, kwargs, "max_guesses", "-G")
    add_value(tokens, kwargs, "signatures", "-z")
    add_value(tokens, kwargs, "max_connections", "-g")
    add_value(tokens, kwargs, "host_connections", "-m")
    add_value(tokens, kwargs, "max_failures", "-f")
    add_value(tokens, kwargs, "request_timeout", "-t")
    add_value(tokens, kwargs, "io_timeout", "-w")
    add_value(tokens, kwargs, "idle_timeout", "-i")
    add_value(tokens, kwargs, "response_size_limit", "-s")
    add_bool(tokens, kwargs, "drop_binary_responses", "-e")
    add_value(tokens, kwargs, "max_requests_per_second", "-l")
    add_value(tokens, kwargs, "stop_after", "-k")
    add_value(tokens, kwargs, "config_file", "--config")
    return tokens
