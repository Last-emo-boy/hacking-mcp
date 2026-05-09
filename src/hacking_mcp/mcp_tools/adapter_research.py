"""Research-state tracking for dedicated per-tool MCP adapters.

This module does not execute tools or fetch upstream repositories. It records
what evidence currently backs each generated adapter so gaps are explicit.
"""

from collections import Counter
from dataclasses import dataclass

from hacking_mcp.mcp_tools.tool_adapters import (
    NAMED_OVERRIDE_TOOL_NAMES,
    adapter_parameter_names,
    build_adapter_specs,
)
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy


SOURCE_STATUS_REGISTRY_DERIVED = "registry-derived"
SOURCE_STATUS_NAMED_OVERRIDE = "named-override"
SOURCE_STATUS_SOURCE_REVIEWED = "source-reviewed"

@dataclass(frozen=True)
class SourceReview:
    """Manual upstream-source review evidence for one adapter."""

    note: str
    references: tuple[str, ...]
    verified_parameters: tuple[str, ...]


SOURCE_REVIEWED_TOOLS: dict[str, SourceReview] = {
    "binwalk": SourceReview(
        note=(
            "Reviewed against upstream Binwalk v3 clap parser definitions for "
            "input mode, listing, quiet/verbose output, extraction, carving, "
            "recursive scans, search-all, entropy graph/logging outputs, "
            "thread count, signature include/exclude filters, and extraction "
            "directory."
        ),
        references=(
            "https://github.com/ReFirmLabs/binwalk",
            "https://raw.githubusercontent.com/ReFirmLabs/binwalk/master/src/cliparser.rs",
        ),
        verified_parameters=(
            "list_signatures",
            "stdin",
            "quiet",
            "verbose",
            "extract",
            "carve",
            "matryoshka",
            "search_all",
            "entropy",
            "png_output",
            "log_file",
            "threads",
            "exclude",
            "include",
            "output_dir",
        ),
    ),
    "volatility3": SourceReview(
        note=(
            "Reviewed against upstream Volatility 3 CLI source and generated "
            "manual page for config, parallelism, extension, plugin/symbol "
            "paths, verbosity, logging, output directory, quiet mode, renderer, "
            "configuration/cache controls, online/offline ISF controls, output "
            "filters, column hiding, memory location inputs, stackers, swap "
            "locations, and plugin selection."
        ),
        references=(
            "https://github.com/volatilityfoundation/volatility3",
            "https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/cli/__init__.py",
            "https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/doc/source/vol-cli.rst",
        ),
        verified_parameters=(
            "config_file",
            "parallelism",
            "extend",
            "plugin_dirs",
            "symbol_dirs",
            "symbol_dir",
            "verbosity",
            "log_file",
            "output_dir",
            "quiet",
            "renderer",
            "write_config",
            "save_config",
            "clear_cache",
            "cache_path",
            "offline",
            "remote_isf_url",
            "filters",
            "hide_columns",
            "single_location",
            "stackers",
            "single_swap_locations",
            "plugin",
        ),
    ),
    "nmap": SourceReview(
        note=(
            "Reviewed against the official Nmap reference guide for target "
            "syntax and adapter flags: -p, -sS, -sT, -sU, -sn, -sV, -O, -sC, "
            "-T, --top-ports, --min-rate, --script, --script-args, --exclude."
        ),
        references=(
            "https://nmap.org/book/man.html",
            "https://nmap.org/book/man-briefoptions.html",
        ),
        verified_parameters=(
            "ports",
            "scan_type",
            "service_version",
            "os_detection",
            "default_scripts",
            "timing",
            "top_ports",
            "rate",
            "scripts",
            "script_args",
            "exclude_hosts",
        ),
    ),
    "nuclei": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery Nuclei docs for "
            "template path/workflow, tags, severity, rate-limit, proxy, "
            "headless, and exclude-template flags."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/nuclei/running",
        ),
        verified_parameters=(
            "severity",
            "tags",
            "template_path",
            "rate_limit",
            "proxy",
            "workflows",
            "exclude_templates",
            "headless",
            "interactsh",
        ),
    ),
    "ffuf": SourceReview(
        note=(
            "Reviewed against the upstream ffuf README usage/help for target "
            "URL, wordlist, thread, extension, redirect, proxy, match/filter, "
            "and recursion flags."
        ),
        references=(
            "https://github.com/ffuf/ffuf",
        ),
        verified_parameters=(
            "wordlist",
            "threads",
            "extensions",
            "match_codes",
            "recursive",
            "follow_redirects",
            "proxy",
            "fuzz_keyword",
            "host_header",
            "recursion_depth",
            "filter_codes",
            "filter_size",
            "filter_words",
            "add_slash",
        ),
    ),
    "httpx": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery httpx usage docs for "
            "single URL/list input, probes, match/filter codes, rate/thread "
            "controls, proxy/header/method, timeout, output, and JSON flags."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/httpx/usage",
        ),
        verified_parameters=(
            "input_file",
            "status_code",
            "title",
            "tech_detect",
            "content_length",
            "match_codes",
            "filter_codes",
            "threads",
            "rate_limit",
            "ports",
            "path",
            "follow_redirects",
            "proxy",
            "headers",
            "method",
            "timeout",
            "output_file",
            "json_output",
            "silent",
        ),
    ),
    "subfinder": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery Subfinder usage docs "
            "for domain list input, source selection/filtering, recursive and "
            "active modes, resolver/rate controls, output formats, config, "
            "proxy, and debug/output controls."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/subfinder/usage",
        ),
        verified_parameters=(
            "input_file",
            "sources",
            "exclude_sources",
            "all_sources",
            "recursive",
            "active",
            "match",
            "filter",
            "resolvers",
            "resolver_file",
            "rate_limit",
            "rate_limits",
            "threads",
            "timeout",
            "max_time",
            "output_file",
            "json_output",
            "output_dir",
            "collect_sources",
            "include_ip",
            "exclude_ip",
            "config_file",
            "provider_config",
            "proxy",
            "silent",
            "verbose",
        ),
    ),
    "gitleaks": SourceReview(
        note=(
            "Reviewed against the upstream Gitleaks README usage/options for "
            "redaction, git log options, config/baseline/ignore files, rule "
            "selection, limits, report output, logging, banner/color, and "
            "verbose flags."
        ),
        references=(
            "https://github.com/gitleaks/gitleaks",
        ),
        verified_parameters=(
            "redact",
            "log_opts",
            "config_path",
            "baseline_path",
            "ignore_path",
            "enable_rule",
            "exit_code",
            "follow_symlinks",
            "ignore_allow",
            "max_decode_depth",
            "max_archive_depth",
            "max_target_mb",
            "report_format",
            "report_path",
            "report_template",
            "log_level",
            "no_banner",
            "no_color",
            "verbose",
        ),
    ),
    "trufflehog": SourceReview(
        note=(
            "Reviewed against the upstream TruffleHog README for filesystem "
            "scans and global flags covering JSON/GitHub output, concurrency, "
            "verification controls, result filtering, entropy/config/logging, "
            "and fail-on-result behavior."
        ),
        references=(
            "https://github.com/trufflesecurity/trufflehog",
        ),
        verified_parameters=(
            "json_output",
            "github_actions",
            "concurrency",
            "no_verification",
            "results",
            "no_color",
            "allow_verification_overlap",
            "filter_unverified",
            "filter_entropy",
            "config_path",
            "print_avg_detector_time",
            "fail",
            "log_level",
        ),
    ),
    "whatweb": SourceReview(
        note=(
            "Reviewed against the upstream WhatWeb README usage help for target "
            "input and URL modifiers, aggression, HTTP/auth/proxy controls, "
            "plugin listing/selection/search, output/log formats, thread/"
            "timeout/wait performance controls, output buffering, and help/"
            "debug/version flags."
        ),
        references=(
            "https://github.com/urbanadventurer/WhatWeb",
            "https://raw.githubusercontent.com/urbanadventurer/WhatWeb/master/README.md",
        ),
        verified_parameters=(
            "input_file",
            "url_prefix",
            "url_suffix",
            "url_pattern",
            "aggression",
            "user_agent",
            "header",
            "follow_redirect",
            "max_redirects",
            "basic_auth",
            "cookie",
            "cookiejar",
            "no_cookies",
            "proxy",
            "proxy_user",
            "list_plugins",
            "info_plugins",
            "info_plugin_search",
            "search_plugins",
            "plugins",
            "grep",
            "custom_plugin",
            "dorks",
            "verbose",
            "color",
            "quiet",
            "no_errors",
            "log_brief",
            "log_verbose",
            "log_errors",
            "log_xml",
            "log_json",
            "log_sql",
            "log_sql_create",
            "log_json_verbose",
            "log_magictree",
            "log_object",
            "log_mongo_database",
            "log_mongo_collection",
            "log_mongo_host",
            "log_mongo_username",
            "log_mongo_password",
            "log_elastic_index",
            "log_elastic_host",
            "max_threads",
            "open_timeout",
            "read_timeout",
            "wait",
            "output_sync",
            "output_buffer_size",
            "short_help",
            "debug",
            "version",
        ),
    ),
    "theHarvester": SourceReview(
        note=(
            "Reviewed against the upstream theHarvester argparse definitions "
            "and README for domain/source selection, result limit/start offset, "
            "proxy/Shodan/screenshot controls, DNS lookup/resolve/brute-force "
            "options, report filename, API endpoint wordlist/scan, and quiet "
            "mode."
        ),
        references=(
            "https://github.com/laramies/theHarvester",
            "https://raw.githubusercontent.com/laramies/theHarvester/master/theHarvester/__main__.py",
        ),
        verified_parameters=(
            "sources",
            "limit",
            "start",
            "proxies",
            "shodan",
            "screenshot",
            "dns_server",
            "takeover",
            "dns_resolve",
            "dns_lookup",
            "dns_brute",
            "filename",
            "wordlist",
            "api_scan",
            "quiet",
        ),
    ),
    "sherlock": SourceReview(
        note=(
            "Reviewed against the upstream Sherlock argparse definitions for "
            "username target input, verbosity, file/folder output controls, "
            "CSV/XLSX/TXT/JSON outputs, repeated --site selection, proxy, "
            "response dumping, timeout, print controls, color, browse, local "
            "site data, NSFW inclusion, and exclusion override flags."
        ),
        references=(
            "https://github.com/sherlock-project/sherlock",
            "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/sherlock.py",
        ),
        verified_parameters=(
            "verbose",
            "folder_output",
            "output_file",
            "csv_output",
            "xlsx_output",
            "sites",
            "site_list",
            "proxy",
            "dump_response",
            "json_file",
            "timeout",
            "print_all",
            "print_found",
            "no_color",
            "browse",
            "local",
            "nsfw",
            "txt_output",
            "ignore_exclusions",
        ),
    ),
    "amass": SourceReview(
        note=(
            "Reviewed against the OWASP Amass user guide for the enum command, "
            "including config/output controls, active/passive modes, alteration "
            "and brute-force inputs, source include/exclude lists, resolver/QPS "
            "controls, ports, scripts, timeout, and verbose output."
        ),
        references=(
            "https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md",
        ),
        verified_parameters=(
            "config_file",
            "output_dir",
            "no_color",
            "silent",
            "active",
            "passive",
            "alts",
            "alteration_wordlist",
            "alteration_masks",
            "blacklist",
            "blacklist_file",
            "brute",
            "domain_file",
            "exclude_sources",
            "exclude_file",
            "include_sources",
            "include_file",
            "interface",
            "include_ip",
            "ipv4",
            "ipv6",
            "list_sources",
            "log_file",
            "max_depth",
            "min_for_recursive",
            "known_names_file",
            "no_recursive",
            "output_file",
            "output_prefix",
            "ports",
            "resolvers",
            "resolver_file",
            "dns_qps",
            "resolver_qps",
            "scripts_dir",
            "timeout",
            "trusted_resolvers",
            "trusted_resolver_file",
            "trusted_qps",
            "verbose",
            "wordlist",
            "wordlist_masks",
        ),
    ),
    "masscan": SourceReview(
        note=(
            "Reviewed against the upstream masscan README for port selection, "
            "rate/config echo, banner-grabbing source settings, include/exclude "
            "files, output formats/files, and readscan replay."
        ),
        references=(
            "https://github.com/robertdavidgraham/masscan",
        ),
        verified_parameters=(
            "ports",
            "rate",
            "config_file",
            "echo",
            "banners",
            "source_ip",
            "source_port",
            "exclude_file",
            "include_file",
            "output_xml",
            "output_json",
            "output_list",
            "output_grepable",
            "output_format",
            "output_filename",
            "readscan",
        ),
    ),
    "rustscan": SourceReview(
        note=(
            "Reviewed against RustScan's upstream clap input definitions for "
            "ports/ranges, config/banner/output modes, resolver, batch/timeout "
            "limits, scan order, scripts, exclusions, UDP mode, and trailing "
            "nmap arguments."
        ),
        references=(
            "https://github.com/RustScan/RustScan",
            "https://github.com/RustScan/RustScan/blob/master/src/input.rs",
        ),
        verified_parameters=(
            "ports",
            "port_range",
            "no_config",
            "no_banner",
            "config_path",
            "greppable",
            "accessible",
            "resolver",
            "batch_size",
            "timeout",
            "tries",
            "ulimit",
            "scan_order",
            "scripts",
            "top",
            "exclude_ports",
            "exclude_addresses",
            "udp",
            "nmap_args",
        ),
    ),
    "katana": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery Katana usage docs for "
            "target list input, crawl depth/strategy, JavaScript and known-file "
            "crawling, form/headless options, proxy/header settings, timeout/"
            "retry/rate/concurrency controls, crawl duration, output, JSONL, "
            "field selection, and quiet/color controls."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/katana/usage",
        ),
        verified_parameters=(
            "input_file",
            "depth",
            "strategy",
            "js_crawl",
            "known_files",
            "automatic_form_fill",
            "form_extraction",
            "headless",
            "headless_options",
            "no_sandbox",
            "system_chrome",
            "proxy",
            "headers",
            "timeout",
            "retry",
            "rate_limit",
            "concurrency",
            "parallelism",
            "delay",
            "crawl_duration",
            "output_file",
            "json_output",
            "field",
            "silent",
            "no_color",
        ),
    ),
    "arjun": SourceReview(
        note=(
            "Reviewed against the upstream Arjun usage guide for target files, "
            "JSON/Burp/text outputs, HTTP method and included data, thread/"
            "delay/timeout/rate controls, wordlist/chunk settings, redirects, "
            "passive discovery, casing, and custom headers."
        ),
        references=(
            "https://github.com/s0md3v/Arjun",
            "https://github.com/s0md3v/Arjun/wiki/Usage",
        ),
        verified_parameters=(
            "input_file",
            "output_json",
            "output_burp",
            "output_text",
            "method",
            "include_data",
            "threads",
            "delay",
            "timeout",
            "stable",
            "rate_limit",
            "wordlist",
            "chunk_size",
            "disable_redirects",
            "passive",
            "casing",
            "headers",
        ),
    ),
    "gobuster": SourceReview(
        note=(
            "Reviewed against the upstream Gobuster README for dir mode "
            "wordlist/extensions, custom headers/cookies, length/status output, "
            "threads/delay/user-agent/timeout, file output, quiet/progress, "
            "expanded URLs, and slash-appending flags."
        ),
        references=(
            "https://github.com/OJ/gobuster",
        ),
        verified_parameters=(
            "wordlist",
            "extensions",
            "headers",
            "cookies",
            "show_length",
            "status_codes",
            "threads",
            "delay",
            "user_agent",
            "timeout",
            "output_file",
            "quiet",
            "no_progress",
            "expanded",
            "add_slash",
        ),
    ),
    "feroxbuster": SourceReview(
        note=(
            "Reviewed against official feroxbuster command-line docs for "
            "wordlists/extensions/methods/request data, headers/cookies/query, "
            "filters/status allow-lists, timeout/redirects/TLS, recursion and "
            "rate controls, collection, verbosity/output, debug/state, and "
            "progress limiting flags."
        ),
        references=(
            "https://github.com/epi052/feroxbuster",
            "https://epi052.github.io/feroxbuster-docs/docs/configuration/command-line/",
        ),
        verified_parameters=(
            "wordlist",
            "extensions",
            "methods",
            "data",
            "headers",
            "cookies",
            "query",
            "add_slash",
            "protocol",
            "dont_scan",
            "scope",
            "filter_size",
            "filter_regex",
            "filter_words",
            "filter_lines",
            "filter_codes",
            "status_codes",
            "unique",
            "timeout",
            "follow_redirects",
            "insecure",
            "threads",
            "no_recursion",
            "depth",
            "force_recursion",
            "dont_extract_links",
            "scan_limit",
            "parallelism",
            "rate_limit",
            "response_size_limit",
            "time_limit",
            "auto_tune",
            "auto_bail",
            "dont_filter",
            "collect_extensions",
            "collect_backups",
            "collect_words",
            "dont_collect",
            "verbosity",
            "silent",
            "quiet",
            "json_output",
            "output_file",
            "debug_log",
            "no_state",
            "limit_bars",
        ),
    ),
    "dirsearch": SourceReview(
        note=(
            "Reviewed against the upstream dirsearch README Options section for "
            "wordlists/extensions, status/size/text/regex filters, prefixes/"
            "suffixes, recursion controls, HTTP method/data/headers, redirect/"
            "agent/cookie/proxy/rate settings, report formats, output, quiet, "
            "full-url, and color controls."
        ),
        references=(
            "https://github.com/maurosoria/dirsearch",
        ),
        verified_parameters=(
            "wordlist",
            "extensions",
            "include_status",
            "exclude_status",
            "exclude_sizes",
            "exclude_text",
            "exclude_regex",
            "prefixes",
            "suffixes",
            "threads",
            "recursive",
            "deep_recursive",
            "force_recursive",
            "recursion_depth",
            "recursion_status",
            "subdirs",
            "exclude_subdirs",
            "method",
            "data",
            "headers",
            "header_list",
            "follow_redirects",
            "random_agent",
            "user_agent",
            "cookies",
            "proxy",
            "proxy_list",
            "timeout",
            "delay",
            "max_rate",
            "retries",
            "format",
            "output_file",
            "json_report",
            "plain_text_report",
            "csv_report",
            "markdown_report",
            "xml_report",
            "sqlite_report",
            "quiet",
            "full_url",
            "no_color",
        ),
    ),
    "nikto": SourceReview(
        note=(
            "Reviewed against the upstream Nikto README help/options for CGI "
            "dirs, config/display/dbcheck/evasion, output formats, auth, plugin "
            "selection, max time, mutation, DNS/SSL/404 behavior, output/save, "
            "ports/root/tuning/timeout/user-agent/proxy/vhost, and update flags."
        ),
        references=(
            "https://github.com/sullo/nikto",
        ),
        verified_parameters=(
            "ask",
            "cgi_dirs",
            "config_file",
            "display",
            "dbcheck",
            "evasion",
            "output_format",
            "auth",
            "list_plugins",
            "max_time",
            "mutate",
            "mutate_options",
            "no_interactive",
            "no_lookup",
            "no_ssl",
            "no_404",
            "output_file",
            "pause",
            "plugins",
            "port",
            "rsa_cert",
            "root",
            "save_dir",
            "ssl",
            "tuning",
            "timeout",
            "user_agent",
            "until",
            "update",
            "use_proxy",
            "vhost",
            "notfound_code",
            "notfound_string",
        ),
    ),
    "owasp-zap": SourceReview(
        note=(
            "Reviewed against the official ZAP desktop command line docs and "
            "Quick Start add-on command line docs for quick scan URL/report/"
            "progress, ZAPit URL, core config/session/logging options, add-on "
            "management, script loading, support info, and SBOM output flags."
        ),
        references=(
            "https://www.zaproxy.org/docs/desktop/cmdline/",
            "https://www.zaproxy.org/docs/desktop/addons/quick-start/cmdline/",
        ),
        verified_parameters=(
            "quick_out",
            "quick_progress",
            "zapit_url",
            "config",
            "config_file",
            "home_dir",
            "install_dir",
            "new_session",
            "session",
            "low_mem",
            "experimental_db",
            "no_stdout",
            "log_level",
            "silent",
            "addon_install",
            "addon_install_all",
            "addon_uninstall",
            "addon_update",
            "addon_list",
            "script",
            "support_info",
            "sbom_zip",
        ),
    ),
    "testssl": SourceReview(
        note=(
            "Reviewed against the upstream testssl.sh manual for input/mass "
            "testing, warnings/timeouts/auth/header/mTLS options, STARTTLS and "
            "proxy/IP/IPv6 handling, tuning flags, single check selectors, "
            "vulnerability/header/client checks, output formatting, and file "
            "output controls."
        ),
        references=(
            "https://github.com/drwetter/testssl.sh",
            "https://raw.githubusercontent.com/drwetter/testssl.sh/3.2/doc/testssl.1.md",
        ),
        verified_parameters=(
            "input_file",
            "mode",
            "warnings",
            "connect_timeout",
            "openssl_timeout",
            "basic_auth",
            "req_header",
            "mtls_file",
            "starttls",
            "xmpp_host",
            "mx",
            "ip",
            "proxy",
            "ipv6",
            "ssl_native",
            "openssl_path",
            "bugs",
            "assume_http",
            "no_dns",
            "sneaky",
            "user_agent",
            "ids_friendly",
            "phone_out",
            "add_ca",
            "each_cipher",
            "cipher_per_proto",
            "categories",
            "forward_secrecy",
            "protocols",
            "server_preference",
            "server_defaults",
            "single_cipher",
            "check_headers",
            "client_simulation",
            "grease",
            "vulnerabilities",
            "quiet",
            "wide",
            "mapping",
            "show_each",
            "color",
            "colorblind",
            "debug",
            "disable_rating",
            "log",
            "logfile",
            "json_output",
            "jsonfile",
            "json_pretty",
            "jsonfile_pretty",
            "csv_output",
            "csvfile",
            "html_output",
            "htmlfile",
            "out_file",
            "outfile",
            "severity",
            "append",
            "overwrite",
            "outprefix",
        ),
    ),
    "dalfox": SourceReview(
        note=(
            "Reviewed against the official DalFox command-line flags reference "
            "for request configuration, scanning behavior, performance, parameter "
            "mining, control flow, and output/reporting flags."
        ),
        references=(
            "https://github.com/hahwul/dalfox",
            "https://dalfox.hahwul.com/advanced/features/command-flags/",
        ),
        verified_parameters=(
            "blind_callback",
            "config_file",
            "cookies",
            "custom_alert_type",
            "custom_alert_value",
            "custom_payload",
            "data",
            "deep_domxss",
            "delay",
            "follow_redirects",
            "force_headless_verification",
            "headers",
            "ignore_param",
            "ignore_return",
            "method",
            "parameter",
            "proxy",
            "remote_payloads",
            "timeout",
            "user_agent",
            "waf_evasion",
            "max_cpu",
            "workers",
            "mining_dict",
            "mining_dict_word",
            "mining_dom",
            "remote_wordlists",
            "skip_mining_all",
            "skip_mining_dict",
            "skip_mining_dom",
            "only_custom_payload",
            "only_discovery",
            "skip_bav",
            "skip_discovery",
            "skip_grepping",
            "skip_headless",
            "skip_xss_scanning",
            "use_bav",
            "debug",
            "format",
            "found_action",
            "found_action_shell",
            "grep_file",
            "har_file_path",
            "no_color",
            "no_spinner",
            "only_poc",
            "output_file",
            "output_all",
            "output_request",
            "output_response",
            "poc_type",
            "report",
            "report_format",
            "silence",
        ),
    ),
    "xsstrike": SourceReview(
        note=(
            "Reviewed against upstream XSStrike argparse definitions for POST "
            "data, encoding, fuzzer/update modes, timeout/proxy/crawl/JSON/path "
            "controls, seed and payload files, crawl level, headers, threads, "
            "delay, skip/DOM/blind toggles, and logging controls."
        ),
        references=(
            "https://github.com/UltimateHackers/XSStrike",
            "https://raw.githubusercontent.com/UltimateHackers/XSStrike/master/xsstrike.py",
        ),
        verified_parameters=(
            "data",
            "encode",
            "fuzzer",
            "update",
            "timeout",
            "use_proxy",
            "crawl",
            "json_data",
            "path_injection",
            "seeds_file",
            "payload_file",
            "level",
            "headers",
            "threads",
            "delay",
            "skip",
            "skip_dom",
            "blind",
            "console_log_level",
            "file_log_level",
            "log_file",
        ),
    ),
    "xspear": SourceReview(
        note=(
            "Reviewed against upstream XSpear README usage for POST data, all-"
            "parameter mode, no-XSS analysis mode, headers/cookies, custom "
            "payloads, raw request input, parameter selection, blind callback, "
            "threading, output format, config file, and verbosity."
        ),
        references=(
            "https://github.com/hahwul/XSpear",
            "https://raw.githubusercontent.com/hahwul/XSpear/master/README.md",
        ),
        verified_parameters=(
            "data",
            "test_all_params",
            "no_xss",
            "headers",
            "cookie",
            "custom_payload",
            "raw_file",
            "parameter",
            "blind_callback",
            "threads",
            "output_format",
            "config_file",
            "verbose",
        ),
    ),
    "xsscon": SourceReview(
        note=(
            "Reviewed against upstream XSSCon argparse definitions for crawl "
            "depth, payload level/value, method mode, user-agent, single URL, "
            "proxy, about, and cookie flags."
        ),
        references=(
            "https://github.com/menkrep1337/XSSCon",
            "https://raw.githubusercontent.com/menkrep1337/XSSCon/master/xsscon.py",
        ),
        verified_parameters=(
            "depth",
            "payload_level",
            "payload",
            "method",
            "user_agent",
            "single_url",
            "proxy",
            "about",
            "cookie",
        ),
    ),
    "xanxss": SourceReview(
        note=(
            "Reviewed against upstream XanXSS argparse definitions for "
            "verification amount, number of findings, test time, inline/file "
            "payloads, verbosity, proxy, headers, throttle, polyglot, prefix, "
            "and suffix flags."
        ),
        references=(
            "https://github.com/Ekultek/XanXSS",
            "https://raw.githubusercontent.com/Ekultek/XanXSS/master/lib/cmd.py",
        ),
        verified_parameters=(
            "verification_amount",
            "amount_to_find",
            "test_time",
            "payloads",
            "payload_file",
            "verbose",
            "proxy",
            "headers",
            "throttle",
            "polyglot",
            "prefix",
            "suffix",
        ),
    ),
    "dsss": SourceReview(
        note=(
            "Reviewed against upstream DSSS option parsing for POST data, cookie, "
            "user-agent, referer, and proxy flags."
        ),
        references=(
            "https://github.com/stamparm/DSSS",
            "https://raw.githubusercontent.com/stamparm/DSSS/master/dsss.py",
        ),
        verified_parameters=(
            "data",
            "cookie",
            "user_agent",
            "referer",
            "proxy",
        ),
    ),
    "sqlscan": SourceReview(
        note=(
            "Reviewed against upstream sqlscan README usage showing URL or input "
            "file targets scanned with the --scan mode flag."
        ),
        references=(
            "https://github.com/Cvar1984/sqlscan",
            "https://raw.githubusercontent.com/Cvar1984/sqlscan/dev/README.md",
        ),
        verified_parameters=(
            "scan",
        ),
    ),
    "wafw00f": SourceReview(
        note=(
            "Reviewed against upstream wafw00f OptionParser definitions for "
            "verbosity, find-all matching, redirect suppression, one-WAF tests, "
            "output file/format, input files, WAF listing, proxy, version, custom "
            "headers file, timeout, and color suppression."
        ),
        references=(
            "https://github.com/EnableSecurity/wafw00f",
            "https://raw.githubusercontent.com/EnableSecurity/wafw00f/master/wafw00f/main.py",
        ),
        verified_parameters=(
            "verbosity",
            "find_all",
            "no_redirect",
            "test_waf",
            "output_file",
            "output_format",
            "input_file",
            "list_wafs",
            "proxy",
            "version",
            "headers_file",
            "timeout",
            "no_color",
        ),
    ),
}

BASE_ADAPTER_PARAMETERS = {"target", "options", "confirm_authorized"}


@dataclass(frozen=True)
class AdapterResearchRecord:
    """Evidence summary for one generated adapter."""

    tool_name: str
    title: str
    category: str
    safety_tier: str
    endpoint: str
    execution_state: str
    source_status: str
    named_override: bool
    source_reviewed: bool
    parameter_count: int
    project_url: str
    verified_parameters: tuple[str, ...]
    unverified_parameters: tuple[str, ...]
    evidence: tuple[str, ...]
    gap: str


def build_adapter_research_records(
    registry: ToolRegistry,
    safety: SafetyPolicy,
) -> list[AdapterResearchRecord]:
    """Build per-tool adapter research records from concrete registry data."""
    specs = {spec.tool_name: spec for spec in build_adapter_specs(registry, safety)}
    records: list[AdapterResearchRecord] = []

    for tool in registry.list_all_tools():
        spec = specs[tool.name]
        params = adapter_parameter_names(tool, spec)
        reviewable_params = sorted(set(params) - BASE_ADAPTER_PARAMETERS)
        source_review = SOURCE_REVIEWED_TOOLS.get(tool.name)
        source_reviewed = source_review is not None
        named_override = tool.name in NAMED_OVERRIDE_TOOL_NAMES
        verified_params = sorted(source_review.verified_parameters) if source_review else []
        unverified_params = (
            sorted(set(reviewable_params) - set(verified_params))
            if source_review
            else reviewable_params
        )

        if source_reviewed:
            source_status = SOURCE_STATUS_SOURCE_REVIEWED
        elif named_override:
            source_status = SOURCE_STATUS_NAMED_OVERRIDE
        else:
            source_status = SOURCE_STATUS_REGISTRY_DERIVED

        evidence = [
            "registry metadata: category, tags, run_command, install_commands, project_url",
            f"generated adapter parameter schema with {len(params)} parameters",
        ]
        if named_override:
            evidence.append("tool-specific named override exists in tool_adapters.py")
        else:
            evidence.append("parameters are derived from category/tag adapter rules")
        if tool.project_url:
            evidence.append(f"registry project_url: {tool.project_url}")
        if source_review:
            evidence.append(f"source review note: {source_review.note}")
            evidence.append(
                "source-verified parameters: " + ", ".join(verified_params)
            )
            evidence.extend(
                f"source reference: {reference}"
                for reference in source_review.references
            )

        gap = ""
        if source_reviewed and unverified_params:
            gap = (
                "source review does not yet verify exposed parameters: "
                + ", ".join(unverified_params)
            )
        elif not source_reviewed:
            gap = (
                "upstream source/docs have not been manually reviewed for exact "
                "CLI parity"
            )

        records.append(
            AdapterResearchRecord(
                tool_name=tool.name,
                title=tool.title,
                category=tool.category,
                safety_tier=tool.safety_tier.value,
                endpoint=spec.mcp_name,
                execution_state="executable" if spec.exposed else "policy/info-only",
                source_status=source_status,
                named_override=named_override,
                source_reviewed=source_reviewed,
                parameter_count=len(params),
                project_url=tool.project_url,
                verified_parameters=tuple(verified_params),
                unverified_parameters=tuple(unverified_params),
                evidence=tuple(evidence),
                gap=gap,
            )
        )

    return records


def summarize_adapter_research(records: list[AdapterResearchRecord]) -> dict[str, int]:
    """Return aggregate research-status counts."""
    by_status = Counter(record.source_status for record in records)
    return {
        "total": len(records),
        "registry_derived": by_status[SOURCE_STATUS_REGISTRY_DERIVED],
        "named_override": by_status[SOURCE_STATUS_NAMED_OVERRIDE],
        "source_reviewed": by_status[SOURCE_STATUS_SOURCE_REVIEWED],
        "fully_source_verified": sum(
            1 for record in records
            if record.source_reviewed and not record.unverified_parameters
        ),
        "source_review_gaps": sum(1 for record in records if record.gap),
    }


def find_adapter_research_record(
    registry: ToolRegistry,
    safety: SafetyPolicy,
    tool_name: str,
) -> AdapterResearchRecord | None:
    """Find one adapter research record by tool name."""
    normalized = tool_name.strip()
    if not normalized:
        return None
    for record in build_adapter_research_records(registry, safety):
        if record.tool_name == normalized:
            return record
    return None
