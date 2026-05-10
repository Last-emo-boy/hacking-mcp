"""Dedicated adapter metadata for Maigret."""

import shlex

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("extra_usernames", str, "", "Additional usernames to search, separated by spaces or commas."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves upstream default."),
        AdapterParameterSpec("retries", int, 0, "Retry count for temporarily failed requests; 0 leaves default."),
        AdapterParameterSpec("max_connections", int, 0, "Maximum concurrent connections; 0 leaves default."),
        AdapterParameterSpec("no_recursion", bool, False, "Disable recursive search from extracted page data."),
        AdapterParameterSpec("no_extracting", bool, False, "Disable parsing pages for additional data."),
        AdapterParameterSpec("id_type", str, "", "Identifier type, for example username, gaia_id, or vk_id."),
        AdapterParameterSpec("permute", bool, False, "Permute multiple usernames to generate variants."),
        AdapterParameterSpec("db_file", str, "", "Maigret database JSON file or web resource."),
        AdapterParameterSpec("no_autoupdate", bool, False, "Disable automatic database update on startup."),
        AdapterParameterSpec("force_update", bool, False, "Force database update check and download."),
        AdapterParameterSpec("cookies_jar_file", str, "", "Cookie jar file path."),
        AdapterParameterSpec("ignore_ids", str, "", "Identifiers to ignore, separated by spaces or commas."),
        AdapterParameterSpec("folder_output", str, "", "Folder for multi-username report output."),
        AdapterParameterSpec("proxy", str, "", "Proxy URL such as socks5://127.0.0.1:1080."),
        AdapterParameterSpec("tor_proxy", str, "", "Tor proxy URL."),
        AdapterParameterSpec("i2p_proxy", str, "", "I2P proxy URL."),
        AdapterParameterSpec("with_domains", bool, False, "Enable experimental domain checks for usernames."),
        AdapterParameterSpec("all_sites", bool, False, "Scan all sites."),
        AdapterParameterSpec("top_sites", int, 0, "Number of top-ranked sites to scan; 0 leaves default."),
        AdapterParameterSpec("tags", str, "", "Site tags to include."),
        AdapterParameterSpec("exclude_tags", str, "", "Site tags to exclude."),
        AdapterParameterSpec("sites", str, "", "Limit search to site names, separated by spaces or commas."),
        AdapterParameterSpec("use_disabled_sites", bool, False, "Include disabled sites in search."),
        AdapterParameterSpec("parse_url", str, "", "Parse a page URL and extract usernames/IDs for search."),
        AdapterParameterSpec("self_check", bool, False, "Run database/site self-check mode."),
        AdapterParameterSpec("stats", bool, False, "Show database statistics."),
        AdapterParameterSpec("print_not_found", bool, False, "Print sites where username was not found."),
        AdapterParameterSpec("print_errors", bool, False, "Print request/captcha/country-ban errors."),
        AdapterParameterSpec("verbose", bool, False, "Display extra information and metrics."),
        AdapterParameterSpec("info", bool, False, "Display service information and metrics."),
        AdapterParameterSpec("debug", bool, False, "Display debug information and save responses in debug.log."),
        AdapterParameterSpec("no_color", bool, False, "Disable colored terminal output."),
        AdapterParameterSpec("no_progressbar", bool, False, "Disable progress bar output."),
        AdapterParameterSpec("txt", bool, False, "Create TXT reports."),
        AdapterParameterSpec("csv", bool, False, "Create CSV reports."),
        AdapterParameterSpec("html", bool, False, "Create HTML report."),
        AdapterParameterSpec("pdf", bool, False, "Create PDF report."),
        AdapterParameterSpec("md", bool, False, "Create Markdown report."),
        AdapterParameterSpec("graph", bool, False, "Create graph report."),
        AdapterParameterSpec("json_report", str, "", "Create JSON report of the specified supported type."),
        AdapterParameterSpec("reports_sorting", str, "", "Report sorting method: default or data."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    _add_positionals(tokens, kwargs, "extra_usernames")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "retries", "--retries")
    add_value(tokens, kwargs, "max_connections", "--max-connections")
    add_bool(tokens, kwargs, "no_recursion", "--no-recursion")
    add_bool(tokens, kwargs, "no_extracting", "--no-extracting")
    add_value(tokens, kwargs, "id_type", "--id-type")
    add_bool(tokens, kwargs, "permute", "--permute")
    add_value(tokens, kwargs, "db_file", "--db")
    add_bool(tokens, kwargs, "no_autoupdate", "--no-autoupdate")
    add_bool(tokens, kwargs, "force_update", "--force-update")
    add_value(tokens, kwargs, "cookies_jar_file", "--cookies-jar-file")
    _add_repeated(tokens, kwargs, "ignore_ids", "--ignore-ids")
    add_value(tokens, kwargs, "folder_output", "--folderoutput")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_value(tokens, kwargs, "tor_proxy", "--tor-proxy")
    add_value(tokens, kwargs, "i2p_proxy", "--i2p-proxy")
    add_bool(tokens, kwargs, "with_domains", "--with-domains")
    add_bool(tokens, kwargs, "all_sites", "--all-sites")
    add_value(tokens, kwargs, "top_sites", "--top-sites")
    add_value(tokens, kwargs, "tags", "--tags")
    add_value(tokens, kwargs, "exclude_tags", "--exclude-tags")
    _add_repeated(tokens, kwargs, "sites", "--site")
    add_bool(tokens, kwargs, "use_disabled_sites", "--use-disabled-sites")
    add_value(tokens, kwargs, "parse_url", "--parse")
    add_bool(tokens, kwargs, "self_check", "--self-check")
    add_bool(tokens, kwargs, "stats", "--stats")
    add_bool(tokens, kwargs, "print_not_found", "--print-not-found")
    add_bool(tokens, kwargs, "print_errors", "--print-errors")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "info", "--info")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    add_bool(tokens, kwargs, "no_progressbar", "--no-progressbar")
    add_bool(tokens, kwargs, "txt", "--txt")
    add_bool(tokens, kwargs, "csv", "--csv")
    add_bool(tokens, kwargs, "html", "--html")
    add_bool(tokens, kwargs, "pdf", "--pdf")
    add_bool(tokens, kwargs, "md", "--md")
    add_bool(tokens, kwargs, "graph", "--graph")
    add_value(tokens, kwargs, "json_report", "--json")
    add_value(tokens, kwargs, "reports_sorting", "--reports-sorting")
    return tokens


def _add_positionals(tokens: list[str], kwargs: dict, key: str) -> None:
    tokens.extend(_split_values(kwargs.get(key)))


def _add_repeated(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    for value in _split_values(kwargs.get(key)):
        tokens.extend([flag, value])


def _split_values(value: object) -> list[str]:
    if value in (None, "", False):
        return []
    raw = str(value).replace(",", " ")
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()
