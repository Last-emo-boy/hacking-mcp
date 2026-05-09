"""Dedicated adapter metadata for Sherlock."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("verbose", bool, False, "Show extra debug output."),
        AdapterParameterSpec("folder_output", str, "", "Folder for output when checking multiple usernames."),
        AdapterParameterSpec("output_file", str, "", "Output file for a single username."),
        AdapterParameterSpec("csv_output", bool, False, "Write CSV output."),
        AdapterParameterSpec("xlsx_output", bool, False, "Write XLSX output."),
        AdapterParameterSpec("sites", str, "", "Comma-separated Sherlock site names to check."),
        AdapterParameterSpec("site_list", str, "", "Backward-compatible comma-separated alias for sites."),
        AdapterParameterSpec("proxy", str, "", "Proxy URL to use for requests."),
        AdapterParameterSpec("dump_response", bool, False, "Dump HTTP responses for debugging."),
        AdapterParameterSpec("json_file", str, "", "JSON output file path."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("print_all", bool, False, "Print sites where the username was not found."),
        AdapterParameterSpec("print_found", bool, False, "Print sites where the username was found."),
        AdapterParameterSpec("no_color", bool, False, "Disable colored terminal output."),
        AdapterParameterSpec("browse", bool, False, "Open found results in a browser."),
        AdapterParameterSpec("local", bool, False, "Use the local data.json file."),
        AdapterParameterSpec("nsfw", bool, False, "Include NSFW sites from the site data."),
        AdapterParameterSpec("txt_output", bool, False, "Write TXT output."),
        AdapterParameterSpec("ignore_exclusions", bool, False, "Ignore site exclusion markers."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_value(tokens, kwargs, "folder_output", "--folderoutput")
    add_value(tokens, kwargs, "output_file", "--output")
    add_bool(tokens, kwargs, "csv_output", "--csv")
    add_bool(tokens, kwargs, "xlsx_output", "--xlsx")
    _add_sites(tokens, kwargs, "sites")
    _add_sites(tokens, kwargs, "site_list")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_bool(tokens, kwargs, "dump_response", "--dump-response")
    add_value(tokens, kwargs, "json_file", "--json")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_bool(tokens, kwargs, "print_all", "--print-all")
    add_bool(tokens, kwargs, "print_found", "--print-found")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    add_bool(tokens, kwargs, "browse", "--browse")
    add_bool(tokens, kwargs, "local", "--local")
    add_bool(tokens, kwargs, "nsfw", "--nsfw")
    add_bool(tokens, kwargs, "txt_output", "--txt")
    add_bool(tokens, kwargs, "ignore_exclusions", "--ignore-exclusions")
    return tokens


def _add_sites(tokens: list[str], kwargs: dict, key: str) -> None:
    sites = str(kwargs.get(key) or "")
    for site in (item.strip() for item in sites.split(",")):
        if site:
            tokens.extend(["--site", site])
