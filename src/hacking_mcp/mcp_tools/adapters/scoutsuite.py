"""Dedicated adapter metadata for ScoutSuite."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, add_values


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("profile", str, "", "AWS credential profile."),
        AdapterParameterSpec("regions", str, "", "Comma- or space-separated AWS regions to include."),
        AdapterParameterSpec("excluded_regions", str, "", "Comma- or space-separated AWS regions to exclude."),
        AdapterParameterSpec("services", str, "", "Comma- or space-separated services to include."),
        AdapterParameterSpec("skipped_services", str, "", "Comma- or space-separated services to skip."),
        AdapterParameterSpec("list_services", bool, False, "List available services for the selected provider."),
        AdapterParameterSpec("result_format", str, "", "Result format: json or sqlite."),
        AdapterParameterSpec("report_dir", str, "", "Report output directory."),
        AdapterParameterSpec("report_name", str, "", "Report name."),
        AdapterParameterSpec("timestamp", str, "", "Timestamp suffix for generated reports."),
        AdapterParameterSpec("fetch_local", bool, False, "Use local data previously fetched."),
        AdapterParameterSpec("update", bool, False, "Reload existing data and update in-scope data."),
        AdapterParameterSpec("ruleset", str, "", "Ruleset file used during analysis."),
        AdapterParameterSpec("exceptions", str, "", "Exceptions file used during analysis."),
        AdapterParameterSpec("force_write", bool, False, "Overwrite existing output files."),
        AdapterParameterSpec("debug", bool, False, "Print stack traces on errors."),
        AdapterParameterSpec("quiet", bool, False, "Disable CLI output."),
        AdapterParameterSpec("no_browser", bool, False, "Do not automatically open the report."),
        AdapterParameterSpec("max_workers", int, 0, "Maximum worker threads; 0 leaves ScoutSuite default."),
        AdapterParameterSpec("max_rate", int, 0, "Maximum API requests per second; 0 leaves unset."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "profile", "--profile")
    add_values(tokens, kwargs, "regions", "--regions")
    add_values(tokens, kwargs, "excluded_regions", "--exclude-regions")
    add_values(tokens, kwargs, "services", "--services")
    add_values(tokens, kwargs, "skipped_services", "--skip")
    add_bool(tokens, kwargs, "list_services", "--list-services")
    add_value(tokens, kwargs, "result_format", "--result-format")
    add_value(tokens, kwargs, "report_dir", "--report-dir")
    add_value(tokens, kwargs, "report_name", "--report-name")
    add_value(tokens, kwargs, "timestamp", "--timestamp")
    add_bool(tokens, kwargs, "fetch_local", "--local")
    add_bool(tokens, kwargs, "update", "--update")
    add_value(tokens, kwargs, "ruleset", "--ruleset")
    add_value(tokens, kwargs, "exceptions", "--exceptions")
    add_bool(tokens, kwargs, "force_write", "--force")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_bool(tokens, kwargs, "no_browser", "--no-browser")
    add_value(tokens, kwargs, "max_workers", "--max-workers")
    add_value(tokens, kwargs, "max_rate", "--max-rate")
    return tokens
