"""Dedicated adapter metadata for Prowler."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, add_values


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("profile", str, "", "AWS credential profile for the aws provider."),
        AdapterParameterSpec("region", str, "", "AWS region filter for the aws provider."),
        AdapterParameterSpec("services", str, "", "Comma- or space-separated services to include."),
        AdapterParameterSpec("severity", str, "", "Comma- or space-separated severities to include."),
        AdapterParameterSpec("checks", str, "", "Comma- or space-separated checks to include."),
        AdapterParameterSpec("excluded_checks", str, "", "Comma- or space-separated checks to exclude."),
        AdapterParameterSpec("excluded_services", str, "", "Comma- or space-separated services to exclude."),
        AdapterParameterSpec("output_formats", str, "", "Comma- or space-separated output formats."),
        AdapterParameterSpec("output_directory", str, "", "Directory for Prowler output files."),
        AdapterParameterSpec("output_filename", str, "", "Base filename for Prowler output files."),
        AdapterParameterSpec("list_checks", bool, False, "List checks for the selected provider."),
        AdapterParameterSpec("list_services", bool, False, "List services for the selected provider."),
        AdapterParameterSpec("no_banner", bool, False, "Hide the Prowler banner."),
        AdapterParameterSpec("no_color", bool, False, "Disable colorized output."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
        AdapterParameterSpec("log_level", str, "", "Logging level: DEBUG, INFO, WARNING, ERROR, or CRITICAL."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "profile", "--profile")
    add_value(tokens, kwargs, "region", "--region")
    add_values(tokens, kwargs, "services", "--service")
    add_values(tokens, kwargs, "severity", "--severity")
    add_values(tokens, kwargs, "checks", "--check")
    add_values(tokens, kwargs, "excluded_checks", "--excluded-check")
    add_values(tokens, kwargs, "excluded_services", "--excluded-service")
    add_values(tokens, kwargs, "output_formats", "--output-formats")
    add_value(tokens, kwargs, "output_directory", "--output-directory")
    add_value(tokens, kwargs, "output_filename", "--output-filename")
    add_bool(tokens, kwargs, "list_checks", "--list-checks")
    add_bool(tokens, kwargs, "list_services", "--list-services")
    add_bool(tokens, kwargs, "no_banner", "--no-banner")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_value(tokens, kwargs, "log_level", "--log-level")
    return tokens
