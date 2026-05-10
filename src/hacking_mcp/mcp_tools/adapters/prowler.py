"""Dedicated adapter metadata for Prowler."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("profile", str, "", "Cloud credential profile when supported."),
        AdapterParameterSpec("region", str, "", "Cloud region when supported."),
        AdapterParameterSpec("services", str, "", "Comma-separated service names when supported."),
        AdapterParameterSpec("severity", str, "", "Severity filter when supported."),
        AdapterParameterSpec("provider", str, "", "Cloud/provider selector when supported."),
        AdapterParameterSpec("checks", str, "", "Comma-separated checks to include when supported."),
        AdapterParameterSpec("excluded_checks", str, "", "Comma-separated checks to exclude when supported."),
        AdapterParameterSpec("output_format", str, "", "Output format when supported."),
        AdapterParameterSpec("ignore_unfixed", bool, False, "Ignore unfixed vulnerabilities when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "profile", "--profile")
    add_value(tokens, kwargs, "region", "--region")
    add_value(tokens, kwargs, "services", "--services")
    add_value(tokens, kwargs, "severity", "--severity")
    add_value(tokens, kwargs, "provider", "--provider")
    add_value(tokens, kwargs, "checks", "--checks")
    add_value(tokens, kwargs, "excluded_checks", "--excluded-checks")
    add_value(tokens, kwargs, "output_format", "--output")
    add_bool(tokens, kwargs, "ignore_unfixed", "--ignore-unfixed")
    return tokens
