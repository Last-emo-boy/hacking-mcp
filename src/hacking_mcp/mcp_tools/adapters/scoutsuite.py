"""Dedicated adapter metadata for ScoutSuite."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("profile", str, "", "Cloud credential profile when supported."),
        AdapterParameterSpec("region", str, "", "Cloud region when supported."),
        AdapterParameterSpec("services", str, "", "Comma-separated service names when supported."),
        AdapterParameterSpec("severity", str, "", "Severity filter when supported."),
        AdapterParameterSpec("session", str, "", "Cloud assessment session/profile when supported."),
        AdapterParameterSpec("module", str, "", "Cloud module/service module when supported."),
        AdapterParameterSpec("regions", str, "", "Comma-separated cloud regions when supported."),
        AdapterParameterSpec("report_dir", str, "", "Report directory when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "profile", "--profile")
    add_value(tokens, kwargs, "region", "--region")
    add_value(tokens, kwargs, "services", "--services")
    add_value(tokens, kwargs, "severity", "--severity")
    add_value(tokens, kwargs, "session", "--session")
    add_value(tokens, kwargs, "module", "--module")
    add_value(tokens, kwargs, "regions", "--regions")
    add_value(tokens, kwargs, "report_dir", "--report-dir")
    return tokens
