"""Dedicated adapter metadata for gitleaks."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("redact", bool, True, "Redact secrets in output."),
        AdapterParameterSpec("log_opts", str, "", "Git log options for detect scans."),
        AdapterParameterSpec("config_path", str, "", "Path to gitleaks config file."),
        AdapterParameterSpec("baseline_path", str, "", "Path to baseline report."),
        AdapterParameterSpec("ignore_path", str, "", "Path to .gitleaksignore file."),
        AdapterParameterSpec("enable_rule", str, "", "Only enable specific rule IDs."),
        AdapterParameterSpec("exit_code", int, 0, "Exit code when leaks are found; 0 leaves default."),
        AdapterParameterSpec("follow_symlinks", bool, False, "Scan files that are symlinks to other files."),
        AdapterParameterSpec("ignore_allow", bool, False, "Ignore gitleaks:allow comments."),
        AdapterParameterSpec("max_decode_depth", int, 0, "Recursive decode depth; 0 leaves default."),
        AdapterParameterSpec("max_archive_depth", int, 0, "Nested archive depth; 0 leaves default."),
        AdapterParameterSpec("max_target_mb", int, 0, "Maximum target file size in MB; 0 leaves default."),
        AdapterParameterSpec("report_format", str, "", "Report format, for example json, csv, junit, sarif."),
        AdapterParameterSpec("report_path", str, "", "Report output path."),
        AdapterParameterSpec("report_template", str, "", "Template file for report generation."),
        AdapterParameterSpec("log_level", str, "", "Log level: trace, debug, info, warn, error, fatal."),
        AdapterParameterSpec("no_banner", bool, False, "Suppress banner output."),
        AdapterParameterSpec("no_color", bool, False, "Disable color output."),
        AdapterParameterSpec("verbose", bool, False, "Show verbose output from scan."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    if kwargs.get("redact", True):
        tokens.append("--redact")
    add_value(tokens, kwargs, "log_opts", "--log-opts")
    add_value(tokens, kwargs, "config_path", "--config")
    add_value(tokens, kwargs, "baseline_path", "--baseline-path")
    add_value(tokens, kwargs, "ignore_path", "--gitleaks-ignore-path")
    add_value(tokens, kwargs, "enable_rule", "--enable-rule")
    add_value(tokens, kwargs, "exit_code", "--exit-code")
    add_bool(tokens, kwargs, "follow_symlinks", "--follow-symlinks")
    add_bool(tokens, kwargs, "ignore_allow", "--ignore-gitleaks-allow")
    add_value(tokens, kwargs, "max_decode_depth", "--max-decode-depth")
    add_value(tokens, kwargs, "max_archive_depth", "--max-archive-depth")
    add_value(tokens, kwargs, "max_target_mb", "--max-target-megabytes")
    add_value(tokens, kwargs, "report_format", "--report-format")
    add_value(tokens, kwargs, "report_path", "--report-path")
    add_value(tokens, kwargs, "report_template", "--report-template")
    add_value(tokens, kwargs, "log_level", "--log-level")
    add_bool(tokens, kwargs, "no_banner", "--no-banner")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    return tokens
