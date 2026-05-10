"""Dedicated adapter metadata for TruffleHog."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("json_output", bool, False, "Output in JSON format."),
        AdapterParameterSpec("github_actions", bool, False, "Output in GitHub Actions format."),
        AdapterParameterSpec("concurrency", int, 0, "Number of concurrent workers; 0 leaves default."),
        AdapterParameterSpec("no_verification", bool, False, "Do not verify discovered results."),
        AdapterParameterSpec("results", str, "", "Result statuses to output, for example verified,unknown."),
        AdapterParameterSpec("no_color", bool, False, "Disable colorized output."),
        AdapterParameterSpec("allow_verification_overlap", bool, False, "Allow verification overlap across detectors."),
        AdapterParameterSpec("filter_unverified", bool, False, "Only output first unverified result per chunk/detector."),
        AdapterParameterSpec("filter_entropy", float, 0.0, "Filter unverified results by Shannon entropy; 0 leaves default."),
        AdapterParameterSpec("config_path", str, "", "Path to TruffleHog configuration file."),
        AdapterParameterSpec("print_avg_detector_time", bool, False, "Print average time spent on each detector."),
        AdapterParameterSpec("fail", bool, False, "Return TruffleHog leak-detected exit code when results are found."),
        AdapterParameterSpec("log_level", str, "", "Logging verbosity level; empty leaves default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "json_output", "--json")
    add_bool(tokens, kwargs, "github_actions", "--github-actions")
    add_value(tokens, kwargs, "concurrency", "--concurrency")
    add_bool(tokens, kwargs, "no_verification", "--no-verification")
    add_value(tokens, kwargs, "results", "--results")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    add_bool(tokens, kwargs, "allow_verification_overlap", "--allow-verification-overlap")
    add_bool(tokens, kwargs, "filter_unverified", "--filter-unverified")
    add_value(tokens, kwargs, "filter_entropy", "--filter-entropy")
    add_value(tokens, kwargs, "config_path", "--config")
    add_bool(tokens, kwargs, "print_avg_detector_time", "--print-avg-detector-time")
    add_bool(tokens, kwargs, "fail", "--fail")
    add_value(tokens, kwargs, "log_level", "--log-level")
    return tokens
