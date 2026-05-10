"""Dedicated adapter metadata for Trivy."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("command", str, "image", "Trivy command such as image, fs, repo, k8s, config, rootfs, vm, or sbom."),
        AdapterParameterSpec("severity", str, "", "Comma-separated severities to display."),
        AdapterParameterSpec("output_format", str, "", "Output format such as table, json, sarif, cyclonedx, or template."),
        AdapterParameterSpec("output_file", str, "", "Output file name."),
        AdapterParameterSpec("template", str, "", "Output template path for template format."),
        AdapterParameterSpec("ignorefile", str, "", "Path to .trivyignore file."),
        AdapterParameterSpec("exit_code", int, 0, "Exit code when issues are found; 0 leaves default."),
        AdapterParameterSpec("ignore_unfixed", bool, False, "Display only fixed vulnerabilities."),
        AdapterParameterSpec("scanners", str, "", "Comma-separated scanners such as vuln,secret,misconfig,license."),
        AdapterParameterSpec("skip_dirs", str, "", "Comma-separated directories or globs to skip."),
        AdapterParameterSpec("skip_files", str, "", "Comma-separated files or globs to skip."),
        AdapterParameterSpec("offline_scan", bool, False, "Do not issue API requests to identify dependencies."),
        AdapterParameterSpec("parallel", int, 0, "Parallel scan workers; 0 leaves Trivy default."),
        AdapterParameterSpec("timeout", str, "", "Timeout duration such as 5m or 30s."),
        AdapterParameterSpec("config", str, "", "Trivy config path."),
        AdapterParameterSpec("cache_dir", str, "", "Trivy cache directory."),
        AdapterParameterSpec("quiet", bool, False, "Suppress progress bar and log output."),
        AdapterParameterSpec("debug", bool, False, "Enable debug mode."),
        AdapterParameterSpec("insecure", bool, False, "Allow insecure server connections."),
    ]


def build_options(kwargs: dict) -> list[str]:
    command = str(kwargs.get("command") or "image").strip() or "image"
    tokens: list[str] = [command]
    add_value(tokens, kwargs, "severity", "--severity")
    add_value(tokens, kwargs, "output_format", "--format")
    add_value(tokens, kwargs, "output_file", "--output")
    add_value(tokens, kwargs, "template", "--template")
    add_value(tokens, kwargs, "ignorefile", "--ignorefile")
    add_value(tokens, kwargs, "exit_code", "--exit-code")
    add_bool(tokens, kwargs, "ignore_unfixed", "--ignore-unfixed")
    add_value(tokens, kwargs, "scanners", "--scanners")
    add_value(tokens, kwargs, "skip_dirs", "--skip-dirs")
    add_value(tokens, kwargs, "skip_files", "--skip-files")
    add_bool(tokens, kwargs, "offline_scan", "--offline-scan")
    add_value(tokens, kwargs, "parallel", "--parallel")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "config", "--config")
    add_value(tokens, kwargs, "cache_dir", "--cache-dir")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "insecure", "--insecure")
    return tokens
