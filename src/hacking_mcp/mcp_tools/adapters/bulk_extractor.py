"""Dedicated adapter metadata for Bulk Extractor."""

import shlex
from typing import Any

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("output_dir", str, "bulk_output", "Output directory for extracted feature files."),
        AdapterParameterSpec("banner_file", str, "", "File prepended to generated feature files."),
        AdapterParameterSpec("alert_list", str, "", "Alert list file of terms to flag specially."),
        AdapterParameterSpec("stop_list", str, "", "Stop list file of terms to suppress from main output."),
        AdapterParameterSpec("sampling", str, "", "Random sampling parameter in frac[:passes] form."),
        AdapterParameterSpec("print_path", str, "", "Print a path[:length][/h][/r] from the image instead of a normal scan."),
        AdapterParameterSpec("find_patterns", str, "", "Patterns to search for; comma- or shell-separated values repeat -f."),
        AdapterParameterSpec("find_files", str, "", "Files containing search patterns; comma- or shell-separated values repeat -F."),
        AdapterParameterSpec("context_window", int, 0, "Context window size in bytes; 0 leaves default."),
        AdapterParameterSpec("page_size", str, "", "Page size in bytes."),
        AdapterParameterSpec("margin_size", str, "", "Margin size in bytes."),
        AdapterParameterSpec("threads", int, 0, "Number of worker threads; 0 leaves default."),
        AdapterParameterSpec("no_threads", bool, False, "Read and process data in the primary thread."),
        AdapterParameterSpec("max_depth", int, 0, "Maximum recursion depth; 0 leaves default."),
        AdapterParameterSpec("scanner_dirs", str, "", "Scanner library directories; comma- or shell-separated values repeat -P."),
        AdapterParameterSpec("recursive", bool, False, "Treat the target as a directory to recursively explore."),
        AdapterParameterSpec("settings", str, "", "Scanner config settings in name=value form; comma- or shell-separated values repeat -S."),
        AdapterParameterSpec("scan_range", str, "", "Input offset range as start[-end]."),
        AdapterParameterSpec("page_start", int, 0, "Starting page number; 0 leaves default."),
        AdapterParameterSpec("exclusive_scanner", str, "", "Disable all scanners except the named scanner."),
        AdapterParameterSpec("enabled_scanners", str, "", "Scanners to enable; comma- or shell-separated values repeat -e."),
        AdapterParameterSpec("disabled_scanners", str, "", "Scanners to disable; comma- or shell-separated values repeat -x."),
        AdapterParameterSpec("quiet", bool, False, "Suppress status and performance output."),
        AdapterParameterSpec("info_scanners", bool, False, "Report information about each scanner."),
        AdapterParameterSpec("version", bool, False, "Print the bulk_extractor version."),
        AdapterParameterSpec("no_notify", bool, False, "Disable real-time notification."),
        AdapterParameterSpec("legacy_notification", bool, False, "Use version 1.0 console notification output."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "output_dir", "-o")
    add_value(tokens, kwargs, "banner_file", "-b")
    add_value(tokens, kwargs, "alert_list", "-r")
    add_value(tokens, kwargs, "stop_list", "-w")
    add_value(tokens, kwargs, "sampling", "-s")
    add_value(tokens, kwargs, "print_path", "-p")
    _add_repeated(tokens, kwargs, "find_patterns", "-f")
    _add_repeated(tokens, kwargs, "find_files", "-F")
    _add_positive_int(tokens, kwargs, "context_window", "-C")
    add_value(tokens, kwargs, "page_size", "-G")
    add_value(tokens, kwargs, "margin_size", "-g")
    _add_positive_int(tokens, kwargs, "threads", "-j")
    add_bool(tokens, kwargs, "no_threads", "-J")
    _add_positive_int(tokens, kwargs, "max_depth", "-M")
    _add_repeated(tokens, kwargs, "scanner_dirs", "-P")
    add_bool(tokens, kwargs, "recursive", "-R")
    _add_repeated(tokens, kwargs, "settings", "-S")
    add_value(tokens, kwargs, "scan_range", "-Y")
    _add_positive_int(tokens, kwargs, "page_start", "-z")
    add_value(tokens, kwargs, "exclusive_scanner", "-E")
    _add_repeated(tokens, kwargs, "enabled_scanners", "-e")
    _add_repeated(tokens, kwargs, "disabled_scanners", "-x")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_bool(tokens, kwargs, "info_scanners", "-H")
    add_bool(tokens, kwargs, "version", "-V")
    add_bool(tokens, kwargs, "no_notify", "-0")
    add_bool(tokens, kwargs, "legacy_notification", "-1")
    return tokens


def _add_positive_int(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    value = int_value(kwargs, key)
    if value > 0:
        tokens.extend([flag, str(value)])


def _add_repeated(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    for value in _split_values(kwargs.get(key)):
        tokens.extend([flag, value])


def _split_values(value: Any) -> list[str]:
    if value in (None, "", 0, False):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "", 0, False)]
    raw = str(value).replace(",", " ")
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()
