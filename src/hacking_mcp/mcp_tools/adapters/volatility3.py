"""Dedicated adapter metadata for Volatility 3."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("config_file", str, "", "JSON configuration file to load."),
        AdapterParameterSpec("parallelism", str, "", "Parallelism mode: processes, threads, or off."),
        AdapterParameterSpec("extend", str, "", "Configuration extension in name=value form."),
        AdapterParameterSpec("plugin_dirs", str, "", "Semicolon-separated plugin search paths."),
        AdapterParameterSpec("symbol_dirs", str, "", "Semicolon-separated symbol search paths."),
        AdapterParameterSpec("symbol_dir", str, "", "Backward-compatible alias for symbol_dirs."),
        AdapterParameterSpec("verbosity", int, 0, "Number of -v flags to emit; 0 leaves default."),
        AdapterParameterSpec("log_file", str, "", "Log file path."),
        AdapterParameterSpec("output_dir", str, "", "Directory for generated plugin files."),
        AdapterParameterSpec("quiet", bool, False, "Mute progress feedback."),
        AdapterParameterSpec("renderer", str, "", "Output renderer such as quick, pretty, json, or jsonl."),
        AdapterParameterSpec("write_config", bool, False, "Write config.json for the current run."),
        AdapterParameterSpec("save_config", str, "", "Save generated configuration to this file."),
        AdapterParameterSpec("clear_cache", bool, False, "Clear short-term cached items."),
        AdapterParameterSpec("cache_path", str, "", "Override the cache directory."),
        AdapterParameterSpec("offline", bool, False, "Disable online symbol lookups."),
        AdapterParameterSpec("remote_isf_url", str, "", "Remote ISF symbol URL."),
        AdapterParameterSpec("filters", str, "", "Output filter expression."),
        AdapterParameterSpec("hide_columns", str, "", "Space-separated output column prefixes to hide."),
        AdapterParameterSpec("single_location", str, "", "Explicit single-location URI."),
        AdapterParameterSpec("stackers", str, "", "Stackers to use."),
        AdapterParameterSpec("single_swap_locations", str, "", "Comma-separated swap file locations."),
        AdapterParameterSpec("plugin", str, "windows.pslist", "Volatility plugin to execute."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "config_file", "--config")
    add_value(tokens, kwargs, "parallelism", "--parallelism")
    add_value(tokens, kwargs, "extend", "--extend")
    add_value(tokens, kwargs, "plugin_dirs", "--plugin-dirs")
    _add_symbol_dirs(tokens, kwargs)
    tokens.extend(["-v"] * min(int_value(kwargs, "verbosity"), 6))
    add_value(tokens, kwargs, "log_file", "--log")
    add_value(tokens, kwargs, "output_dir", "--output-dir")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_value(tokens, kwargs, "renderer", "--renderer")
    add_bool(tokens, kwargs, "write_config", "--write-config")
    add_value(tokens, kwargs, "save_config", "--save-config")
    add_bool(tokens, kwargs, "clear_cache", "--clear-cache")
    add_value(tokens, kwargs, "cache_path", "--cache-path")
    add_bool(tokens, kwargs, "offline", "--offline")
    add_value(tokens, kwargs, "remote_isf_url", "--remote-isf-url")
    add_value(tokens, kwargs, "filters", "--filters")
    add_value(tokens, kwargs, "hide_columns", "--hide-columns")
    add_value(tokens, kwargs, "single_location", "--single-location")
    add_value(tokens, kwargs, "stackers", "--stackers")
    add_value(tokens, kwargs, "single_swap_locations", "--single-swap-locations")
    _add_plugin(tokens, kwargs)
    return tokens


def _add_symbol_dirs(tokens: list[str], kwargs: dict) -> None:
    value = kwargs.get("symbol_dirs") or kwargs.get("symbol_dir")
    if value:
        tokens.extend(["--symbol-dirs", str(value)])


def _add_plugin(tokens: list[str], kwargs: dict) -> None:
    plugin = str(kwargs.get("plugin") or "").strip()
    if plugin:
        tokens.append(plugin)
