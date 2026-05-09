"""Dedicated adapter metadata for OWASP ZAP."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("quick_out", str, "", "Quick Start report output file."),
        AdapterParameterSpec("quick_progress", bool, False, "Show ASCII progress bars in command mode."),
        AdapterParameterSpec("zapit_url", str, "", "URL for a quick ZAPit reconnaissance scan."),
        AdapterParameterSpec("config", str, "", "Override a key=value configuration pair."),
        AdapterParameterSpec("config_file", str, "", "Properties file with configuration overrides."),
        AdapterParameterSpec("home_dir", str, "", "ZAP home directory."),
        AdapterParameterSpec("install_dir", str, "", "ZAP installation directory."),
        AdapterParameterSpec("new_session", str, "", "Create a new session at this path."),
        AdapterParameterSpec("session", str, "", "Open an existing session path."),
        AdapterParameterSpec("low_mem", bool, False, "Use database storage as much as possible."),
        AdapterParameterSpec("experimental_db", bool, False, "Use the experimental generic database code."),
        AdapterParameterSpec("no_stdout", bool, False, "Disable default stdout logging."),
        AdapterParameterSpec("log_level", str, "", "Log level, for example INFO or DEBUG."),
        AdapterParameterSpec("silent", bool, False, "Disable unsolicited requests such as update checks."),
        AdapterParameterSpec("addon_install", str, "", "Install an add-on by ID."),
        AdapterParameterSpec("addon_install_all", bool, False, "Install all marketplace add-ons."),
        AdapterParameterSpec("addon_uninstall", str, "", "Uninstall an add-on by ID."),
        AdapterParameterSpec("addon_update", bool, False, "Update changed marketplace add-ons."),
        AdapterParameterSpec("addon_list", bool, False, "List installed add-ons."),
        AdapterParameterSpec("script", str, "", "Run or load a script file."),
        AdapterParameterSpec("support_info", bool, False, "Print support and troubleshooting details."),
        AdapterParameterSpec("sbom_zip", str, "", "Create a zip containing available SBOMs."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "quick_out", "-quickout")
    add_bool(tokens, kwargs, "quick_progress", "-quickprogress")
    add_value(tokens, kwargs, "zapit_url", "-zapit")
    add_value(tokens, kwargs, "config", "-config")
    add_value(tokens, kwargs, "config_file", "-configfile")
    add_value(tokens, kwargs, "home_dir", "-dir")
    add_value(tokens, kwargs, "install_dir", "-installdir")
    add_value(tokens, kwargs, "new_session", "-newsession")
    add_value(tokens, kwargs, "session", "-session")
    add_bool(tokens, kwargs, "low_mem", "-lowmem")
    add_bool(tokens, kwargs, "experimental_db", "-experimentaldb")
    add_bool(tokens, kwargs, "no_stdout", "-nostdout")
    add_value(tokens, kwargs, "log_level", "-loglevel")
    add_bool(tokens, kwargs, "silent", "-silent")
    add_value(tokens, kwargs, "addon_install", "-addoninstall")
    add_bool(tokens, kwargs, "addon_install_all", "-addoninstallall")
    add_value(tokens, kwargs, "addon_uninstall", "-addonuninstall")
    add_bool(tokens, kwargs, "addon_update", "-addonupdate")
    add_bool(tokens, kwargs, "addon_list", "-addonlist")
    add_value(tokens, kwargs, "script", "-script")
    add_bool(tokens, kwargs, "support_info", "-suppinfo")
    add_value(tokens, kwargs, "sbom_zip", "-sbomzip")
    return tokens
