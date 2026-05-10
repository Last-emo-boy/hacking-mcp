"""Dedicated adapter metadata for Pacu."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, add_values


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("session", str, "", "Pacu session name."),
        AdapterParameterSpec("activate_session", bool, False, "Activate the named session."),
        AdapterParameterSpec("new_session", str, "", "Create a new Pacu session."),
        AdapterParameterSpec("set_keys", str, "", "Set AWS keys: alias, access id, secret key, token."),
        AdapterParameterSpec("import_keys", str, "", "Import AWS keys from an AWS profile name."),
        AdapterParameterSpec("module_name", str, "", "Pacu module name used with module actions."),
        AdapterParameterSpec("data", str, "", "Local database service name or all."),
        AdapterParameterSpec("module_args", str, "", "Module arguments passed to the selected module."),
        AdapterParameterSpec("list_modules", bool, False, "List available modules."),
        AdapterParameterSpec("pacu_help", bool, False, "Show the Pacu help window."),
        AdapterParameterSpec("module_info", bool, False, "Show information for module_name."),
        AdapterParameterSpec("execute_module", bool, False, "Execute module_name."),
        AdapterParameterSpec("set_regions", str, "", "Space-separated AWS regions or all."),
        AdapterParameterSpec("whoami", bool, False, "Display information about the current IAM user."),
        AdapterParameterSpec("version", bool, False, "Display Pacu version."),
        AdapterParameterSpec("quiet", bool, False, "Do not print the banner on startup."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "session", "--session")
    add_bool(tokens, kwargs, "activate_session", "--activate-session")
    add_value(tokens, kwargs, "new_session", "--new-session")
    add_value(tokens, kwargs, "set_keys", "--set-keys")
    add_value(tokens, kwargs, "import_keys", "--import-keys")
    add_value(tokens, kwargs, "module_name", "--module-name")
    add_value(tokens, kwargs, "data", "--data")
    add_value(tokens, kwargs, "module_args", "--module-args")
    add_bool(tokens, kwargs, "list_modules", "--list-modules")
    add_bool(tokens, kwargs, "pacu_help", "--pacu-help")
    add_bool(tokens, kwargs, "module_info", "--module-info")
    add_bool(tokens, kwargs, "execute_module", "--exec")
    add_values(tokens, kwargs, "set_regions", "--set-regions")
    add_bool(tokens, kwargs, "whoami", "--whoami")
    add_bool(tokens, kwargs, "version", "--version")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    return tokens
