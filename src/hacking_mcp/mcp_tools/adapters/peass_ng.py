"""Dedicated adapter metadata for PEASS-ng."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("all_checks", bool, False, "Run all checks except regex checks."),
        AdapterParameterSpec("extra_enum", bool, False, "Run extra enumeration checks."),
        AdapterParameterSpec("regex_checks", bool, False, "Enable regex/API-key filesystem checks."),
        AdapterParameterSpec("stealth", bool, False, "Use superfast/stealth mode."),
        AdapterParameterSpec(
            "password",
            str,
            "",
            "Password for sudo/user bruteforce checks; may be present in process/audit logs.",
        ),
        AdapterParameterSpec("debug", bool, False, "Print debug/timing information."),
        AdapterParameterSpec("auto_network_scan", bool, False, "Run automatic network scan and connectivity checks."),
        AdapterParameterSpec("discover_net", str, "", "Network CIDR for host discovery with -d."),
        AdapterParameterSpec("ports", str, "", "Ports used with -p for network scan/discovery."),
        AdapterParameterSpec("scan_ip", str, "", "Single IP to scan with -i."),
        AdapterParameterSpec("port_forward", str, "", "Port-forward mapping LOCAL_IP:LOCAL_PORT:REMOTE_IP:REMOTE_PORT."),
        AdapterParameterSpec("firmware_path", str, "", "Folder path for firmware/filesystem analysis."),
        AdapterParameterSpec("selected_checks", str, "", "Comma-separated LinPEAS checks for -o."),
        AdapterParameterSpec("wait", bool, False, "Wait between big blocks of checks."),
        AdapterParameterSpec("force_linpeas", bool, False, "Force LinPEAS execution."),
        AdapterParameterSpec("force_macpeas", bool, False, "Force MacPEAS execution."),
        AdapterParameterSpec("quiet", bool, False, "Do not show banner."),
        AdapterParameterSpec("no_color", bool, False, "Disable colors."),
        AdapterParameterSpec("help", bool, False, "Show LinPEAS help."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "all_checks", "-a")
    add_bool(tokens, kwargs, "extra_enum", "-e")
    add_bool(tokens, kwargs, "regex_checks", "-r")
    add_bool(tokens, kwargs, "stealth", "-s")
    add_value(tokens, kwargs, "password", "-P")
    add_bool(tokens, kwargs, "debug", "-D")
    add_bool(tokens, kwargs, "auto_network_scan", "-t")
    add_value(tokens, kwargs, "discover_net", "-d")
    add_value(tokens, kwargs, "ports", "-p")
    add_value(tokens, kwargs, "scan_ip", "-i")
    add_value(tokens, kwargs, "port_forward", "-F")
    add_value(tokens, kwargs, "firmware_path", "-f")
    add_value(tokens, kwargs, "selected_checks", "-o")
    add_bool(tokens, kwargs, "wait", "-w")
    add_bool(tokens, kwargs, "force_linpeas", "-L")
    add_bool(tokens, kwargs, "force_macpeas", "-M")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_bool(tokens, kwargs, "no_color", "-N")
    add_bool(tokens, kwargs, "help", "-h")
    return tokens
