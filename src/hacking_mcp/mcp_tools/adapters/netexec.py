"""Dedicated adapter metadata for NetExec."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("ports", str, "", "Ports or ranges, for example 80,443 or 1-1000."),
        AdapterParameterSpec(
            "scan_type",
            str,
            "",
            "Optional scan profile: syn, tcp, udp, ping, or empty for tool default.",
        ),
        AdapterParameterSpec("service_version", bool, False, "Request service/version detection when supported."),
        AdapterParameterSpec("os_detection", bool, False, "Request OS detection when supported."),
        AdapterParameterSpec("default_scripts", bool, False, "Run default safe scripts when supported."),
        AdapterParameterSpec("timing", int, 0, "Timing profile 0-5 when supported; 0 leaves default."),
        AdapterParameterSpec("top_ports", int, 0, "Scan top N ports when supported; 0 disables."),
        AdapterParameterSpec("rate", int, 0, "Packet/request rate limit when supported; 0 leaves default."),
        AdapterParameterSpec("domain", str, "", "Active Directory domain when supported."),
        AdapterParameterSpec("username", str, "", "Username for authorized AD assessment."),
        AdapterParameterSpec(
            "password",
            str,
            "",
            "Password for lab/authorized use; may be present in process/audit logs.",
        ),
        AdapterParameterSpec("hashes", str, "", "NTLM hashes when supported."),
        AdapterParameterSpec("dc_ip", str, "", "Domain controller IP address when supported."),
        AdapterParameterSpec("nameserver", str, "", "DNS nameserver when supported."),
        AdapterParameterSpec("interface", str, "", "Network interface name when supported."),
        AdapterParameterSpec("collection_method", str, "", "Collection method, for example All or Default."),
        AdapterParameterSpec("lhost", str, "", "Listener host for authorized lab use."),
        AdapterParameterSpec("lport", int, 0, "Listener port when supported; 0 leaves default."),
        AdapterParameterSpec("session_id", str, "", "Session identifier when supported."),
        AdapterParameterSpec("listener", str, "", "Listener/profile name when supported."),
        AdapterParameterSpec("protocol", str, "", "Protocol selector when supported."),
        AdapterParameterSpec("users_file", str, "", "Username list path when supported."),
        AdapterParameterSpec("passwords_file", str, "", "Password list path when supported."),
        AdapterParameterSpec("kerberos", bool, False, "Use Kerberos authentication when supported."),
        AdapterParameterSpec("local_auth", bool, False, "Use local authentication when supported."),
        AdapterParameterSpec("target_ip", str, "", "Target/DC IP override when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "ports", "-p")
    _add_scan_type(tokens, kwargs)
    add_bool(tokens, kwargs, "service_version", "-sV")
    add_bool(tokens, kwargs, "os_detection", "-O")
    add_bool(tokens, kwargs, "default_scripts", "-sC")
    timing = int_value(kwargs, "timing")
    if timing:
        tokens.append(f"-T{timing}")
    add_value(tokens, kwargs, "top_ports", "--top-ports")
    add_value(tokens, kwargs, "rate", "--rate")
    add_value(tokens, kwargs, "domain", "-d")
    add_value(tokens, kwargs, "username", "-u")
    add_value(tokens, kwargs, "password", "-p")
    add_value(tokens, kwargs, "hashes", "-H")
    add_value(tokens, kwargs, "dc_ip", "-dc-ip")
    add_value(tokens, kwargs, "nameserver", "-ns")
    add_value(tokens, kwargs, "interface", "-I")
    add_value(tokens, kwargs, "collection_method", "-c")
    add_value(tokens, kwargs, "lhost", "--lhost")
    add_value(tokens, kwargs, "lport", "--lport")
    add_value(tokens, kwargs, "session_id", "--session")
    add_value(tokens, kwargs, "listener", "--listener")
    add_value(tokens, kwargs, "protocol", "--protocol")
    add_value(tokens, kwargs, "users_file", "-U")
    add_value(tokens, kwargs, "passwords_file", "-P")
    add_bool(tokens, kwargs, "kerberos", "-k")
    add_bool(tokens, kwargs, "local_auth", "--local-auth")
    add_value(tokens, kwargs, "target_ip", "--target-ip")
    return tokens


def _add_scan_type(tokens: list[str], kwargs: dict) -> None:
    scan_type = str(kwargs.get("scan_type") or "").lower()
    scan_flags = {
        "syn": "-sS",
        "tcp": "-sT",
        "udp": "-sU",
        "ping": "-sn",
    }
    if scan_type in scan_flags:
        tokens.append(scan_flags[scan_type])
