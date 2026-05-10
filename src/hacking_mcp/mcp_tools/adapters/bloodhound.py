"""Dedicated adapter metadata for BloodHound."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
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
        AdapterParameterSpec("sources", str, "", "Comma-separated OSINT sources when supported."),
        AdapterParameterSpec("passive", bool, False, "Use passive enumeration when supported."),
        AdapterParameterSpec("resolvers", str, "", "Resolver file path when supported."),
        AdapterParameterSpec("api_key", str, "", "API key/profile name when supported."),
        AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
        AdapterParameterSpec("json_output", bool, False, "Request JSON output when supported."),
        AdapterParameterSpec("ldap", bool, False, "Use LDAP collection/protocol mode when supported."),
        AdapterParameterSpec("smb", bool, False, "Use SMB protocol mode when supported."),
        AdapterParameterSpec("no_pass", bool, False, "Use no-password auth mode when supported."),
        AdapterParameterSpec("output_prefix", str, "", "Output prefix/path when supported."),
        AdapterParameterSpec("disable_llmnr", bool, False, "Disable LLMNR poisoning when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "domain", "-d")
    add_value(tokens, kwargs, "username", "-u")
    add_value(tokens, kwargs, "password", "-p")
    add_value(tokens, kwargs, "hashes", "-H")
    add_value(tokens, kwargs, "dc_ip", "-dc-ip")
    add_value(tokens, kwargs, "nameserver", "-ns")
    add_value(tokens, kwargs, "interface", "-I")
    add_value(tokens, kwargs, "collection_method", "-c")
    add_value(tokens, kwargs, "sources", "-sources")
    add_bool(tokens, kwargs, "passive", "-passive")
    add_value(tokens, kwargs, "resolvers", "-r")
    add_value(tokens, kwargs, "api_key", "--api-key")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "json_output", "-json")
    add_bool(tokens, kwargs, "ldap", "--ldap")
    add_bool(tokens, kwargs, "smb", "--smb")
    add_bool(tokens, kwargs, "no_pass", "--no-pass")
    add_value(tokens, kwargs, "output_prefix", "-o")
    add_bool(tokens, kwargs, "disable_llmnr", "-d")
    return tokens
