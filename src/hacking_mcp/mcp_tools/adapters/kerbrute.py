"""Dedicated adapter metadata for Kerbrute."""

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
        AdapterParameterSpec("users_file", str, "", "Username list path when supported."),
        AdapterParameterSpec("passwords_file", str, "", "Password list path when supported."),
        AdapterParameterSpec("kerberos", bool, False, "Use Kerberos authentication when supported."),
        AdapterParameterSpec("local_auth", bool, False, "Use local authentication when supported."),
        AdapterParameterSpec("target_ip", str, "", "Target/DC IP override when supported."),
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
    add_value(tokens, kwargs, "users_file", "-U")
    add_value(tokens, kwargs, "passwords_file", "-P")
    add_bool(tokens, kwargs, "kerberos", "-k")
    add_bool(tokens, kwargs, "local_auth", "--local-auth")
    add_value(tokens, kwargs, "target_ip", "--target-ip")
    return tokens
