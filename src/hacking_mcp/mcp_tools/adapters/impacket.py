"""Dedicated adapter metadata for Impacket."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_file", str, "", "File with commands to execute in the mini shell."),
        AdapterParameterSpec("output_file", str, "", "File to log smbclient actions in."),
        AdapterParameterSpec("debug", bool, False, "Turn debug output on."),
        AdapterParameterSpec("timestamp", bool, False, "Add timestamp to every logging output."),
        AdapterParameterSpec("hashes", str, "", "NTLM hashes in LMHASH:NTHASH format."),
        AdapterParameterSpec("no_pass", bool, False, "Do not ask for password."),
        AdapterParameterSpec("kerberos", bool, False, "Use Kerberos authentication."),
        AdapterParameterSpec("aes_key", str, "", "AES key for Kerberos authentication."),
        AdapterParameterSpec("dc_ip", str, "", "Domain controller IP address."),
        AdapterParameterSpec("target_ip", str, "", "Target machine IP address override."),
        AdapterParameterSpec("port", str, "", "SMB destination port, 139 or 445."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "input_file", "-inputfile")
    add_value(tokens, kwargs, "output_file", "-outputfile")
    add_bool(tokens, kwargs, "debug", "-debug")
    add_bool(tokens, kwargs, "timestamp", "-ts")
    add_value(tokens, kwargs, "hashes", "-hashes")
    add_bool(tokens, kwargs, "no_pass", "-no-pass")
    add_bool(tokens, kwargs, "kerberos", "-k")
    add_value(tokens, kwargs, "aes_key", "-aesKey")
    add_value(tokens, kwargs, "dc_ip", "-dc-ip")
    add_value(tokens, kwargs, "target_ip", "-target-ip")
    add_value(tokens, kwargs, "port", "-port")
    return tokens
