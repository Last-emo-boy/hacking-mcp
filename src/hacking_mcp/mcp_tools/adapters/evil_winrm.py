"""Dedicated adapter metadata for Evil-WinRM."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("username", str, "", "Username for authorized WinRM access."),
        AdapterParameterSpec(
            "password",
            str,
            "",
            "Password for authorized WinRM access; may be present in process/audit logs.",
        ),
        AdapterParameterSpec("nt_hash", str, "", "NTLM hash for pass-the-hash authentication."),
        AdapterParameterSpec("port", int, 0, "Remote WinRM port; 0 leaves Evil-WinRM default."),
        AdapterParameterSpec("ssl", bool, False, "Enable SSL transport."),
        AdapterParameterSpec("public_key", str, "", "Local path to public key certificate."),
        AdapterParameterSpec("private_key", str, "", "Local path to private key certificate."),
        AdapterParameterSpec("realm", str, "", "Kerberos realm/domain."),
        AdapterParameterSpec("ccache", str, "", "Kerberos ccache or kirbi ticket file."),
        AdapterParameterSpec("scripts_path", str, "", "Local path for PowerShell scripts."),
        AdapterParameterSpec("spn", str, "", "SPN prefix for Kerberos authentication."),
        AdapterParameterSpec("executables_path", str, "", "Local path for C# executables."),
        AdapterParameterSpec("url", str, "", "Remote WinRM URL endpoint."),
        AdapterParameterSpec("user_agent", str, "", "Connection User-Agent string."),
        AdapterParameterSpec("version", bool, False, "Show Evil-WinRM version and exit."),
        AdapterParameterSpec("no_colors", bool, False, "Disable colored output."),
        AdapterParameterSpec("no_rpath_completion", bool, False, "Disable remote path completion."),
        AdapterParameterSpec("log_session", bool, False, "Log the WinRM session."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "username", "-u")
    add_value(tokens, kwargs, "password", "-p")
    add_value(tokens, kwargs, "nt_hash", "-H")
    add_value(tokens, kwargs, "port", "-P")
    add_bool(tokens, kwargs, "ssl", "-S")
    add_value(tokens, kwargs, "public_key", "-c")
    add_value(tokens, kwargs, "private_key", "-k")
    add_value(tokens, kwargs, "realm", "-r")
    add_value(tokens, kwargs, "ccache", "-K")
    add_value(tokens, kwargs, "scripts_path", "-s")
    add_value(tokens, kwargs, "spn", "--spn")
    add_value(tokens, kwargs, "executables_path", "-e")
    add_value(tokens, kwargs, "url", "-U")
    add_value(tokens, kwargs, "user_agent", "-a")
    add_bool(tokens, kwargs, "version", "-V")
    add_bool(tokens, kwargs, "no_colors", "-n")
    add_bool(tokens, kwargs, "no_rpath_completion", "-N")
    add_bool(tokens, kwargs, "log_session", "-l")
    return tokens
