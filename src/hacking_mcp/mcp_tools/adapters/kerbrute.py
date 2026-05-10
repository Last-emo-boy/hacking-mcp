"""Dedicated adapter metadata for Kerbrute."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("dc", str, "", "Domain controller/KDC to target."),
        AdapterParameterSpec("output_file", str, "", "File to write logs to."),
        AdapterParameterSpec("verbose", bool, False, "Log failures and errors."),
        AdapterParameterSpec("safe", bool, False, "Abort if any user comes back locked out."),
        AdapterParameterSpec("threads", int, 0, "Thread count; 0 leaves Kerbrute default."),
        AdapterParameterSpec("delay", int, 0, "Delay in milliseconds between attempts."),
        AdapterParameterSpec("downgrade", bool, False, "Force downgraded arcfour-hmac-md5 encryption."),
        AdapterParameterSpec("hash_file", str, "", "File to save captured AS-REP hashes."),
        AdapterParameterSpec("users_file", str, "", "Username wordlist for the userenum command."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "dc", "--dc")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_bool(tokens, kwargs, "safe", "--safe")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "delay", "--delay")
    add_bool(tokens, kwargs, "downgrade", "--downgrade")
    add_value(tokens, kwargs, "hash_file", "--hash-file")
    users_file = kwargs.get("users_file")
    if users_file not in (None, "", 0, False):
        tokens.append(str(users_file))
    return tokens
