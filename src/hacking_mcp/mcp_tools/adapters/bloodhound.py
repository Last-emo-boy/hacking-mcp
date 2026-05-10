"""Dedicated adapter metadata for BloodHound."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("username", str, "", "Username for authorized AD assessment."),
        AdapterParameterSpec(
            "password",
            str,
            "",
            "Password for lab/authorized use; may be present in process/audit logs.",
        ),
        AdapterParameterSpec("kerberos", bool, False, "Use Kerberos ccache authentication."),
        AdapterParameterSpec("hashes", str, "", "LM:NTLM hashes."),
        AdapterParameterSpec("no_pass", bool, False, "Do not ask for password."),
        AdapterParameterSpec("aes_key", str, "", "AES key for Kerberos authentication."),
        AdapterParameterSpec("auth_method", str, "", "Authentication method: auto, ntlm, or kerberos."),
        AdapterParameterSpec("collection_method", str, "", "Collection method, for example Default or All."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
        AdapterParameterSpec("nameserver", str, "", "Alternative nameserver for DNS queries."),
        AdapterParameterSpec("dns_tcp", bool, False, "Use TCP instead of UDP for DNS queries."),
        AdapterParameterSpec("dns_timeout", int, 0, "DNS query timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("domain_controller", str, "", "Domain controller hostname override."),
        AdapterParameterSpec("global_catalog", str, "", "Global Catalog hostname override."),
        AdapterParameterSpec("workers", int, 0, "Worker count for computer enumeration; 0 leaves default."),
        AdapterParameterSpec("exclude_dcs", bool, False, "Skip DCs during computer enumeration."),
        AdapterParameterSpec("disable_pooling", bool, False, "Disable subprocess pooling for ACL parsing."),
        AdapterParameterSpec("disable_autogc", bool, False, "Disable automatic Global Catalog selection."),
        AdapterParameterSpec("zip_output", bool, False, "Compress JSON output files into a zip archive."),
        AdapterParameterSpec("computerfile", str, "", "Allowlist file of computer FQDNs."),
        AdapterParameterSpec("cachefile", str, "", "Experimental cache file."),
        AdapterParameterSpec("ldap_channel_binding", bool, False, "Use LDAP channel binding."),
        AdapterParameterSpec("use_ldaps", bool, False, "Use LDAP over TLS on port 636 by default."),
        AdapterParameterSpec("output_prefix", str, "", "Prefix to prepend to output filenames."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "username", "-u")
    add_value(tokens, kwargs, "password", "-p")
    add_bool(tokens, kwargs, "kerberos", "-k")
    add_value(tokens, kwargs, "hashes", "--hashes")
    add_bool(tokens, kwargs, "no_pass", "-no-pass")
    add_value(tokens, kwargs, "aes_key", "-aesKey")
    add_value(tokens, kwargs, "auth_method", "--auth-method")
    add_value(tokens, kwargs, "collection_method", "-c")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_value(tokens, kwargs, "nameserver", "-ns")
    add_bool(tokens, kwargs, "dns_tcp", "--dns-tcp")
    add_value(tokens, kwargs, "dns_timeout", "--dns-timeout")
    add_value(tokens, kwargs, "domain_controller", "-dc")
    add_value(tokens, kwargs, "global_catalog", "-gc")
    add_value(tokens, kwargs, "workers", "-w")
    add_bool(tokens, kwargs, "exclude_dcs", "--exclude-dcs")
    add_bool(tokens, kwargs, "disable_pooling", "--disable-pooling")
    add_bool(tokens, kwargs, "disable_autogc", "--disable-autogc")
    add_bool(tokens, kwargs, "zip_output", "--zip")
    add_value(tokens, kwargs, "computerfile", "--computerfile")
    add_value(tokens, kwargs, "cachefile", "--cachefile")
    add_bool(tokens, kwargs, "ldap_channel_binding", "--ldap-channel-binding")
    add_bool(tokens, kwargs, "use_ldaps", "--use-ldaps")
    add_value(tokens, kwargs, "output_prefix", "-op")
    return tokens
