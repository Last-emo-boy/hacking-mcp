"""Dedicated adapter metadata for Certipy."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "password",
            str,
            "",
            "Password for authentication; may be present in process/audit logs.",
        ),
        AdapterParameterSpec("hashes", str, "", "NTLM hash in [LMHASH:]NTHASH format."),
        AdapterParameterSpec("kerberos", bool, False, "Use Kerberos authentication."),
        AdapterParameterSpec("aes_key", str, "", "AES key for Kerberos authentication."),
        AdapterParameterSpec("no_pass", bool, False, "Do not ask for password."),
        AdapterParameterSpec("dc_ip", str, "", "Domain controller IP address."),
        AdapterParameterSpec("dc_host", str, "", "Domain controller hostname."),
        AdapterParameterSpec("target_ip", str, "", "Target machine IP address override."),
        AdapterParameterSpec("target_host", str, "", "Target DNS name or IP address."),
        AdapterParameterSpec("nameserver", str, "", "Nameserver for DNS resolution."),
        AdapterParameterSpec("dns_tcp", bool, False, "Use TCP instead of UDP for DNS queries."),
        AdapterParameterSpec("timeout", int, 0, "Connection timeout in seconds; 0 leaves Certipy default."),
        AdapterParameterSpec("ldap_scheme", str, "", "LDAP scheme, ldap or ldaps."),
        AdapterParameterSpec("ldap_port", int, 0, "LDAP port; 0 leaves Certipy default."),
        AdapterParameterSpec(
            "no_ldap_channel_binding",
            bool,
            False,
            "Disable LDAP channel binding for LDAPS.",
        ),
        AdapterParameterSpec("no_ldap_signing", bool, False, "Disable LDAP signing for LDAP."),
        AdapterParameterSpec("ldap_simple_auth", bool, False, "Use SIMPLE LDAP authentication."),
        AdapterParameterSpec("ldap_user_dn", str, "", "Distinguished Name for LDAP authentication."),
        AdapterParameterSpec("text", bool, False, "Write formatted text output."),
        AdapterParameterSpec("stdout", bool, False, "Write text output to stdout."),
        AdapterParameterSpec("json_output", bool, False, "Write JSON output."),
        AdapterParameterSpec("csv", bool, False, "Write CSV output."),
        AdapterParameterSpec("output_prefix", str, "", "Filename prefix for writing results."),
        AdapterParameterSpec("enabled", bool, False, "Show only enabled certificate templates."),
        AdapterParameterSpec("dc_only", bool, False, "Collect only from the domain controller."),
        AdapterParameterSpec("vulnerable", bool, False, "Show only vulnerable certificate templates."),
        AdapterParameterSpec("oids", bool, False, "Show OIDs and their properties."),
        AdapterParameterSpec("hide_admins", bool, False, "Hide administrator permissions in output."),
        AdapterParameterSpec("sid", str, "", "SID of the command-line user for cross-domain auth."),
        AdapterParameterSpec("dn", str, "", "Distinguished Name of the command-line user."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "password", "-p")
    add_value(tokens, kwargs, "hashes", "-hashes")
    add_bool(tokens, kwargs, "kerberos", "-k")
    add_value(tokens, kwargs, "aes_key", "-aes")
    add_bool(tokens, kwargs, "no_pass", "-no-pass")
    add_value(tokens, kwargs, "dc_ip", "-dc-ip")
    add_value(tokens, kwargs, "dc_host", "-dc-host")
    add_value(tokens, kwargs, "target_ip", "-target-ip")
    add_value(tokens, kwargs, "target_host", "-target")
    add_value(tokens, kwargs, "nameserver", "-ns")
    add_bool(tokens, kwargs, "dns_tcp", "-dns-tcp")
    add_value(tokens, kwargs, "timeout", "-timeout")
    add_value(tokens, kwargs, "ldap_scheme", "-ldap-scheme")
    add_value(tokens, kwargs, "ldap_port", "-ldap-port")
    add_bool(tokens, kwargs, "no_ldap_channel_binding", "-no-ldap-channel-binding")
    add_bool(tokens, kwargs, "no_ldap_signing", "-no-ldap-signing")
    add_bool(tokens, kwargs, "ldap_simple_auth", "-ldap-simple-auth")
    add_value(tokens, kwargs, "ldap_user_dn", "-ldap-user-dn")
    add_bool(tokens, kwargs, "text", "-text")
    add_bool(tokens, kwargs, "stdout", "-stdout")
    add_bool(tokens, kwargs, "json_output", "-json")
    add_bool(tokens, kwargs, "csv", "-csv")
    add_value(tokens, kwargs, "output_prefix", "-output")
    add_bool(tokens, kwargs, "enabled", "-enabled")
    add_bool(tokens, kwargs, "dc_only", "-dc-only")
    add_bool(tokens, kwargs, "vulnerable", "-vulnerable")
    add_bool(tokens, kwargs, "oids", "-oids")
    add_bool(tokens, kwargs, "hide_admins", "-hide-admins")
    add_value(tokens, kwargs, "sid", "-sid")
    add_value(tokens, kwargs, "dn", "-dn")
    return tokens
