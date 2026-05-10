"""Dedicated adapter metadata for NetExec."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, add_values


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("username", str, "", "Username, usernames, or username file for authentication."),
        AdapterParameterSpec(
            "password",
            str,
            "",
            "Password, passwords, or password file; may be present in process/audit logs.",
        ),
        AdapterParameterSpec("hashes", str, "", "NTLM hash, hashes, or hash file."),
        AdapterParameterSpec("domain", str, "", "Domain to authenticate to."),
        AdapterParameterSpec("local_auth", bool, False, "Authenticate locally to each target."),
        AdapterParameterSpec("kerberos", bool, False, "Use Kerberos authentication."),
        AdapterParameterSpec("use_kcache", bool, False, "Use Kerberos ccache from KRB5CCNAME."),
        AdapterParameterSpec("aes_key", str, "", "AES key for Kerberos authentication."),
        AdapterParameterSpec("kdc_host", str, "", "FQDN of the KDC/domain controller."),
        AdapterParameterSpec("cred_id", str, "", "Database credential ID or IDs to use."),
        AdapterParameterSpec("ignore_pw_decoding", bool, False, "Ignore non-UTF-8 password file characters."),
        AdapterParameterSpec("no_bruteforce", bool, False, "Pair usernames/passwords instead of spraying."),
        AdapterParameterSpec("continue_on_success", bool, False, "Continue authentication after success."),
        AdapterParameterSpec("gfail_limit", int, 0, "Global failed login limit; 0 leaves default."),
        AdapterParameterSpec("ufail_limit", int, 0, "Per-username failed login limit; 0 leaves default."),
        AdapterParameterSpec("fail_limit", int, 0, "Per-host failed login limit; 0 leaves default."),
        AdapterParameterSpec("threads", int, 0, "Concurrent thread count; 0 leaves default."),
        AdapterParameterSpec("timeout", int, 0, "Per-thread timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("jitter", str, "", "Random delay interval between authentications."),
        AdapterParameterSpec("no_progress", bool, False, "Disable progress bar output."),
        AdapterParameterSpec("log_file", str, "", "Custom log file path."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
        AdapterParameterSpec("debug", bool, False, "Enable debug output."),
        AdapterParameterSpec("force_ipv6", bool, False, "Force IPv6 DNS behavior."),
        AdapterParameterSpec("dns_server", str, "", "DNS server to use."),
        AdapterParameterSpec("dns_tcp", bool, False, "Use TCP instead of UDP for DNS queries."),
        AdapterParameterSpec("dns_timeout", int, 0, "DNS query timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("module", str, "", "NetExec module to use."),
        AdapterParameterSpec("module_options", str, "", "Module options, split like shell words."),
        AdapterParameterSpec("list_modules", str, "", "List modules, optionally filtered by text."),
        AdapterParameterSpec("show_module_options", bool, False, "Display selected module options."),
        AdapterParameterSpec("port", int, 0, "SMB port; 0 leaves default."),
        AdapterParameterSpec("share", str, "", "SMB share name."),
        AdapterParameterSpec("smb_server_port", int, 0, "SMB server port; 0 leaves default."),
        AdapterParameterSpec("no_smbv1", bool, False, "Disable SMBv1 in connection."),
        AdapterParameterSpec("no_admin_check", bool, False, "Skip admin check via SCM query."),
        AdapterParameterSpec("gen_relay_list", str, "", "Output hosts without SMB signing to this file."),
        AdapterParameterSpec("smb_timeout", int, 0, "SMB connection timeout; 0 leaves default."),
        AdapterParameterSpec("shares", str, "", "Enumerate shares, optionally filtered by access."),
        AdapterParameterSpec("users", str, "", "Enumerate domain users, optionally filtered."),
        AdapterParameterSpec("groups", str, "", "Enumerate domain groups, optionally filtered."),
        AdapterParameterSpec("pass_pol", bool, False, "Dump password policy."),
        AdapterParameterSpec("rid_brute", int, 0, "Bruteforce RIDs up to this value; 0 disables."),
        AdapterParameterSpec("exec_method", str, "", "Execution method: wmiexec, mmcexec, smbexec, or atexec."),
        AdapterParameterSpec("execute_cmd", str, "", "Execute a CMD command."),
        AdapterParameterSpec("execute_ps", str, "", "Execute a PowerShell command."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "username", "-u")
    add_value(tokens, kwargs, "password", "-p")
    add_value(tokens, kwargs, "hashes", "-H")
    add_value(tokens, kwargs, "domain", "-d")
    add_bool(tokens, kwargs, "local_auth", "--local-auth")
    add_bool(tokens, kwargs, "kerberos", "-k")
    add_bool(tokens, kwargs, "use_kcache", "--use-kcache")
    add_value(tokens, kwargs, "aes_key", "--aesKey")
    add_value(tokens, kwargs, "kdc_host", "--kdcHost")
    add_value(tokens, kwargs, "cred_id", "-id")
    add_bool(tokens, kwargs, "ignore_pw_decoding", "--ignore-pw-decoding")
    add_bool(tokens, kwargs, "no_bruteforce", "--no-bruteforce")
    add_bool(tokens, kwargs, "continue_on_success", "--continue-on-success")
    add_value(tokens, kwargs, "gfail_limit", "--gfail-limit")
    add_value(tokens, kwargs, "ufail_limit", "--ufail-limit")
    add_value(tokens, kwargs, "fail_limit", "--fail-limit")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "jitter", "--jitter")
    add_bool(tokens, kwargs, "no_progress", "--no-progress")
    add_value(tokens, kwargs, "log_file", "--log")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "force_ipv6", "-6")
    add_value(tokens, kwargs, "dns_server", "--dns-server")
    add_bool(tokens, kwargs, "dns_tcp", "--dns-tcp")
    add_value(tokens, kwargs, "dns_timeout", "--dns-timeout")
    add_value(tokens, kwargs, "module", "-M")
    add_values(tokens, kwargs, "module_options", "-o")
    add_value(tokens, kwargs, "list_modules", "-L")
    add_bool(tokens, kwargs, "show_module_options", "--options")
    add_value(tokens, kwargs, "port", "--port")
    add_value(tokens, kwargs, "share", "--share")
    add_value(tokens, kwargs, "smb_server_port", "--smb-server-port")
    add_bool(tokens, kwargs, "no_smbv1", "--no-smbv1")
    add_bool(tokens, kwargs, "no_admin_check", "--no-admin-check")
    add_value(tokens, kwargs, "gen_relay_list", "--gen-relay-list")
    add_value(tokens, kwargs, "smb_timeout", "--smb-timeout")
    add_value(tokens, kwargs, "shares", "--shares")
    add_value(tokens, kwargs, "users", "--users")
    add_value(tokens, kwargs, "groups", "--groups")
    add_bool(tokens, kwargs, "pass_pol", "--pass-pol")
    add_value(tokens, kwargs, "rid_brute", "--rid-brute")
    add_value(tokens, kwargs, "exec_method", "--exec-method")
    add_value(tokens, kwargs, "execute_cmd", "-x")
    add_value(tokens, kwargs, "execute_ps", "-X")
    return tokens
