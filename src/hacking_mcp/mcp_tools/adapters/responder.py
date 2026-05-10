"""Dedicated adapter metadata for Responder."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("analyze", bool, False, "Analyze requests without poisoning."),
        AdapterParameterSpec("external_ip", str, "", "IPv4 address to use in poisoned answers."),
        AdapterParameterSpec("external_ipv6", str, "", "IPv6 address to use in poisoned answers."),
        AdapterParameterSpec("rdnss", bool, False, "Poison via router advertisements with RDNSS."),
        AdapterParameterSpec("dnssl_domain", str, "", "DNSSL domain injected via router advertisements."),
        AdapterParameterSpec("ttl", str, "", "TTL for poisoned answers, hex value or random."),
        AdapterParameterSpec("answer_name", str, "", "Canonical name in LLMNR answers."),
        AdapterParameterSpec("dhcp", bool, False, "Enable DHCPv4 poisoning."),
        AdapterParameterSpec("dhcp_dns", bool, False, "Inject DNS server in DHCPv4 responses."),
        AdapterParameterSpec("dhcpv6", bool, False, "Enable DHCPv6 poisoning."),
        AdapterParameterSpec("wpad", bool, False, "Start WPAD rogue proxy server."),
        AdapterParameterSpec("force_wpad_auth", bool, False, "Force auth on wpad.dat retrieval."),
        AdapterParameterSpec("proxy_auth", bool, False, "Force proxy authentication."),
        AdapterParameterSpec("upstream_proxy", str, "", "Upstream proxy host:port."),
        AdapterParameterSpec("basic", bool, False, "Return HTTP Basic auth instead of NTLM."),
        AdapterParameterSpec("lm", bool, False, "Force LM hashing downgrade."),
        AdapterParameterSpec("disable_ess", bool, False, "Disable Extended Session Security."),
        AdapterParameterSpec("error_code", bool, False, "Return STATUS_LOGON_FAILURE."),
        AdapterParameterSpec("verbose", bool, False, "Increase verbosity."),
        AdapterParameterSpec("quiet", bool, False, "Quiet mode with minimal poisoner output."),
        AdapterParameterSpec("local_ip", str, "", "Local IP to use on OSX."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "analyze", "-A")
    add_value(tokens, kwargs, "external_ip", "-e")
    add_value(tokens, kwargs, "external_ipv6", "-6")
    add_bool(tokens, kwargs, "rdnss", "--rdnss")
    add_value(tokens, kwargs, "dnssl_domain", "--dnssl")
    add_value(tokens, kwargs, "ttl", "-t")
    add_value(tokens, kwargs, "answer_name", "-N")
    add_bool(tokens, kwargs, "dhcp", "-d")
    add_bool(tokens, kwargs, "dhcp_dns", "-D")
    add_bool(tokens, kwargs, "dhcpv6", "--dhcpv6")
    add_bool(tokens, kwargs, "wpad", "-w")
    add_bool(tokens, kwargs, "force_wpad_auth", "-F")
    add_bool(tokens, kwargs, "proxy_auth", "-P")
    add_value(tokens, kwargs, "upstream_proxy", "-u")
    add_bool(tokens, kwargs, "basic", "-b")
    add_bool(tokens, kwargs, "lm", "--lm")
    add_bool(tokens, kwargs, "disable_ess", "--disable-ess")
    add_bool(tokens, kwargs, "error_code", "-E")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_bool(tokens, kwargs, "quiet", "-Q")
    add_value(tokens, kwargs, "local_ip", "-i")
    return tokens
