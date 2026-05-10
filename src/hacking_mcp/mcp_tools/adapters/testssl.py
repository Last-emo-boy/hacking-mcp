"""Dedicated adapter metadata for testssl.sh."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_file", str, "", "Mass testing input file."),
        AdapterParameterSpec("mode", str, "", "Mass testing mode: serial or parallel."),
        AdapterParameterSpec("warnings", str, "", "Warning handling: batch or off."),
        AdapterParameterSpec("connect_timeout", int, 0, "TCP connect timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("openssl_timeout", int, 0, "OpenSSL connect timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("basic_auth", str, "", "HTTP basic auth credentials user:pass."),
        AdapterParameterSpec("req_header", str, "", "Additional HTTP request header."),
        AdapterParameterSpec("mtls_file", str, "", "PEM file containing client certificate and private key."),
        AdapterParameterSpec("starttls", str, "", "STARTTLS protocol, for example smtp or imap."),
        AdapterParameterSpec("xmpp_host", str, "", "XMPP domain for STARTTLS XMPP checks."),
        AdapterParameterSpec("mx", str, "", "Domain or host whose MX records should be tested."),
        AdapterParameterSpec("ip", str, "", "IP address or resolver mode instead of resolving target host."),
        AdapterParameterSpec("proxy", str, "", "Proxy host:port or auto."),
        AdapterParameterSpec("ipv6", bool, False, "Also perform IPv6 checks."),
        AdapterParameterSpec("ssl_native", bool, False, "Use OpenSSL s_client for most checks."),
        AdapterParameterSpec("openssl_path", str, "", "Path to the OpenSSL binary to use."),
        AdapterParameterSpec("bugs", bool, False, "Enable OpenSSL bug workarounds for broken servers."),
        AdapterParameterSpec("assume_http", bool, False, "Assume HTTP when protocol detection cannot prove it."),
        AdapterParameterSpec("no_dns", str, "", "DNS lookup mode: min or none."),
        AdapterParameterSpec("sneaky", bool, False, "Use a less verbose browser-like HTTP user agent."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
        AdapterParameterSpec("ids_friendly", bool, False, "Skip selected offensive vulnerability probes."),
        AdapterParameterSpec("phone_out", bool, False, "Allow CRL and OCSP revocation lookups."),
        AdapterParameterSpec("add_ca", str, "", "Additional CA file, directory, or comma-separated list."),
        AdapterParameterSpec("each_cipher", bool, False, "Check each configured cipher."),
        AdapterParameterSpec("cipher_per_proto", bool, False, "Check ciphers per protocol."),
        AdapterParameterSpec("categories", bool, False, "Test cipher categories."),
        AdapterParameterSpec("forward_secrecy", bool, False, "Check forward secrecy."),
        AdapterParameterSpec("protocols", bool, False, "Check TLS/SSL protocols."),
        AdapterParameterSpec("server_preference", bool, False, "Display server cipher preferences."),
        AdapterParameterSpec("server_defaults", bool, False, "Display server defaults and certificate data."),
        AdapterParameterSpec("single_cipher", str, "", "Single cipher pattern to test."),
        AdapterParameterSpec("check_headers", bool, False, "Test HTTP response headers."),
        AdapterParameterSpec("client_simulation", bool, False, "Run browser/client handshake simulation."),
        AdapterParameterSpec("grease", bool, False, "Check GREASE tolerance."),
        AdapterParameterSpec("vulnerabilities", bool, False, "Run vulnerability checks."),
        AdapterParameterSpec("quiet", bool, False, "Suppress the banner."),
        AdapterParameterSpec("wide", bool, False, "Use wide output."),
        AdapterParameterSpec("mapping", str, "", "Cipher name mapping: openssl, iana, no-openssl, no-iana."),
        AdapterParameterSpec("show_each", bool, False, "Display all ciphers tested in wide modes."),
        AdapterParameterSpec("color", int, 0, "Color mode 0-3; 0 leaves default."),
        AdapterParameterSpec("colorblind", bool, False, "Swap colors for colorblind readability."),
        AdapterParameterSpec("debug", int, 0, "Debug level 0-6; 0 leaves default."),
        AdapterParameterSpec("disable_rating", bool, False, "Disable rating output."),
        AdapterParameterSpec("log", bool, False, "Write a log file using the default name."),
        AdapterParameterSpec("logfile", str, "", "Log output file or directory."),
        AdapterParameterSpec("json_output", bool, False, "Write flat JSON output using the default name."),
        AdapterParameterSpec("jsonfile", str, "", "Flat JSON output file or directory."),
        AdapterParameterSpec("json_pretty", bool, False, "Write pretty JSON output using the default name."),
        AdapterParameterSpec("jsonfile_pretty", str, "", "Pretty JSON output file or directory."),
        AdapterParameterSpec("csv_output", bool, False, "Write CSV output using the default name."),
        AdapterParameterSpec("csvfile", str, "", "CSV output file or directory."),
        AdapterParameterSpec("html_output", bool, False, "Write HTML output using the default name."),
        AdapterParameterSpec("htmlfile", str, "", "HTML output file or directory."),
        AdapterParameterSpec("out_file", str, "", "Base name or directory for all output formats."),
        AdapterParameterSpec("outfile", str, "", "Base name or directory for flat JSON plus other outputs."),
        AdapterParameterSpec("severity", str, "", "Minimum severity for CSV/JSON output."),
        AdapterParameterSpec("append", bool, False, "Append to existing output files."),
        AdapterParameterSpec("overwrite", bool, False, "Overwrite existing output files."),
        AdapterParameterSpec("outprefix", str, "", "Prefix for generated output filenames."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "input_file", "--file")
    add_value(tokens, kwargs, "mode", "--mode")
    add_value(tokens, kwargs, "warnings", "--warnings")
    add_value(tokens, kwargs, "connect_timeout", "--connect-timeout")
    add_value(tokens, kwargs, "openssl_timeout", "--openssl-timeout")
    add_value(tokens, kwargs, "basic_auth", "--basicauth")
    add_value(tokens, kwargs, "req_header", "--reqheader")
    add_value(tokens, kwargs, "mtls_file", "--mtls")
    add_value(tokens, kwargs, "starttls", "-t")
    add_value(tokens, kwargs, "xmpp_host", "--xmpphost")
    add_value(tokens, kwargs, "mx", "--mx")
    add_value(tokens, kwargs, "ip", "--ip")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_bool(tokens, kwargs, "ipv6", "-6")
    add_bool(tokens, kwargs, "ssl_native", "--ssl-native")
    add_value(tokens, kwargs, "openssl_path", "--openssl")
    add_bool(tokens, kwargs, "bugs", "--bugs")
    add_bool(tokens, kwargs, "assume_http", "--assuming-http")
    add_value(tokens, kwargs, "no_dns", "--nodns")
    add_bool(tokens, kwargs, "sneaky", "--sneaky")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_bool(tokens, kwargs, "ids_friendly", "--ids-friendly")
    add_bool(tokens, kwargs, "phone_out", "--phone-out")
    add_value(tokens, kwargs, "add_ca", "--add-ca")
    add_bool(tokens, kwargs, "each_cipher", "-e")
    add_bool(tokens, kwargs, "cipher_per_proto", "-E")
    add_bool(tokens, kwargs, "categories", "-s")
    add_bool(tokens, kwargs, "forward_secrecy", "-f")
    add_bool(tokens, kwargs, "protocols", "-p")
    add_bool(tokens, kwargs, "server_preference", "-P")
    add_bool(tokens, kwargs, "server_defaults", "-S")
    add_value(tokens, kwargs, "single_cipher", "-x")
    add_bool(tokens, kwargs, "check_headers", "-h")
    add_bool(tokens, kwargs, "client_simulation", "-c")
    add_bool(tokens, kwargs, "grease", "-g")
    add_bool(tokens, kwargs, "vulnerabilities", "-U")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_bool(tokens, kwargs, "wide", "--wide")
    add_value(tokens, kwargs, "mapping", "--mapping")
    add_bool(tokens, kwargs, "show_each", "--show-each")
    add_value(tokens, kwargs, "color", "--color")
    add_bool(tokens, kwargs, "colorblind", "--colorblind")
    add_value(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "disable_rating", "--disable-rating")
    add_bool(tokens, kwargs, "log", "--log")
    add_value(tokens, kwargs, "logfile", "--logfile")
    add_bool(tokens, kwargs, "json_output", "--json")
    add_value(tokens, kwargs, "jsonfile", "--jsonfile")
    add_bool(tokens, kwargs, "json_pretty", "--json-pretty")
    add_value(tokens, kwargs, "jsonfile_pretty", "--jsonfile-pretty")
    add_bool(tokens, kwargs, "csv_output", "--csv")
    add_value(tokens, kwargs, "csvfile", "--csvfile")
    add_bool(tokens, kwargs, "html_output", "--html")
    add_value(tokens, kwargs, "htmlfile", "--htmlfile")
    add_value(tokens, kwargs, "out_file", "--outFile")
    add_value(tokens, kwargs, "outfile", "--outfile")
    add_value(tokens, kwargs, "severity", "--severity")
    add_bool(tokens, kwargs, "append", "--append")
    add_bool(tokens, kwargs, "overwrite", "--overwrite")
    add_value(tokens, kwargs, "outprefix", "--outprefix")
    return tokens
