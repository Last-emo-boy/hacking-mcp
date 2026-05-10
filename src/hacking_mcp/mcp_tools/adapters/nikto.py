"""Dedicated adapter metadata for Nikto."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("ask", str, "", "Interactive prompt behavior."),
        AdapterParameterSpec("cgi_dirs", str, "", "CGI directories to scan."),
        AdapterParameterSpec("config_file", str, "", "Nikto config file path."),
        AdapterParameterSpec("display", str, "", "Display selector."),
        AdapterParameterSpec("dbcheck", bool, False, "Check database and syntax errors."),
        AdapterParameterSpec("evasion", str, "", "IDS evasion technique."),
        AdapterParameterSpec("output_format", str, "", "Output format."),
        AdapterParameterSpec("auth", str, "", "Host authentication credential pair."),
        AdapterParameterSpec("list_plugins", bool, False, "List installed plugins."),
        AdapterParameterSpec("max_time", str, "", "Maximum testing time."),
        AdapterParameterSpec("mutate", str, "", "Guess additional file names."),
        AdapterParameterSpec("mutate_options", str, "", "Mutate option values."),
        AdapterParameterSpec("no_interactive", bool, False, "Disable interactive prompts."),
        AdapterParameterSpec("no_lookup", bool, False, "Disable DNS lookups."),
        AdapterParameterSpec("no_ssl", bool, False, "Disable SSL/TLS."),
        AdapterParameterSpec("no_404", bool, False, "Disable 404 checks."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("pause", int, 0, "Pause between tests in seconds; 0 leaves default."),
        AdapterParameterSpec("plugins", str, "", "Plugin selector."),
        AdapterParameterSpec("port", str, "", "Ports to scan."),
        AdapterParameterSpec("rsa_cert", str, "", "Client certificate file."),
        AdapterParameterSpec("root", str, "", "Prepend root path to requests."),
        AdapterParameterSpec("save_dir", str, "", "Directory to save positive responses."),
        AdapterParameterSpec("ssl", bool, False, "Force SSL/TLS mode."),
        AdapterParameterSpec("tuning", str, "", "Scan tuning selector."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
        AdapterParameterSpec("until", str, "", "Run until specified time or duration."),
        AdapterParameterSpec("update", bool, False, "Update plugins and databases."),
        AdapterParameterSpec("use_proxy", bool, False, "Use configured HTTP proxy."),
        AdapterParameterSpec("vhost", str, "", "Virtual host header."),
        AdapterParameterSpec("notfound_code", str, "", "Treat this HTTP code as 404."),
        AdapterParameterSpec("notfound_string", str, "", "Treat response body containing this string as 404."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "ask", "-ask")
    add_value(tokens, kwargs, "cgi_dirs", "-Cgidirs")
    add_value(tokens, kwargs, "config_file", "-config")
    add_value(tokens, kwargs, "display", "-Display")
    add_bool(tokens, kwargs, "dbcheck", "-dbcheck")
    add_value(tokens, kwargs, "evasion", "-evasion")
    add_value(tokens, kwargs, "output_format", "-Format")
    add_value(tokens, kwargs, "auth", "-id")
    add_bool(tokens, kwargs, "list_plugins", "-list-plugins")
    add_value(tokens, kwargs, "max_time", "-maxtime")
    add_value(tokens, kwargs, "mutate", "-mutate")
    add_value(tokens, kwargs, "mutate_options", "-mutate-options")
    add_bool(tokens, kwargs, "no_interactive", "-nointeractive")
    add_bool(tokens, kwargs, "no_lookup", "-nolookup")
    add_bool(tokens, kwargs, "no_ssl", "-nossl")
    add_bool(tokens, kwargs, "no_404", "-no404")
    add_value(tokens, kwargs, "output_file", "-output")
    add_value(tokens, kwargs, "pause", "-Pause")
    add_value(tokens, kwargs, "plugins", "-Plugins")
    add_value(tokens, kwargs, "port", "-port")
    add_value(tokens, kwargs, "rsa_cert", "-RSAcert")
    add_value(tokens, kwargs, "root", "-root")
    add_value(tokens, kwargs, "save_dir", "-Save")
    add_bool(tokens, kwargs, "ssl", "-ssl")
    add_value(tokens, kwargs, "tuning", "-Tuning")
    add_value(tokens, kwargs, "timeout", "-timeout")
    add_value(tokens, kwargs, "user_agent", "-useragent")
    add_value(tokens, kwargs, "until", "-until")
    add_bool(tokens, kwargs, "update", "-update")
    add_bool(tokens, kwargs, "use_proxy", "-useproxy")
    add_value(tokens, kwargs, "vhost", "-vhost")
    add_value(tokens, kwargs, "notfound_code", "-404code")
    add_value(tokens, kwargs, "notfound_string", "-404string")
    return tokens
