"""Dedicated adapter metadata for DIRB."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "", "Optional DIRB wordlist file placed after the URL target."),
        AdapterParameterSpec("user_agent", str, "", "Custom User-Agent for -a."),
        AdapterParameterSpec("preserve_url_path", bool, False, "Do not squash /../ or /./ sequences with -b."),
        AdapterParameterSpec("cookie", str, "", "Cookie string for -c."),
        AdapterParameterSpec("client_cert", str, "", "Client certificate file for -E."),
        AdapterParameterSpec("fine_tune_404", bool, False, "Fine tune 404 detection with -f."),
        AdapterParameterSpec("header", str, "", "Custom HTTP header for -H."),
        AdapterParameterSpec("case_insensitive", bool, False, "Use case-insensitive search with -i."),
        AdapterParameterSpec("show_location", bool, False, "Print Location header with -l."),
        AdapterParameterSpec("ignore_code", int, 0, "HTTP response code to ignore with -N; 0 disables."),
        AdapterParameterSpec("output_file", str, "", "Save output to disk with -o."),
        AdapterParameterSpec("proxy", str, "", "Proxy host[:port] for -p."),
        AdapterParameterSpec("proxy_auth", str, "", "Proxy username:password for -P."),
        AdapterParameterSpec("no_recursive", bool, False, "Do not search recursively with -r."),
        AdapterParameterSpec("interactive_recursion", bool, False, "Ask for recursion directories with -R."),
        AdapterParameterSpec("silent", bool, False, "Silent mode with -S."),
        AdapterParameterSpec("no_force_slash", bool, False, "Do not force ending slash on URLs with -t."),
        AdapterParameterSpec("auth", str, "", "HTTP username:password for -u."),
        AdapterParameterSpec("show_not_found", bool, False, "Show not-existent pages with -v."),
        AdapterParameterSpec("ignore_warnings", bool, False, "Do not stop on warning messages with -w."),
        AdapterParameterSpec("extensions_file", str, "", "Extensions file for -x."),
        AdapterParameterSpec("extensions", str, "", "Comma-separated extensions for -X."),
        AdapterParameterSpec("delay_ms", int, 0, "Request delay in milliseconds for -z; 0 disables."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    wordlist = kwargs.get("wordlist")
    if wordlist:
        tokens.append(str(wordlist))
    add_value(tokens, kwargs, "user_agent", "-a")
    add_bool(tokens, kwargs, "preserve_url_path", "-b")
    add_value(tokens, kwargs, "cookie", "-c")
    add_value(tokens, kwargs, "client_cert", "-E")
    add_bool(tokens, kwargs, "fine_tune_404", "-f")
    add_value(tokens, kwargs, "header", "-H")
    add_bool(tokens, kwargs, "case_insensitive", "-i")
    add_bool(tokens, kwargs, "show_location", "-l")
    add_value(tokens, kwargs, "ignore_code", "-N")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "proxy", "-p")
    add_value(tokens, kwargs, "proxy_auth", "-P")
    add_bool(tokens, kwargs, "no_recursive", "-r")
    add_bool(tokens, kwargs, "interactive_recursion", "-R")
    add_bool(tokens, kwargs, "silent", "-S")
    add_bool(tokens, kwargs, "no_force_slash", "-t")
    add_value(tokens, kwargs, "auth", "-u")
    add_bool(tokens, kwargs, "show_not_found", "-v")
    add_bool(tokens, kwargs, "ignore_warnings", "-w")
    add_value(tokens, kwargs, "extensions_file", "-x")
    add_value(tokens, kwargs, "extensions", "-X")
    add_value(tokens, kwargs, "delay_ms", "-z")
    return tokens
