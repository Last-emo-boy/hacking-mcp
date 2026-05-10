"""Dedicated adapter metadata for NoSQLMap."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "attack",
            int,
            0,
            "Attack mode: 1 database access, 2 web app attack, 3 anonymous access scan; 0 leaves interactive default.",
        ),
        AdapterParameterSpec("platform", str, "", "Target database platform, for example MongoDB or CouchDB."),
        AdapterParameterSpec("victim", str, "", "Target host or IP; defaults to the adapter target when omitted."),
        AdapterParameterSpec("db_port", int, 0, "Database port for --dbPort; 0 leaves default."),
        AdapterParameterSpec("my_ip", str, "", "Local platform or shell IP for --myIP."),
        AdapterParameterSpec("my_port", int, 0, "Local platform or shell port for --myPort; 0 leaves default."),
        AdapterParameterSpec("web_port", int, 0, "Web application port for --webPort; 0 leaves default."),
        AdapterParameterSpec("uri", str, "", "Web application path for --uri."),
        AdapterParameterSpec("http_method", str, "", "HTTP method for --httpMethod, usually GET or POST."),
        AdapterParameterSpec("https", bool, False, "Set --https ON."),
        AdapterParameterSpec("verbose", bool, False, "Set --verb ON for verbose output."),
        AdapterParameterSpec(
            "post_data",
            str,
            "",
            "POST data comma list for --postData, for example param1,value1,param2,value2.",
        ),
        AdapterParameterSpec(
            "request_headers",
            str,
            "",
            "Request headers comma list for --requestHeaders, for example Header,Value.",
        ),
        AdapterParameterSpec("injected_parameter", str, "", "Parameter to inject for --injectedParameter."),
        AdapterParameterSpec("inject_size", int, 0, "Payload size for --injectSize; 0 leaves default."),
        AdapterParameterSpec(
            "inject_format",
            int,
            0,
            "Payload format for --injectFormat: 1 alphanumeric, 2 letters, 3 numbers, 4 email; 0 leaves default.",
        ),
        AdapterParameterSpec("params", str, "", "Parameters to inject in a comma-separated list for --params."),
        AdapterParameterSpec("do_time_attack", str, "", "Timing attack switch for --doTimeAttack, usually y or n."),
        AdapterParameterSpec("save_path", str, "", "Output file path for --savePath."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "attack", "--attack")
    add_value(tokens, kwargs, "platform", "--platform")
    victim = kwargs.get("victim") or kwargs.get("target")
    if victim:
        tokens.extend(["--victim", str(victim)])
    add_value(tokens, kwargs, "db_port", "--dbPort")
    add_value(tokens, kwargs, "my_ip", "--myIP")
    add_value(tokens, kwargs, "my_port", "--myPort")
    add_value(tokens, kwargs, "web_port", "--webPort")
    add_value(tokens, kwargs, "uri", "--uri")
    add_value(tokens, kwargs, "http_method", "--httpMethod")
    if kwargs.get("https"):
        tokens.extend(["--https", "ON"])
    if kwargs.get("verbose"):
        tokens.extend(["--verb", "ON"])
    add_value(tokens, kwargs, "post_data", "--postData")
    add_value(tokens, kwargs, "request_headers", "--requestHeaders")
    add_value(tokens, kwargs, "injected_parameter", "--injectedParameter")
    add_value(tokens, kwargs, "inject_size", "--injectSize")
    add_value(tokens, kwargs, "inject_format", "--injectFormat")
    add_value(tokens, kwargs, "params", "--params")
    add_value(tokens, kwargs, "do_time_attack", "--doTimeAttack")
    add_value(tokens, kwargs, "save_path", "--savePath")
    return tokens
