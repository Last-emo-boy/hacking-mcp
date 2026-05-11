"""Dedicated adapter metadata for PyPhisher."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("port", int, 0, "PyPhisher local server port; 0 leaves default."),
        AdapterParameterSpec("template_option", str, "", "Template index for -o/--option."),
        AdapterParameterSpec("tunneler", str, "", "Tunneler selector for -t/--tunneler."),
        AdapterParameterSpec("region", str, "", "LocalXpose region."),
        AdapterParameterSpec("folder", str, "", "Custom template folder path."),
        AdapterParameterSpec("domain", str, "", "LocalXpose reserved domain."),
        AdapterParameterSpec("subdomain", str, "", "LocalXpose subdomain."),
        AdapterParameterSpec("redirect_url", str, "", "Redirection URL after data capture."),
        AdapterParameterSpec("mode", str, "", "PyPhisher mode, for example normal or test."),
        AdapterParameterSpec("troubleshoot", str, "", "Tunneler to troubleshoot."),
        AdapterParameterSpec("nokey", bool, False, "Use localtunnel without an SSH key."),
        AdapterParameterSpec("kshrt", bool, False, "Show kshrt URL."),
        AdapterParameterSpec("noupdate", bool, False, "Skip update checking."),
        AdapterParameterSpec("nokill", bool, False, "Skip killing services."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "port", "--port")
    add_value(tokens, kwargs, "template_option", "--option")
    add_value(tokens, kwargs, "tunneler", "--tunneler")
    add_value(tokens, kwargs, "region", "--region")
    add_value(tokens, kwargs, "folder", "--folder")
    add_value(tokens, kwargs, "domain", "--domain")
    add_value(tokens, kwargs, "subdomain", "--subdomain")
    add_value(tokens, kwargs, "redirect_url", "--url")
    add_value(tokens, kwargs, "mode", "--mode")
    add_value(tokens, kwargs, "troubleshoot", "--troubleshoot")
    add_bool(tokens, kwargs, "nokey", "--nokey")
    add_bool(tokens, kwargs, "kshrt", "--kshrt")
    add_bool(tokens, kwargs, "noupdate", "--noupdate")
    add_bool(tokens, kwargs, "nokill", "--nokill")
    return tokens
