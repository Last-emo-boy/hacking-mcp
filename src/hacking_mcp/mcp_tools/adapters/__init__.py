"""Registry for split-out dedicated per-tool adapters."""

from collections.abc import Callable

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters import owasp_zap, sherlock, theharvester, whatweb


ParameterProvider = Callable[[], list[AdapterParameterSpec]]
OptionsBuilder = Callable[[dict], list[str]]


PARAMETER_PROVIDERS: dict[str, ParameterProvider] = {
    "owasp-zap": owasp_zap.parameters,
    "sherlock": sherlock.parameters,
    "theHarvester": theharvester.parameters,
    "whatweb": whatweb.parameters,
}

OPTIONS_BUILDERS: dict[str, OptionsBuilder] = {
    "owasp-zap": owasp_zap.build_options,
    "sherlock": sherlock.build_options,
    "theHarvester": theharvester.build_options,
    "whatweb": whatweb.build_options,
}


def has_split_adapter(tool_name: str) -> bool:
    return tool_name in PARAMETER_PROVIDERS and tool_name in OPTIONS_BUILDERS


def split_adapter_parameters(tool_name: str) -> list[AdapterParameterSpec] | None:
    provider = PARAMETER_PROVIDERS.get(tool_name)
    if provider is None:
        return None
    return provider()


def split_adapter_options(tool_name: str, kwargs: dict) -> list[str] | None:
    builder = OPTIONS_BUILDERS.get(tool_name)
    if builder is None:
        return None
    return builder(kwargs)
