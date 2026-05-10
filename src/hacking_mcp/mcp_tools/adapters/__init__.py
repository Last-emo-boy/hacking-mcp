"""Registry for split-out dedicated per-tool adapters."""

from collections.abc import Callable

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters import (
    androguard,
    amass,
    apk2gold,
    binwalk,
    dirsearch,
    feroxbuster,
    ffuf,
    frida,
    ghidra,
    gobuster,
    haiti,
    hashcat,
    httpx,
    jadx,
    john,
    masscan,
    mobsf,
    nmap,
    nuclei,
    objection,
    owasp_zap,
    pspy,
    radare2,
    rustscan,
    sherlock,
    stegcracker,
    steghide,
    subfinder,
    theharvester,
    volatility3,
    whatweb,
)


ParameterProvider = Callable[[], list[AdapterParameterSpec]]
OptionsBuilder = Callable[[dict], list[str]]


PARAMETER_PROVIDERS: dict[str, ParameterProvider] = {
    "androguard": androguard.parameters,
    "amass": amass.parameters,
    "apk2gold": apk2gold.parameters,
    "binwalk": binwalk.parameters,
    "dirsearch": dirsearch.parameters,
    "feroxbuster": feroxbuster.parameters,
    "ffuf": ffuf.parameters,
    "frida": frida.parameters,
    "ghidra": ghidra.parameters,
    "gobuster": gobuster.parameters,
    "haiti": haiti.parameters,
    "hashcat": hashcat.parameters,
    "httpx": httpx.parameters,
    "jadx": jadx.parameters,
    "john": john.parameters,
    "masscan": masscan.parameters,
    "mobsf": mobsf.parameters,
    "nmap": nmap.parameters,
    "nuclei": nuclei.parameters,
    "objection": objection.parameters,
    "owasp-zap": owasp_zap.parameters,
    "pspy": pspy.parameters,
    "radare2": radare2.parameters,
    "rustscan": rustscan.parameters,
    "sherlock": sherlock.parameters,
    "stegcracker": stegcracker.parameters,
    "steghide": steghide.parameters,
    "subfinder": subfinder.parameters,
    "theHarvester": theharvester.parameters,
    "volatility3": volatility3.parameters,
    "whatweb": whatweb.parameters,
}

OPTIONS_BUILDERS: dict[str, OptionsBuilder] = {
    "androguard": androguard.build_options,
    "amass": amass.build_options,
    "apk2gold": apk2gold.build_options,
    "binwalk": binwalk.build_options,
    "dirsearch": dirsearch.build_options,
    "feroxbuster": feroxbuster.build_options,
    "ffuf": ffuf.build_options,
    "frida": frida.build_options,
    "ghidra": ghidra.build_options,
    "gobuster": gobuster.build_options,
    "haiti": haiti.build_options,
    "hashcat": hashcat.build_options,
    "httpx": httpx.build_options,
    "jadx": jadx.build_options,
    "john": john.build_options,
    "masscan": masscan.build_options,
    "mobsf": mobsf.build_options,
    "nmap": nmap.build_options,
    "nuclei": nuclei.build_options,
    "objection": objection.build_options,
    "owasp-zap": owasp_zap.build_options,
    "pspy": pspy.build_options,
    "radare2": radare2.build_options,
    "rustscan": rustscan.build_options,
    "sherlock": sherlock.build_options,
    "stegcracker": stegcracker.build_options,
    "steghide": steghide.build_options,
    "subfinder": subfinder.build_options,
    "theHarvester": theharvester.build_options,
    "volatility3": volatility3.build_options,
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
