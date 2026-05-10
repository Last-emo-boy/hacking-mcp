"""Registry-derived adapter metadata helpers.

These wrappers keep one module per registry tool while preserving the
existing generic parameter and option generation behavior.
"""

from hacking_mcp.ai_help import build_ai_help
from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.registry import ALL_CATEGORIES


GENERIC_MODULES = {
    'dracnmap': 'dracnmap',
    'portscan': 'portscan',
    'host2ip': 'host2ip',
    'xerosploit': 'xerosploit',
    'redhawk': 'redhawk',
    'reconspider': 'reconspider',
    'isitdown': 'isitdown',
    'infoga': 'infoga',
    'recondog': 'recondog',
    'striker': 'striker',
    'secretfinder': 'secretfinder',
    'shodanfy': 'shodanfy',
    'rang3r': 'rang3r',
    'breacher': 'breacher',
    'holehe': 'holehe',
    'maigret': 'maigret',
    'spiderfoot': 'spiderfoot',
    'web2attack': 'web2attack',
    'skipfish': 'skipfish',
    'sublist3r': 'sublist3r',
    'checkurl': 'checkurl',
    'blazy': 'blazy',
    'takeover': 'takeover',
    'dirb': 'dirb',
    'caido': 'caido',
    'mitmproxy': 'mitmproxy',
    'autopsy': 'autopsy',
    'wireshark': 'wireshark',
    'bulk-extractor': 'bulk_extractor',
    'guymager': 'guymager',
    'toolsley': 'toolsley',
    'xssfinder': 'xssfinder',
    'xss-payload-generator': 'xss_payload_generator',
    'xss-freak': 'xss_freak',
    'rvuln': 'rvuln',
    'vegil': 'vegil',
    'chrome-keylogger': 'chrome_keylogger',
    'mythic': 'mythic',
    'cupp': 'cupp',
    'wlcreator': 'wlcreator',
    'goblin-wordgenerator': 'goblin_wordgenerator',
    'showme': 'showme',
    'stegocracker': 'stegocracker',
    'whitespace': 'whitespace',
    'ddos-script': 'ddos_script',
    'slowloris': 'slowloris',
    'asyncrone': 'asyncrone',
    'ufonet': 'ufonet',
    'goldeneye': 'goldeneye',
    'saphyra': 'saphyra',
    'autophisher': 'autophisher',
    'advphishing': 'advphishing',
    'socialfish': 'socialfish',
    'iseeyou': 'iseeyou',
    'saycheese': 'saycheese',
    'qrjacking': 'qrjacking',
    'thanos': 'thanos',
    'qrljacking': 'qrljacking',
    'dnstwist': 'dnstwist',
    'stitch': 'stitch',
    'spycam': 'spycam',
    'enigma': 'enigma',
    'wifipumpkin': 'wifipumpkin',
    'pixiewps': 'pixiewps',
    'bluepot': 'bluepot',
    'eviltwin': 'eviltwin',
    'fastssh': 'fastssh',
    'howmanypeople': 'howmanypeople',
    'pyshell': 'pyshell',
    'keydroid': 'keydroid',
    'mysms': 'mysms',
    'lockphish': 'lockphish',
    'droidcam': 'droidcam',
    'evilapp': 'evilapp',
    'knockmail': 'knockmail',
    'hashbuster': 'hashbuster',
    'evilurl': 'evilurl',
    'instabrute': 'instabrute',
    'allinone-socialmedia': 'allinone_socialmedia',
    'faceshell': 'faceshell',
    'appcheck': 'appcheck',
    'socialmapper': 'socialmapper',
    'finduser': 'finduser',
    'socialscan': 'socialscan',
    'wifijammer-ng': 'wifijammer_ng',
    'kawaiideauther': 'kawaiideauther',
    'debinject': 'debinject',
    'pixload': 'pixload',
    'gospider': 'gospider',
    'hatcloud': 'hatcloud',
    'terminal-multiplexer': 'terminal_multiplexer',
    'crivo': 'crivo'
}


def parameters_for(tool_name: str) -> list[AdapterParameterSpec]:
    from hacking_mcp.mcp_tools.tool_adapters import ToolAdapterSpec, _adapter_parameters

    tool = _tool_by_name(tool_name)
    ai_help = build_ai_help(tool)
    spec = ToolAdapterSpec(
        tool_name=tool.name,
        mcp_name=f"security_tool_{tool.name}",
        title=tool.title,
        category=tool.category,
        description=tool.description,
        target_hint=ai_help.target_hint,
        option_hint=ai_help.option_hint,
        safety_tier=tool.safety_tier.value,
        target_required=bool(tool.run_command and "{target}" in tool.run_command),
        validate_scope=False,
        requires_confirmation=False,
        exposed=True,
    )
    excluded = {"target", "options", "confirm_authorized"}
    return [param for param in _adapter_parameters(tool, spec, use_split=False) if param.name not in excluded]


def build_options_for(tool_name: str, kwargs: dict) -> list[str]:
    from hacking_mcp.mcp_tools.tool_adapters import _structured_options

    return _structured_options(_tool_by_name(tool_name), kwargs, use_split=False)


def _tool_by_name(tool_name: str):
    for tools in ALL_CATEGORIES.values():
        for tool in tools:
            if tool.name == tool_name:
                return tool
    raise KeyError(f"Unknown registry tool: {tool_name}")
