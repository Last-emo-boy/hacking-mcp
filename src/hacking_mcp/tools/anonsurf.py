"""Anonymously Hiding tools — Tor, privacy, IP masking (2 tools)."""

from hacking_mcp.models import HackingToolDef, SafetyTier

ANONSURF_TOOLS: list[HackingToolDef] = [
    HackingToolDef(
        name="anonsurf",
        title="Anonymously Surf (Tor)",
        description="Routes all traffic through Tor and automatically overwrites RAM on system shutdown.",
        category="Anonymously Hiding",
        install_commands=[
            "git clone https://github.com/Und3rf10w/kali-anonsurf.git",
            "cd kali-anonsurf && sudo ./installer.sh",
        ],
        run_command="sudo anonsurf",
        project_url="https://github.com/Und3rf10w/kali-anonsurf",
        tags=["anonymity", "tor", "privacy", "defense"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux"],
        requires_root=True,
    ),
    HackingToolDef(
        name="multitor",
        title="Multitor (Multiple Tor Instances)",
        description="Create and manage multiple Tor instances with load-balanced anonymity.",
        category="Anonymously Hiding",
        install_commands=[
            "git clone https://github.com/trimstray/multitor.git",
            "cd multitor && sudo bash setup.sh install",
        ],
        run_command="multitor",
        project_url="https://github.com/trimstray/multitor",
        tags=["anonymity", "tor", "privacy", "multitor", "defense"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux"],
        requires_root=True,
    ),
]
