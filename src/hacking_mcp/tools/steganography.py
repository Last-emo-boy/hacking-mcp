"""Steganography tools — hide/extract data in files (4 tools)."""

from hacking_mcp.models import HackingToolDef, SafetyTier

STEGANOGRAPHY_TOOLS: list[HackingToolDef] = [
    HackingToolDef(
        name="steghide",
        title="SteganoHide (steghide)",
        description="Hide and extract data within image and audio files using steghide.",
        category="Steganography",
        install_commands=["sudo apt-get install steghide -y"],
        run_command="steghide",
        project_url="https://steghide.sourceforge.net/",
        tags=["stegano", "hide", "extract", "image", "audio"],
        safety_tier=SafetyTier.SAFE,
    ),
    HackingToolDef(
        name="stegcracker",
        title="StegnoCracker",
        description="Brute-force utility to uncover hidden data inside files. Usage: stegcracker file wordlist.txt",
        category="Steganography",
        install_commands=["pip3 install stegcracker"],
        run_command="stegcracker {target}",
        project_url="https://github.com/Paradoxis/StegCracker",
        tags=["stegano", "bruteforce", "extract", "password"],
        safety_tier=SafetyTier.SAFE,
    ),
    HackingToolDef(
        name="stegocracker",
        title="StegoCracker",
        description="Multi-tool for hiding and retrieving data in image or audio files.",
        category="Steganography",
        install_commands=[
            "git clone https://github.com/W1LDN16H7/StegoCracker.git",
            "sudo chmod -R 755 StegoCracker",
        ],
        run_command="stego",
        project_url="https://github.com/W1LDN16H7/StegoCracker",
        tags=["stegano", "hide", "extract", "image", "audio"],
        safety_tier=SafetyTier.SAFE,
    ),
    HackingToolDef(
        name="whitespace",
        title="Whitespace (Snow Steganography)",
        description="Use whitespace and unicode characters for steganography — hide data in text.",
        category="Steganography",
        install_commands=[
            "git clone https://github.com/beardog108/snow10.git",
            "sudo chmod -R 755 snow10",
        ],
        run_command="cd snow10 && ./install.sh",
        project_url="https://github.com/beardog108/snow10",
        tags=["stegano", "whitespace", "text", "unicode", "snow"],
        safety_tier=SafetyTier.SAFE,
    ),
]
