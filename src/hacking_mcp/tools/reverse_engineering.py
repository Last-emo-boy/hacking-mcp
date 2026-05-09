"""Reverse Engineering tools — APK, binary, and malware analysis (5 tools)."""

from hacking_mcp.models import HackingToolDef, SafetyTier

REVERSE_ENGINEERING_TOOLS: list[HackingToolDef] = [
    HackingToolDef(
        name="androguard",
        title="Androguard (Android RE)",
        description="Reverse engineering, malware and goodware analysis of Android applications.",
        category="Reverse Engineering",
        install_commands=["sudo pip3 install -U androguard"],
        run_command="androguard --help",
        project_url="https://github.com/androguard/androguard",
        tags=["reverse-engineering", "android", "malware", "apk"],
        safety_tier=SafetyTier.SAFE,
    ),
    HackingToolDef(
        name="apk2gold",
        title="Apk2Gold (APK Decompiler)",
        description="CLI tool for decompiling Android APK apps to Java source code.",
        category="Reverse Engineering",
        install_commands=[
            "git clone https://github.com/lxdvs/apk2gold.git",
            "cd apk2gold && sudo bash make.sh",
        ],
        run_command="sudo apk2gold {target}",
        project_url="https://github.com/lxdvs/apk2gold",
        tags=["reverse-engineering", "android", "apk", "decompile", "java"],
        safety_tier=SafetyTier.SAFE,
    ),
    HackingToolDef(
        name="jadx",
        title="JadX (DEX to Java Decompiler)",
        description="Decompile Dalvik bytecode to Java classes from APK, dex, aar, and zip files.",
        category="Reverse Engineering",
        install_commands=[
            "git clone https://github.com/skylot/jadx.git",
            "cd jadx && ./gradlew dist",
        ],
        run_command="cd jadx && ./build/jadx/bin/jadx {target}",
        project_url="https://github.com/skylot/jadx",
        tags=["reverse-engineering", "android", "dex", "java", "decompile"],
        safety_tier=SafetyTier.SAFE,
    ),
    HackingToolDef(
        name="ghidra",
        title="Ghidra (NSA Reverse Engineering)",
        description="NSA's software reverse engineering framework — disassembly, decompilation, scripting.",
        category="Reverse Engineering",
        install_commands=["sudo apt-get install -y ghidra"],
        run_command="ghidraRun",
        project_url="https://github.com/NationalSecurityAgency/ghidra",
        tags=["reverse-engineering", "disassembler", "decompiler", "nsa", "malware"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux", "macos"],
    ),
    HackingToolDef(
        name="radare2",
        title="Radare2 (RE Framework)",
        description="Portable UNIX-like reverse engineering framework and command-line toolset.",
        category="Reverse Engineering",
        install_commands=[
            "git clone https://github.com/radareorg/radare2.git",
            "cd radare2 && sys/install.sh",
        ],
        run_command="r2 {target}",
        project_url="https://github.com/radareorg/radare2",
        tags=["reverse-engineering", "disassembler", "debugger", "binary", "analysis"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux", "macos"],
    ),
]
