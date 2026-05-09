"""Mobile Security tools — Android/iOS analysis and instrumentation (3 tools)."""

from hacking_mcp.models import HackingToolDef, SafetyTier

MOBILE_SECURITY_TOOLS: list[HackingToolDef] = [
    HackingToolDef(
        name="mobsf",
        title="MobSF (Mobile Security Framework)",
        description="All-in-one mobile app pentesting, malware analysis, and security assessment framework.",
        category="Mobile Security",
        install_commands=[
            "git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git",
            "cd Mobile-Security-Framework-MobSF && ./setup.sh",
        ],
        run_command="cd Mobile-Security-Framework-MobSF && ./run.sh",
        project_url="https://github.com/MobSF/Mobile-Security-Framework-MobSF",
        tags=["mobile", "android", "ios", "analysis", "malware", "pentesting"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux", "macos"],
    ),
    HackingToolDef(
        name="frida",
        title="Frida (Dynamic Instrumentation)",
        description="Dynamic instrumentation toolkit for runtime hooking on Android, iOS, Windows, macOS, Linux.",
        category="Mobile Security",
        install_commands=["pip install --user frida-tools"],
        run_command="frida {target}",
        project_url="https://github.com/frida/frida-tools",
        tags=["mobile", "android", "ios", "hooking", "instrumentation", "runtime"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux", "macos"],
    ),
    HackingToolDef(
        name="objection",
        title="Objection (Mobile Runtime Exploration)",
        description="Runtime mobile exploration toolkit powered by Frida — no jailbreak/root required.",
        category="Mobile Security",
        install_commands=["pip install --user objection"],
        run_command="objection",
        project_url="https://github.com/sensepost/objection",
        tags=["mobile", "android", "ios", "runtime", "exploration", "frida"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux", "macos"],
    ),
]
