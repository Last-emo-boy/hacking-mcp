"""Remote Administration Tools — RAT (1 tool)."""

from hacking_mcp.models import HackingToolDef, SafetyTier

RAT_TOOLS: list[HackingToolDef] = [
    HackingToolDef(
        name="pyshell",
        title="Pyshell (Remote Shell)",
        description="Python-based RAT tool that can download/upload files, execute OS commands, and more.",
        category="Remote Administration (RAT)",
        install_commands=[
            "git clone https://github.com/knassar702/Pyshell.git",
            "pip install --user pyscreenshot python-nmap requests",
        ],
        run_command="cd Pyshell && ./Pyshell",
        project_url="https://github.com/knassar702/pyshell",
        tags=["rat", "remote", "shell", "backdoor"],
        safety_tier=SafetyTier.DANGEROUS,
    ),
]
