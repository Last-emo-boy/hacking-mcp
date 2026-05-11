"""DDOS Attack tools — stress testing and denial of service (6 tools)."""

from hacking_mcp.models import HackingToolDef, SafetyTier

DDOS_TOOLS: list[HackingToolDef] = [
    HackingToolDef(
        name="ddos-script",
        title="DDoS Script (36 Methods)",
        description="Best DDoS Attack Script with 36 plus methods. For SECURITY TESTING PURPOSES ONLY!",
        category="DDOS Attack",
        install_commands=[
            "git clone https://github.com/the-deepnet/ddos.git",
            "cd ddos && sudo pip3 install -r requirements.txt",
        ],
        run_command="cd ddos && sudo python3 ddos {target}",
        project_url="https://github.com/the-deepnet/ddos",
        tags=["ddos", "stress-test", "network"],
        safety_tier=SafetyTier.DANGEROUS,
        supported_os=["linux"],
        requires_root=True,
    ),
    HackingToolDef(
        name="slowloris",
        title="SlowLoris (HTTP DoS)",
        description="HTTP Denial of Service attack tool — sends lots of HTTP requests to exhaust server resources.",
        category="DDOS Attack",
        install_commands=["sudo pip3 install slowloris"],
        run_command="slowloris {target}",
        tags=["ddos", "http", "stress-test"],
        safety_tier=SafetyTier.DANGEROUS,
        supported_os=["linux"],
    ),
    HackingToolDef(
        name="asyncrone",
        title="Asyncrone | SYN Flood DDoS",
        description="Multifunction SYN Flood DDoS weapon written in C. Disables target systems by sending SYN packets intensively.",
        category="DDOS Attack",
        install_commands=[
            "git clone https://github.com/fatih4842/aSYNcrone.git",
            "cd aSYNcrone && sudo gcc aSYNcrone.c -o aSYNcrone -lpthread",
        ],
        run_command="",
        project_url="https://github.com/fatihsnsy/aSYNcrone",
        tags=["ddos", "syn-flood", "network"],
        safety_tier=SafetyTier.DANGEROUS,
        supported_os=["linux"],
        requires_root=True,
        archived=True,
        archived_reason=(
            "Original upstream and install repositories return 404 and no "
            "verified aSYNcrone.c source is available."
        ),
    ),
    HackingToolDef(
        name="ufonet",
        title="UFOnet (P2P Disruptive Toolkit)",
        description="Free P2P and cryptographic disruptive toolkit for DoS and DDoS attacks.",
        category="DDOS Attack",
        install_commands=[
            "git clone https://github.com/epsylon/ufonet.git",
            "cd ufonet && pip install --user .",
        ],
        run_command="cd ufonet && python3 ufonet --gui",
        project_url="https://github.com/epsylon/ufonet",
        tags=["ddos", "p2p", "network"],
        safety_tier=SafetyTier.DANGEROUS,
        supported_os=["linux"],
    ),
    HackingToolDef(
        name="goldeneye",
        title="GoldenEye (HTTP DoS Tester)",
        description="Python3 HTTP DoS Test Tool. Usage: ./goldeneye.py <url> [OPTIONS]",
        category="DDOS Attack",
        install_commands=[
            "git clone https://github.com/jseidl/GoldenEye.git",
            "chmod -R 755 GoldenEye",
        ],
        run_command="cd GoldenEye && sudo ./goldeneye.py {target}",
        project_url="https://github.com/jseidl/GoldenEye",
        tags=["ddos", "http", "stress-test"],
        safety_tier=SafetyTier.DANGEROUS,
        supported_os=["linux"],
        requires_root=True,
    ),
    HackingToolDef(
        name="saphyra",
        title="SaphyraDDoS",
        description="Python DDoS script for SECURITY TESTING PURPOSES ONLY.",
        category="DDOS Attack",
        install_commands=[
            "git clone https://github.com/anonymous24x7/Saphyra-DDoS.git",
            "chmod +x Saphyra-DDoS/saphyra.py",
        ],
        run_command="cd Saphyra-DDoS && python saphyra.py {target}",
        project_url="https://github.com/anonymous24x7/Saphyra-DDoS",
        tags=["ddos", "python", "stress-test"],
        safety_tier=SafetyTier.DANGEROUS,
        supported_os=["linux"],
    ),
]
