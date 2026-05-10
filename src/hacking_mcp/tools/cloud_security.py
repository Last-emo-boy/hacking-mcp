"""Cloud Security tools — AWS, Azure, GCP assessment and exploitation (4 tools)."""

from hacking_mcp.models import HackingToolDef, SafetyTier

CLOUD_SECURITY_TOOLS: list[HackingToolDef] = [
    HackingToolDef(
        name="prowler",
        title="Prowler (Cloud Security Scanner)",
        description="Open-source security tool for AWS, Azure, GCP, and Kubernetes assessments.",
        category="Cloud Security",
        install_commands=["pip install --user prowler"],
        run_command="prowler {target}",
        project_url="https://github.com/prowler-cloud/prowler",
        tags=["cloud", "aws", "azure", "gcp", "kubernetes", "compliance"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux", "macos"],
    ),
    HackingToolDef(
        name="scoutsuite",
        title="ScoutSuite (Multi-Cloud Auditing)",
        description="Multi-cloud security auditing tool for AWS, Azure, GCP, Alibaba, and Oracle.",
        category="Cloud Security",
        install_commands=["pip install --user scoutsuite"],
        run_command="scout {target}",
        project_url="https://github.com/nccgroup/ScoutSuite",
        tags=["cloud", "aws", "azure", "gcp", "audit", "multi-cloud"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux", "macos"],
    ),
    HackingToolDef(
        name="pacu",
        title="Pacu (AWS Exploitation Framework)",
        description="AWS exploitation framework for offensive security testing of AWS environments.",
        category="Cloud Security",
        install_commands=["pip install --user pacu"],
        run_command="pacu",
        project_url="https://github.com/RhinoSecurityLabs/pacu",
        tags=["cloud", "aws", "exploit", "offensive"],
        safety_tier=SafetyTier.CAUTION,
        supported_os=["linux", "macos"],
    ),
    HackingToolDef(
        name="trivy",
        title="Trivy (Container/K8s Scanner)",
        description="Comprehensive vulnerability scanner for containers, Kubernetes, IaC, and code.",
        category="Cloud Security",
        install_commands=[
            "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin",
        ],
        run_command="trivy {target}",
        project_url="https://github.com/aquasecurity/trivy",
        tags=["cloud", "container", "kubernetes", "vuln", "iac", "scanner"],
        safety_tier=SafetyTier.SAFE,
        supported_os=["linux", "macos"],
    ),
]
