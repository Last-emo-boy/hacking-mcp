"""AI-facing usage guidance for security tools.

This layer turns raw hackingtool-style metadata into concise guidance an agent
can use to choose the right MCP endpoint, target shape, and options.
"""

from dataclasses import dataclass

from hacking_mcp.models import HackingToolDef, SafetyTier


@dataclass(frozen=True)
class ToolAIHelp:
    endpoint: str
    target_hint: str
    option_hint: str
    safe_example: str
    cautions: list[str]
    related_tags: list[str]


_CATEGORY_ENDPOINTS = {
    "Information Gathering": "security_run_recon",
    "Web Attack": "security_run_web_audit",
    "Forensics": "security_run_forensics",
    "Cloud Security": "security_run_cloud_audit",
    "Active Directory": "security_run_ad_tools",
    "SQL Injection": "security_run_exploit",
    "XSS Attack": "security_run_scanner",
    "Exploit Framework": "security_run_exploit",
    "Post Exploitation": "security_run_exploit",
}


def build_ai_help(tool: HackingToolDef) -> ToolAIHelp:
    endpoint = _endpoint_for(tool)
    target_hint = _target_hint(tool)
    option_hint = _option_hint(tool)
    safe_target = _safe_target(tool)
    safe_example = (
        f'{endpoint}(tool_name="{tool.name}", target="{safe_target}", options="")'
        if endpoint
        else "This tool is not exposed through a run endpoint by default."
    )
    return ToolAIHelp(
        endpoint=endpoint,
        target_hint=target_hint,
        option_hint=option_hint,
        safe_example=safe_example,
        cautions=_cautions(tool),
        related_tags=sorted(set(tool.tags)),
    )


def format_ai_help(tool: HackingToolDef) -> str:
    help_doc = build_ai_help(tool)
    lines = [
        "## AI Usage Guidance",
        f"**Recommended endpoint:** `{help_doc.endpoint or 'not exposed'}`",
        f"**Target shape:** {help_doc.target_hint}",
        f"**Options:** {help_doc.option_hint}",
        f"**Safe local test:** `{help_doc.safe_example}`",
    ]
    if help_doc.related_tags:
        lines.append(f"**Tags:** {', '.join(help_doc.related_tags)}")
    if help_doc.cautions:
        lines.append("")
        lines.append("**Cautions:**")
        lines.extend(f"- {item}" for item in help_doc.cautions)
    return "\n".join(lines)


def _endpoint_for(tool: HackingToolDef) -> str:
    if tool.safety_tier == SafetyTier.DANGEROUS or tool.archived:
        return ""
    if tool.name in {"trufflehog", "gitleaks", "sherlock", "socialscan", "finduser", "socialmapper", "knockmail", "hatcloud"}:
        return "security_run_recon"
    if tool.name in {"nuclei", "nikto", "wafw00f", "testssl", "owasp-zap", "dalfox", "xspear", "xsscon", "xanxss", "xsstrike", "rvuln", "dsss", "sqlscan"}:
        return "security_run_scanner"
    return _CATEGORY_ENDPOINTS.get(tool.category, "")


def _target_hint(tool: HackingToolDef) -> str:
    tags = set(tool.tags)
    text = f"{tool.name} {tool.title} {tool.description}".lower()
    if "email" in tags:
        return "email address, for example user@example.com"
    if "username" in tags or "social" in tags or "social-media" in tags:
        return "username or account identifier"
    if "git" in tags or "secrets" in tags:
        return "local repository/path or supported source URL"
    if "cloud" in tags or tool.category == "Cloud Security":
        return "cloud account/profile, container image, IaC path, or leave empty if the tool uses local credentials"
    if "forensics" in tags:
        return "local evidence file/path, memory image, firmware image, or literal input for helper tools"
    if "hash" in tags:
        return "hash value or local file, depending on the tool"
    if "web" in tags or "http" in tags or "url" in tags or "xss" in tags or "sqli" in tags:
        return "URL such as https://example.com or http://127.0.0.1:8000"
    if "network" in tags or "port-scan" in tags:
        return "IP address, CIDR, or hostname within authorized scope"
    if "subdomain" in tags or "dns" in tags:
        return "domain name within authorized scope"
    return "tool-specific target; inspect description and run command before use"


def _option_hint(tool: HackingToolDef) -> str:
    if "{target}" not in tool.run_command:
        return "Usually empty; this tool's run command does not use the target placeholder."
    if tool.name == "nmap":
        return "Optional nmap flags, for example -sV -p 80,443"
    if tool.name in {"nuclei", "httpx", "katana", "ffuf", "feroxbuster", "gobuster", "dirsearch"}:
        return "Additional CLI flags supported by the underlying web tool."
    if tool.safety_tier == SafetyTier.CAUTION:
        return "Keep minimal; only pass flags needed for the authorized assessment."
    return "Additional CLI flags, or empty string for the default command."


def _safe_target(tool: HackingToolDef) -> str:
    tags = set(tool.tags)
    if "email" in tags:
        return "user@example.com"
    if "username" in tags or "social" in tags or "social-media" in tags:
        return "testuser"
    if "web" in tags or "http" in tags or "url" in tags or "xss" in tags or "sqli" in tags:
        return "http://127.0.0.1:8000"
    if "forensics" in tags or "hash" in tags:
        return "local-test"
    if tool.category == "Cloud Security":
        return ""
    return "localhost"


def _cautions(tool: HackingToolDef) -> list[str]:
    cautions: list[str] = []
    if tool.safety_tier == SafetyTier.CAUTION:
        cautions.append("Requires explicit authorization and should be used only against approved targets.")
    if tool.safety_tier == SafetyTier.DANGEROUS:
        cautions.append("Dangerous tool; excluded from MCP execution and installation by policy.")
    if tool.archived:
        reason = tool.archived_reason.rstrip(".")
        suffix = f": {reason}" if reason else ""
        cautions.append(f"Archived catalog entry{suffix}.")
    if tool.requires_root:
        cautions.append("May require root privileges in WSL/Linux.")
    if tool.requires_wifi:
        cautions.append("Requires compatible wireless hardware and local authorization.")
    if tool.requires_docker:
        cautions.append("Requires Docker.")
    if tool.category in {"Phishing Attack", "Payload Creation", "DDOS Attack", "Remote Administration (RAT)"}:
        cautions.append("Category is disabled by the default safety policy.")
    return cautions
