# hacking-mcp

MCP server exposing ~100 security tools from [hackingtool](https://github.com/Z4nzu/hackingtool) for Claude-assisted security testing.

**For authorized security testing only.**

## Overview

hacking-mcp wraps security CLI tools as MCP tools, allowing Claude to assist with:

- **Reconnaissance** — nmap, theHarvester, Amass, subfinder, httpx, masscan, rustscan, holehe, maigret
- **Vulnerability Scanning** — nuclei, nikto, wafw00f, testssl, XSStrike, DalFox
- **Web Application Testing** — ffuf, dirsearch, gobuster, feroxbuster, katana, arjun, sublist3r
- **Digital Forensics** — binwalk, volatility3, pspy, trufflehog, gitleaks, haiti
- **Cloud Security** — prowler, scoutsuite, trivy, pacu
- **Active Directory** — bloodhound-python, netexec, certipy, kerbrute, responder, impacket
- **Exploitation** — sqlmap, nosqlmap, commix, routersploit (CAUTION-gated)

## Installation

```bash
pip install -e .
```

## Usage

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hacking-mcp": {
      "command": "python",
      "args": ["-m", "hacking_mcp"]
    }
  }
}
```

### Dev mode

```bash
mcp dev src/hacking_mcp/server.py
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `security_list_tools` | List/search/filter all 106 tools by category, tag, or keyword |
| `security_get_tool_info` | Detailed info on a tool including install commands |
| `security_get_policy` | Show current safety policy and scope configuration |
| `security_run_recon` | Reconnaissance tools (nmap, amass, theHarvester, etc.) |
| `security_run_scanner` | Vulnerability scanners (nuclei, nikto, dalfox, etc.) |
| `security_run_web_audit` | Web testing (ffuf, dirsearch, gobuster, etc.) |
| `security_run_forensics` | Forensics analysis (binwalk, volatility3, etc.) |
| `security_run_cloud_audit` | Cloud assessment (prowler, scoutsuite, trivy, etc.) |
| `security_run_ad_tools` | Active Directory tools (bloodhound, netexec, etc.) |
| `security_run_exploit` | Exploitation tools (sqlmap, commix, etc.) — CAUTION-gated |

## Safety Model

Three-tier safety system:

- **SAFE**: Recon, info gathering, analysis — always available
- **CAUTION**: Active scanning, exploitation — requires explicit target, logged
- **DANGEROUS**: DDOS, RAT, payload creation, phishing — **permanently excluded**

Configure via `config/safety_policy.yaml`. Set target scope to restrict operations to authorized IP ranges/domains.

## Requirements

- Python 3.10+
- Security tools must be installed separately (the MCP server detects them on PATH)
- Most tools require Linux; the server works on any OS but tools show as unavailable

## License

MIT
