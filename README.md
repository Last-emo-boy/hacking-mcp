<div align="center">

# 🛡 hacking-mcp

**MCP Server — 184 Security Tools for AI-Assisted Pentesting**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.0-FF61DC?style=for-the-badge&logo=anthropic&logoColor=white)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-00FF88?style=for-the-badge)](LICENSE)

[![Tools](https://img.shields.io/badge/Tools-184-00FF88?style=flat-square)](.)
[![Categories](https://img.shields.io/badge/Categories-20-7B61FF?style=flat-square)](.)
[![MCP Endpoints](https://img.shields.io/badge/MCP_Endpoints-209-FF61DC?style=flat-square)](.)
[![Tests](https://img.shields.io/badge/Tests-218_passing-00FF88?style=flat-square)](.)
[![Platform](https://img.shields.io/badge/Platform-Windows_|_Linux_|_macOS-FFA116?style=flat-square)](.)

[![Star](https://img.shields.io/github/stars/Last-emo-boy/hacking-mcp?style=social)](.)

</div>

---

> **⚠️ For authorized security testing only.** Always obtain written permission before testing.

> **💡 Inspiration**: Tool catalog derived from [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) (MIT). hacking-mcp is a ground-up reimplementation as an MCP server — no original code is used. All execution, safety, orchestration, background task, and asset management layers are original.

---

## 📌 Features

|  | Feature | Description |
|:---:|---|---|
| 🐍 | **Native MCP Server** | FastMCP-based, stdio transport, works with Claude Code, Claude Desktop, Codex CLI |
| 🖥 | **184 Security Tools** | Ported from hackingtool across 20 categories — recon, web, forensics, cloud, AD, exploit, and more |
| 🔍 | **Progressive Disclosure** | Browse by category → see compact tool list → drill into full detail. Never flood context |
| 🏷 | **3-Tier Safety** | SAFE (read-only), CAUTION (confirmation required), DANGEROUS (permanently blocked) |
| 💡 | **Scope Enforcement** | CIDR and domain whitelisting — targets outside scope are auto-rejected |
| ✅ | **One-Click Install** | `security_install_tool("nmap")` — auto-detects git clone, pip, apt, go, gem, and more |
| ⚡ | **Background Tasks** | `security_task_start(...)` — non-blocking execution with persistent state and cancellation |
| 🔄 | **Diff Comparison** | `security_asset_compare(target, scan1, scan2)` — unified diff of two scans |
| 📂 | **Asset Management** | Per-target output in `~/.hacking-mcp/assets/192.168.1.1/` — structured JSON, always queryable |
| 🐳 | **WSL2 Auto-Routing** | Windows → auto-detects WSL2 distro and routes Linux tools through `wsl bash -c` |
| 🚀 | **Extensible** | `ToolProvider` ABC — add Docker tools, API wrappers, custom YAML configs |
| 🏢 | **Audit Logging** | Every invocation recorded to persistent JSONL: timestamp, tool, target, args, allowed/blocked |

---

## 🚀 Quick Start

| # | Command | What it does |
|:---:|---|---|
| 1 | `pip install git+https://github.com/user/hacking-mcp.git` | Install from GitHub |
| 2 | `hacking-mcp` | Start the MCP server (stdio transport) |
| 3 | `security_list_tools` | Browse 20 categories interactively |
| 4 | `security_install_tool("nmap")` | One-click install nmap |
| 5 | `security_run_recon("nmap", "192.168.1.1", "-sV")` | Run your first scan |

### Claude Configuration

<table>
<tr><td width="50%">

**Claude Code**
```json
// .mcp.json (project root)
{
  "mcpServers": {
    "hacking-mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "hacking_mcp"]
    }
  }
}
```

</td><td width="50%">

**Claude Desktop**
```json
// claude_desktop_config.json
{
  "mcpServers": {
    "hacking-mcp": {
      "command": "python",
      "args": ["-m", "hacking_mcp"]
    }
  }
}
```

</td></tr>
</table>

---

## 📂 Data Directory

```
~/.hacking-mcp/
├── tools/                  # Git clones & installed tools
├── installs/
│   └── state.json          # Install state: {nmap: {installed: true, method: "apt"}, ...}
├── tasks/
│   └── task-*.json         # Background task state & results
├── assets/                 # Per-target structured output
│   ├── 192.168.1.1/
│   │   ├── index.json
│   │   ├── 2026-05-05T103000Z_nmap.json
│   │   └── 2026-05-05T110000Z_nuclei.json
│   └── example.com/
│       └── ...
├── audit/
│   └── audit.jsonl         # Persistent invocation and policy-decision log
└── safety_policy.yaml      # Your custom safety config (auto-generated)
```

---

## 🧰 Tool Categories

<div align="center">

| # | Category | | # | Category | |
|:---:|---|:---:|:---:|---|:---:|
| 1 | 🟢 **Information Gathering** | 27 | 11 | 🟢 **Wordlist Generator** | 7 |
| 2 | 🟢 **Web Attack** | 20 | 12 | 🟢 **Steganography** | 4 |
| 3 | 🟢 **Forensics** | 8 | 13 | 🟡 **Mobile Security** | 3 |
| 4 | 🟡 **Cloud Security** | 4 | 14 | 🟢 **Reverse Engineering** | 5 |
| 5 | 🟡 **Active Directory** | 6 | 15 | 🚫 **DDOS Attack** | 6 |
| 6 | 🟡 **SQL Injection** | 7 | 16 | 🚫 **Phishing Attack** | 17 |
| 7 | 🟡 **XSS Attack** | 9 | 17 | 🚫 **Payload Creation** | 8 |
| 8 | 🟡 **Exploit Framework** | 3 | 18 | 🚫 **Wireless Attack** | 13 |
| 9 | 🟡 **Post Exploitation** | 10 | 19 | 🚫 **Anonymously Hiding** | 2 |
| 10 | 🟡 **Other Tools** | 24 | 20 | 🚫 **Remote Administration (RAT)** | 1 |

> 🟢 = SAFE (always available) · 🟡 = CAUTION (requires confirmation) · 🚫 = DANGEROUS (disabled by default)

</div>

---

## 📡 MCP Tool Reference (209 endpoints)

The server exposes 25 base workflow endpoints plus 184 generated per-tool adapters under
`security_tool_<tool_name>`. Safety-eligible adapters execute through the normal
orchestrator gates; dangerous, archived, no-command, or policy-disabled adapters return
policy information only and never execute the underlying tool.
Adapters expose generated tool-specific parameters such as `ports`, `wordlist`,
`severity`, `risk`, and `profile` where applicable, while keeping `options` for raw
CLI flags.

### Discovery

| Endpoint | Description |
|---|---|
| `security_list_tools` | Browse categories (L1) → list tools in category (L2) → search by keyword |
| `security_list_tool_adapters` | Inventory all generated per-tool adapters, filter executable vs policy-only |
| `security_get_tool_info` | Full detail (L3): description, install commands, safety tier, project URL |
| `security_get_environment` | OS, execution backend (native/WSL2), WSL distro, tools directory |
| `security_get_policy` | Disabled categories, confirmation categories, scope, execution limits |

### Execution

| Endpoint | Tools | Tier |
|---|---|---|
| `security_run_recon` | nmap, amass, theHarvester, subfinder, httpx, masscan, holehe, maigret, sherlock... | 🟢 SAFE |
| `security_run_scanner` | nuclei, nikto, wafw00f, dalfox, xsstrike, dsss, sqlscan... | 🟢 SAFE |
| `security_run_web_audit` | ffuf, dirsearch, gobuster, feroxbuster, katana, arjun, sublist3r... | 🟢 SAFE |
| `security_run_forensics` | binwalk, volatility3, trufflehog, gitleaks, haiti, steghide... | 🟢 SAFE |
| `security_run_cloud_audit` | prowler, scoutsuite, trivy, pacu | 🟡 CAUTION |
| `security_run_ad_tools` | bloodhound, netexec, impacket, certipy, kerbrute, responder | 🟡 CAUTION |
| `security_run_exploit` | sqlmap, nosqlmap, commix, routersploit, websploit... | 🟡 CAUTION |

### Install

| Endpoint | Description |
|---|---|
| `security_install_tool` | One-click install: auto-detects git clone / pip / apt / go / gem / curl |
| `security_get_install_status` | Check install state for one tool or list all |
| `security_uninstall_tool` | Remove install tracking |

### Background Tasks

| Endpoint | Description |
|---|---|
| `security_task_start` | Launch background scan → returns `task_id` immediately |
| `security_task_status` | Check progress, get results when done |
| `security_cancel_task` | Kill running task |
| `security_list_tasks` | List all tasks, filter by status (pending/running/completed/failed/cancelled) |

### Asset Management

| Endpoint | Description |
|---|---|
| `security_asset_list` | All tracked targets with scan counts |
| `security_asset_history` | Scan timeline for a target, optional tool filter |
| `security_asset_scan` | Full stdout/stderr for a specific scan |
| `security_asset_compare` | Unified diff between two scans — see what changed |

---

## 🛡 Safety Configuration

Edit `~/.hacking-mcp/safety_policy.yaml` (auto-generated on first run):

```yaml
# Disabled categories — tools in these will never execute
disabled_categories:
  - "DDOS Attack"
  - "Remote Administration (RAT)"
  - "Payload Creation"
  - "Phishing Attack"
  - "Wireless Attack"
  - "Anonymously Hiding"

# Confirmation required — AI must explicitly confirm before each use
require_confirmation_categories:
  - "SQL Injection"
  - "Exploit Framework"
  - "Post Exploitation"
  - "XSS Attack"

# Target scope — empty = allow all
scope:
  allowed_cidrs:
    - "10.0.0.0/8"
    - "192.168.1.0/24"
  allowed_domains:
    - "example.com"
    - "*.test.local"

# Execution limits
max_execution_timeout_seconds: 300
max_output_bytes: 52428800  # 50MB
```

---

## 📦 Installation

<table>
<tr><td width="50%">

**From Source**
```bash
git clone https://github.com/user/hacking-mcp.git
cd hacking-mcp
pip install -e .
```

</td><td width="50%">

**With Dev Dependencies**
```bash
git clone https://github.com/user/hacking-mcp.git
cd hacking-mcp
pip install -e ".[dev]"
pytest tests/ -v
```

</td></tr>
</table>

---

## 🧪 Development

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_tasks.py -v

# MCP Inspector (interactive testing)
mcp dev src/hacking_mcp/server.py

# Run the server directly
python -m hacking_mcp
```

---

## 🔧 Requirements

| Dependency | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Runtime |
| mcp | 1.0+ | FastMCP framework |
| pydantic | 2.0+ | Data validation |
| pyyaml | 6.0+ | Config parsing |
| WSL2 | Any distro | Linux tool routing (Windows only) |

---

## 📜 License & Attribution

- **hacking-mcp** is licensed under [MIT](LICENSE)
- Tool catalog (names, categories, install/run commands) derived from [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) (MIT License)
- All execution, safety, WSL2, orchestration, background task, and asset management code is original

---

<div align="center">

### 🛡 Made for Security Professionals

**Use responsibly. Test only what you own or have written authorization for.**

</div>
