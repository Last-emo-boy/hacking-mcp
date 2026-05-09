"""ToolRegistry — discovers installed tools, tracks availability, provides queries.

On Windows, scans for Linux tools inside WSL2 where available.
"""

import shutil
import platform
import subprocess
import logging
import shlex
from pathlib import Path
from typing import Optional

from hacking_mcp.models import HackingToolDef, ToolAvailability
from hacking_mcp.command import parse_command
from hacking_mcp.environment import (
    detect_environment,
    ExecBackend,
    _decode_wsl_output,
    get_tools_dir,
    to_wsl_path,
)
from hacking_mcp.providers import ToolProvider

logger = logging.getLogger("hacking-mcp.registry")

# Module-level cache for batch WSL scan results (shared across ToolRegistry instances)
_wsl_commands_cache: Optional[tuple[set[str], dict[str, str]]] = None

from hacking_mcp.tools.information_gathering import INFORMATION_GATHERING_TOOLS
from hacking_mcp.tools.web_attack import WEB_ATTACK_TOOLS
from hacking_mcp.tools.forensics import FORENSICS_TOOLS
from hacking_mcp.tools.cloud_security import CLOUD_SECURITY_TOOLS
from hacking_mcp.tools.active_directory import ACTIVE_DIRECTORY_TOOLS
from hacking_mcp.tools.sql_injection import SQL_INJECTION_TOOLS
from hacking_mcp.tools.xss_attack import XSS_ATTACK_TOOLS
from hacking_mcp.tools.exploit_frameworks import EXPLOIT_FRAMEWORK_TOOLS
from hacking_mcp.tools.post_exploitation import POST_EXPLOITATION_TOOLS
from hacking_mcp.tools.wordlist_generator import WORDLIST_GENERATOR_TOOLS
from hacking_mcp.tools.steganography import STEGANOGRAPHY_TOOLS
from hacking_mcp.tools.mobile_security import MOBILE_SECURITY_TOOLS
from hacking_mcp.tools.reverse_engineering import REVERSE_ENGINEERING_TOOLS
from hacking_mcp.tools.ddos import DDOS_TOOLS
from hacking_mcp.tools.phishing_attack import PHISHING_TOOLS
from hacking_mcp.tools.payload_creator import PAYLOAD_TOOLS
from hacking_mcp.tools.wireless_attack import WIRELESS_TOOLS
from hacking_mcp.tools.anonsurf import ANONSURF_TOOLS
from hacking_mcp.tools.remote_administration import RAT_TOOLS
from hacking_mcp.tools.other_tools import OTHER_TOOLS


# All category tool lists
ALL_CATEGORIES: dict[str, list[HackingToolDef]] = {
    "Information Gathering": INFORMATION_GATHERING_TOOLS,
    "Web Attack": WEB_ATTACK_TOOLS,
    "Forensics": FORENSICS_TOOLS,
    "Cloud Security": CLOUD_SECURITY_TOOLS,
    "Active Directory": ACTIVE_DIRECTORY_TOOLS,
    "SQL Injection": SQL_INJECTION_TOOLS,
    "XSS Attack": XSS_ATTACK_TOOLS,
    "Exploit Framework": EXPLOIT_FRAMEWORK_TOOLS,
    "Post Exploitation": POST_EXPLOITATION_TOOLS,
    "Wordlist Generator": WORDLIST_GENERATOR_TOOLS,
    "Steganography": STEGANOGRAPHY_TOOLS,
    "Mobile Security": MOBILE_SECURITY_TOOLS,
    "Reverse Engineering": REVERSE_ENGINEERING_TOOLS,
    "DDOS Attack": DDOS_TOOLS,
    "Phishing Attack": PHISHING_TOOLS,
    "Payload Creation": PAYLOAD_TOOLS,
    "Wireless Attack": WIRELESS_TOOLS,
    "Anonymously Hiding": ANONSURF_TOOLS,
    "Remote Administration (RAT)": RAT_TOOLS,
    "Other Tools": OTHER_TOOLS,
}

CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "Information Gathering": "Reconnaissance, OSINT, network scanning, and intelligence collection tools.",
    "Web Attack": "Web application scanning, fuzzing, directory discovery, and proxy tools.",
    "Forensics": "Memory, disk, network, and file analysis for digital investigations.",
    "Cloud Security": "Cloud infrastructure security assessment for AWS, Azure, GCP, and Kubernetes.",
    "Active Directory": "AD enumeration, attack path discovery, and credential-based attack tools.",
    "SQL Injection": "Detection and exploitation of SQL and NoSQL injection vulnerabilities.",
    "XSS Attack": "Cross-site scripting vulnerability detection, scanning, and payload generation.",
    "Exploit Framework": "Frameworks for exploiting embedded devices, web apps, and command injection.",
    "Post Exploitation": "C2 frameworks, reverse shells, privilege escalation, tunneling, and pivoting.",
    "Wordlist Generator": "Password profiling, wordlist generation, hash cracking, and hash identification.",
    "Steganography": "Hide and extract data within image, audio, and text files.",
    "Mobile Security": "Android and iOS application security testing, instrumentation, and analysis.",
    "Reverse Engineering": "Binary, APK, and malware reverse engineering and decompilation tools.",
    "DDOS Attack": "Stress testing and denial of service tools. DANGEROUS — excluded from execution by default.",
    "Phishing Attack": "Social engineering, credential harvesting, and phishing frameworks. DANGEROUS — excluded by default.",
    "Payload Creation": "Backdoor, payload, and dropper generators. DANGEROUS — excluded from execution by default.",
    "Wireless Attack": "WiFi, Bluetooth, rogue AP, and wireless auditing tools. DANGEROUS — excluded by default.",
    "Anonymously Hiding": "Tor routing, privacy, and IP masking tools for defensive anonymity.",
    "Remote Administration (RAT)": "Remote access trojans and backdoor tools. DANGEROUS — excluded by default.",
    "Other Tools": "Miscellaneous tools: Android hacking, social media bruteforce/finder, WiFi jamming, hash cracking, payload injection, web crawling, and more.",
}


class ToolRegistry:
    """Central registry of all known security tools with availability tracking.

    Scans PATH on initialization to determine which tools are installed.
    Provides query methods for discovery, filtering, and search.
    """

    def __init__(self, providers: Optional[list[ToolProvider]] = None):
        self._system = platform.system().lower()
        self._tools: dict[str, HackingToolDef] = {}
        self._availability: dict[str, ToolAvailability] = {}
        self._by_tag: dict[str, list[str]] = {}
        self._providers = providers
        self._wsl_scanned = False  # Defer WSL scan to first availability query
        self._build_index(providers)
        self._scan_availability()

    def _build_index(self, providers: Optional[list[ToolProvider]] = None) -> None:
        """Build internal lookup indexes from providers or built-in category tool lists."""
        if providers:
            for provider in providers:
                for tool in provider.get_tools():
                    self._tools[tool.name] = tool
                    for tag in tool.tags:
                        if tag not in self._by_tag:
                            self._by_tag[tag] = []
                        if tool.name not in self._by_tag[tag]:
                            self._by_tag[tag].append(tool.name)
        else:
            for category, tools in ALL_CATEGORIES.items():
                for tool in tools:
                    self._tools[tool.name] = tool
                    for tag in tool.tags:
                        if tag not in self._by_tag:
                            self._by_tag[tag] = []
                        self._by_tag[tag].append(tool.name)

    def _scan_availability(self) -> None:
        """Check which tools are on PATH (native only — WSL is deferred).

        Native PATH scan is fast. WSL2 scan runs lazily on first
        availability query to avoid blocking MCP startup.
        """
        env = detect_environment()
        use_wsl = env.backend == ExecBackend.WSL2

        for name, tool in self._tools.items():
            # Check platform support
            native_supported = self._system in tool.supported_os
            wsl_supported = use_wsl and "linux" in tool.supported_os
            platform_supported = native_supported or wsl_supported

            if not platform_supported:
                self._availability[name] = ToolAvailability(
                    tool_name=name,
                    available=False,
                    platform_supported=False,
                )
                continue

            exe = tool.executable

            if not tool.run_command:
                self._availability[name] = ToolAvailability(
                    tool_name=name,
                    available=False,
                    platform_supported=True,
                )
                continue

            # Only check native PATH if the tool actually supports this OS.
            # Otherwise generic names (python3, bash, java) on Windows host
            # cause false positives for Linux-only security tools.
            if native_supported and not wsl_supported:
                path = shutil.which(exe)
                if path and self._tool_chdir_exists_native(tool):
                    self._availability[name] = ToolAvailability(
                        tool_name=name,
                        available=True,
                        path=path,
                        platform_supported=True,
                    )
                    continue

            # WSL-capable tools: check during init only if cache exists;
            # otherwise defer to first query (lazy batch scan). This includes
            # tools that also support Windows because the runner uses the WSL2
            # backend whenever it is available.
            if wsl_supported:
                # Check module-level cache first (from previous batch scan)
                if _wsl_commands_cache is not None:
                    wsl_cmds, wsl_paths = _wsl_commands_cache
                    if self._tool_available_in_wsl(tool, wsl_cmds, wsl_paths):
                        self._availability[name] = ToolAvailability(
                            tool_name=name,
                            available=True,
                            path=self._wsl_availability_path(tool, wsl_paths),
                            platform_supported=True,
                        )
                        continue
                    else:
                        self._availability[name] = ToolAvailability(
                            tool_name=name,
                            available=False,
                            platform_supported=True,
                        )
                        continue
                # No cache yet — defer
                self._availability[name] = ToolAvailability(
                    tool_name=name,
                    available=False,
                    platform_supported=True,
                )
                continue

            self._availability[name] = ToolAvailability(
                tool_name=name,
                available=False,
                platform_supported=True,
            )

    def _ensure_wsl_scanned(self) -> None:
        """Run the batch WSL scan if it hasn't been done yet."""
        if self._wsl_scanned:
            return
        self._wsl_scanned = True

        env = detect_environment()
        if env.backend != ExecBackend.WSL2:
            return

        wsl_cmds, wsl_paths = self._batch_wsl_which()
        if not wsl_cmds:
            return

        # Update availability for tools found in WSL
        for name, tool in self._tools.items():
            if "linux" not in tool.supported_os:
                continue
            avail = self._availability.get(name)
            if avail and avail.available:
                continue  # Already found natively

            exe = tool.executable
            if self._tool_available_in_wsl(tool, wsl_cmds, wsl_paths):
                self._availability[name] = ToolAvailability(
                    tool_name=name,
                    available=True,
                    path=self._wsl_availability_path(tool, wsl_paths),
                    platform_supported=True,
                )

    def _batch_wsl_which(self) -> tuple[set[str], dict[str, str]]:
        """Check all tool executables in WSL2 with a single call.

        Results are cached at module level — the WSL scan only runs once
        per process, even if multiple ToolRegistry instances are created.

        Returns (set of available command names, dict of command→path).
        """
        global _wsl_commands_cache
        if _wsl_commands_cache is not None:
            return _wsl_commands_cache

        # Collect all unique executables and repository directories to check.
        executables = set()
        dirs = set()
        python_modules: set[tuple[str, str]] = set()
        for tool in self._tools.values():
            if "linux" in tool.supported_os and tool.run_command:
                parsed = parse_command(tool.run_command)
                executables.add(tool.executable)
                if parsed.chdir:
                    dirs.add(self._resolve_tool_chdir_wsl(parsed.chdir))
                module_name = self._python_module_name(parsed)
                if module_name:
                    python_modules.add((parsed.executable or tool.executable, module_name))

        if not executables and not dirs:
            _wsl_commands_cache = (set(), {})
            return _wsl_commands_cache

        # Build a shell command that checks all executables at once
        # Output format: "cmd:/path/to/cmd" for found tools
        checks = "; ".join(
            "if command -v {exe} >/dev/null 2>&1; "
            'then printf "%s:" {label}; command -v {exe}; fi'.format(
                exe=shlex.quote(exe),
                label=shlex.quote(exe),
            )
            for exe in sorted(executables)
        )
        dir_checks = "; ".join(
            'if [ -d {path} ]; then printf "%s:%s\\n" {label} {path}; fi'.format(
                path=shlex.quote(path),
                label=shlex.quote(f"dir={path}"),
            )
            for path in sorted(dirs)
        )
        module_checks = "; ".join(
            (
                "if {python} -c {code} >/dev/null 2>&1; "
                'then printf "%s:%s\\n" {label} {module}; fi'
            ).format(
                python=shlex.quote(python),
                code=shlex.quote(
                    f"import importlib.util, sys; sys.exit(0 if importlib.util.find_spec({module!r}) else 1)"
                ),
                label=shlex.quote(f"py={python}:{module}"),
                module=shlex.quote(module),
            )
            for python, module in sorted(python_modules)
        )
        if checks and dir_checks:
            checks = f"{checks}; {dir_checks}"
        elif dir_checks:
            checks = dir_checks
        if checks and module_checks:
            checks = f"{checks}; {module_checks}"
        elif module_checks:
            checks = module_checks
        try:
            result = subprocess.run(
                ["wsl", "bash", "-c", checks],
                capture_output=True,
                timeout=60,
            )
            commands: set[str] = set()
            paths: dict[str, str] = {}
            if result.stdout:
                text = _decode_wsl_output(result.stdout)
                for line in text.strip().split("\n"):
                    line = line.strip()
                    if ":" in line:
                        cmd, path = line.split(":", 1)
                        if cmd and path:
                            commands.add(cmd)
                            paths[cmd] = f"wsl:{path}"
            _wsl_commands_cache = (commands, paths)
            return _wsl_commands_cache
        except subprocess.TimeoutExpired:
            # WSL cold starts can be slow; do not permanently cache a transient timeout.
            return set(), {}
        except (OSError, FileNotFoundError):
            _wsl_commands_cache = (set(), {})
            return _wsl_commands_cache

    def _tool_available_in_wsl(
        self,
        tool: HackingToolDef,
        wsl_cmds: set[str],
        wsl_paths: dict[str, str],
    ) -> bool:
        """Return whether a tool can actually start in WSL.

        For repository-backed tools, a generic interpreter such as python3 or
        bash is not enough. The cloned tool directory must also exist.
        """
        parsed = parse_command(tool.run_command)
        exe = parsed.executable or tool.executable
        if exe not in wsl_cmds:
            return False
        if parsed.chdir:
            key = self._wsl_chdir_key(parsed.chdir)
            if key not in wsl_cmds:
                return False
        module_name = self._python_module_name(parsed)
        if module_name and self._wsl_python_module_key(exe, module_name) not in wsl_cmds:
            return False
        return True

    def _wsl_availability_path(self, tool: HackingToolDef, wsl_paths: dict[str, str]) -> str:
        """Build a human-readable WSL availability path for a tool."""
        parsed = parse_command(tool.run_command)
        exe = parsed.executable or tool.executable
        if parsed.chdir:
            key = self._wsl_chdir_key(parsed.chdir)
            return wsl_paths.get(key, f"wsl:{parsed.chdir}")
        return wsl_paths.get(exe, f"wsl:{exe}")

    def _wsl_chdir_key(self, chdir: str) -> str:
        return f"dir={self._resolve_tool_chdir_wsl(chdir)}"

    def _wsl_python_module_key(self, python_executable: str, module_name: str) -> str:
        return f"py={python_executable}:{module_name}"

    @staticmethod
    def _python_module_name(parsed) -> str:
        if parsed.executable not in ("python", "python3") or len(parsed.args) < 2:
            return ""
        if parsed.args[0] != "-m":
            return ""
        module_name = parsed.args[1]
        if module_name == "pip":
            return ""
        return module_name

    def _resolve_tool_chdir_wsl(self, chdir: str) -> str:
        """Resolve a run_command cd target to a WSL-visible path."""
        if chdir.startswith("/") or chdir.startswith("~"):
            return chdir
        native_path = str(get_tools_dir() / chdir)
        return to_wsl_path(native_path)

    def _tool_chdir_exists_native(self, tool: HackingToolDef) -> bool:
        parsed = parse_command(tool.run_command)
        if not parsed.chdir:
            return True
        chdir = parsed.chdir
        if chdir.startswith("~"):
            return bool(Path(chdir).expanduser().is_dir())
        if chdir.startswith("/"):
            return bool(Path(chdir).is_dir())
        return bool((get_tools_dir() / chdir).is_dir())

    def get_tool(self, name: str) -> Optional[HackingToolDef]:
        """Get a tool definition by name."""
        return self._tools.get(name)

    def get_availability(self, name: str) -> ToolAvailability:
        """Get availability status for a tool (triggers lazy WSL scan on first call)."""
        self._ensure_wsl_scanned()
        return self._availability.get(
            name,
            ToolAvailability(tool_name=name, available=False, platform_supported=False),
        )

    def is_available(self, name: str) -> bool:
        """Check if a tool is available to run (triggers lazy WSL scan on first call)."""
        self._ensure_wsl_scanned()
        avail = self._availability.get(name)
        return avail is not None and avail.available

    def list_all_tools(self) -> list[HackingToolDef]:
        """List all registered tools."""
        return list(self._tools.values())

    def list_categories(self) -> list[dict]:
        """List all categories with tool counts."""
        if self._providers:
            result = []
            for provider in self._providers:
                for cat in provider.get_categories():
                    cat_tools = provider.get_category_tools(cat["name"])
                    result.append({
                        "name": cat["name"],
                        "description": cat.get("description", ""),
                        "tool_count": len(cat_tools),
                        "available_count": sum(1 for t in cat_tools if self.is_available(t.name)),
                    })
            return result
        return [
            {
                "name": cat,
                "description": CATEGORY_DESCRIPTIONS.get(cat, ""),
                "tool_count": len(tools),
                "available_count": sum(1 for t in tools if self.is_available(t.name)),
            }
            for cat, tools in ALL_CATEGORIES.items()
        ]

    def get_category_tools(self, category: str) -> list[HackingToolDef]:
        """Get all tools in a category."""
        if self._providers:
            for provider in self._providers:
                tools = provider.get_category_tools(category)
                if tools:
                    return tools
            return []
        return ALL_CATEGORIES.get(category, [])

    def search_tools(self, query: str) -> list[HackingToolDef]:
        """Search tools by name, title, description, or tags.

        Case-insensitive search across multiple fields.
        """
        q = query.lower()
        results = []
        for tool in self._tools.values():
            if (
                q in tool.name.lower()
                or q in tool.title.lower()
                or q in tool.description.lower()
                or any(q in tag.lower() for tag in tool.tags)
            ):
                results.append(tool)
        return results

    def search_by_tag(self, tag: str) -> list[HackingToolDef]:
        """Find all tools with a specific tag."""
        tool_names = self._by_tag.get(tag.lower(), [])
        return [self._tools[n] for n in tool_names if n in self._tools]

    def get_all_tags(self) -> list[str]:
        """List all unique tags."""
        return sorted(self._by_tag.keys())

    def get_install_commands(self, name: str) -> list[str]:
        """Get install commands for a tool."""
        tool = self._tools.get(name)
        if tool and tool.install_commands:
            return tool.install_commands
        return []

    def get_tool_names(self) -> list[str]:
        """Get all tool names."""
        return list(self._tools.keys())

    def refresh(self) -> None:
        """Re-scan PATH for availability (clears WSL cache)."""
        global _wsl_commands_cache
        _wsl_commands_cache = None
        self._wsl_scanned = False
        self._scan_availability()
