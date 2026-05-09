"""FastMCP server — the main MCP server for hacking-mcp.

Instantiates the ToolRegistry, SafetyPolicy, ToolRunner, ToolOrchestrator,
InstallManager, TaskManager, and AssetManager, then registers all MCP tool functions.
"""

import logging
import shutil
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.runner import ToolRunner
from hacking_mcp.orchestrator import ToolOrchestrator
from hacking_mcp.formatters import OutputFormatter
from hacking_mcp.install import InstallManager
from hacking_mcp.tasks import TaskManager
from hacking_mcp.assets import AssetManager
from hacking_mcp.environment import ensure_data_dirs

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hacking-mcp")

# Configuration paths — try repo dir (dev mode), then ~/.hacking-mcp/ (installed)
_REPO_CONFIG = Path(__file__).parent.parent.parent / "config" / "safety_policy.yaml"
_USER_CONFIG = Path.home() / ".hacking-mcp" / "safety_policy.yaml"

# Ensure data directories exist
ensure_data_dirs()

def _resolve_safety_config() -> SafetyPolicy:
    """Load safety policy, preferring repo config in dev, user config otherwise."""
    if _REPO_CONFIG.exists():
        return SafetyPolicy.from_yaml(_REPO_CONFIG)
    if _USER_CONFIG.exists():
        return SafetyPolicy.from_yaml(_USER_CONFIG)
    # Create default config in user directory
    _USER_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    if _REPO_CONFIG.exists():
        # Copy from repo
        shutil.copy(_REPO_CONFIG, _USER_CONFIG)
    else:
        # Write built-in default
        _USER_CONFIG.write_text("""# Safety policy for hacking-mcp
# Controls which tools/categories are exposed via MCP and under what conditions

# Categories permanently excluded from MCP
disabled_categories:
  - "DDOS Attack"
  - "Remote Administration (RAT)"
  - "Payload Creation"
  - "Phishing Attack"
  - "Wireless Attack"
  - "Anonymously Hiding"

# Individual tools permanently excluded
disabled_tools:
  - "Chrome Keylogger"
  - "Vegile"
  - "Spycam"
  - "SayCheese"

# Categories that require explicit user confirmation per invocation
require_confirmation_categories:
  - "SQL Injection"
  - "Exploit Framework"
  - "Post Exploitation"
  - "XSS Attack"

# Execution limits
max_execution_timeout_seconds: 300
max_output_bytes: 52428800  # 50MB

# Target scope (empty = allow all)
scope:
  allowed_cidrs: []
  allowed_domains: []

# Proxy for tool downloads (git clone, pip install, curl, etc.)
# Only used during installation — security tool execution never uses proxy.
# Uncomment and set your proxy if downloads fail due to network restrictions:
# proxy:
#   http: "http://127.0.0.1:8080"
#   https: "http://127.0.0.1:8080"
#   no_proxy: "localhost,127.0.0.1,.local"
""")
    return SafetyPolicy.from_yaml(_USER_CONFIG)

# Initialize shared state
registry = ToolRegistry()
safety = _resolve_safety_config()
runner = ToolRunner(registry, safety)
formatter = OutputFormatter()
asset_mgr = AssetManager()
orchestrator = ToolOrchestrator(registry, safety, runner, formatter, asset_manager=asset_mgr)
install_mgr = InstallManager(runner, registry, safety,
                            proxy_env=safety.get_proxy_env(),
                            mirrors=safety.get_mirrors_config())
task_mgr = TaskManager(orchestrator, asset_mgr=asset_mgr)

# Create the MCP server
mcp = FastMCP(
    name="hacking-mcp",
    instructions="Security tool aggregator MCP server — exposing ~100 security CLI tools "
    "for reconnaissance, scanning, forensics, cloud auditing, and more. "
    "For authorized security testing only.",
    dependencies=["mcp>=1.0"],
)


def create_server():
    """Register all MCP tools and return the configured server."""
    from hacking_mcp.mcp_tools.discovery import register as register_discovery
    from hacking_mcp.mcp_tools.recon import register as register_recon
    from hacking_mcp.mcp_tools.scanner import register as register_scanner
    from hacking_mcp.mcp_tools.web import register as register_web
    from hacking_mcp.mcp_tools.forensics_tools import register as register_forensics
    from hacking_mcp.mcp_tools.cloud_tools import register as register_cloud
    from hacking_mcp.mcp_tools.ad_tools import register as register_ad
    from hacking_mcp.mcp_tools.exploit import register as register_exploit
    from hacking_mcp.mcp_tools.install_tools import register as register_install
    from hacking_mcp.mcp_tools.task_tools import register as register_task
    from hacking_mcp.mcp_tools.asset_tools import register as register_asset

    # Discovery tools — need registry + safety directly
    register_discovery(mcp, registry, safety)
    # Execution tools — all use the orchestrator
    register_recon(mcp, orchestrator)
    register_scanner(mcp, orchestrator)
    register_web(mcp, orchestrator)
    register_forensics(mcp, orchestrator)
    register_cloud(mcp, orchestrator)
    register_ad(mcp, orchestrator)
    register_exploit(mcp, orchestrator)
    # Install management
    register_install(mcp, install_mgr, registry)
    # Background tasks
    register_task(mcp, task_mgr)
    # Asset management
    register_asset(mcp, asset_mgr)

    logger.info(
        "hacking-mcp initialized: %d tools across %d categories. "
        "Safety policy: %d categories disabled, %d require confirmation.",
        len(registry.get_tool_names()),
        20,  # Static — avoid triggering lazy WSL scan
        len(safety.disabled_categories),
        len(safety.require_confirmation_categories),
    )

    return mcp
