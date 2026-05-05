"""FastMCP server — the main MCP server for hacking-mcp.

Instantiates the ToolRegistry, SafetyPolicy, ToolRunner, ToolOrchestrator,
InstallManager, TaskManager, and AssetManager, then registers all MCP tool functions.
"""

import logging
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

# Configuration paths
CONFIG_DIR = Path(__file__).parent.parent.parent / "config"
SAFETY_POLICY_PATH = CONFIG_DIR / "safety_policy.yaml"

# Ensure data directories exist
ensure_data_dirs()

# Initialize shared state
registry = ToolRegistry()
safety = SafetyPolicy.from_yaml(SAFETY_POLICY_PATH)
runner = ToolRunner(registry, safety)
formatter = OutputFormatter()
asset_mgr = AssetManager()
orchestrator = ToolOrchestrator(registry, safety, runner, formatter, asset_manager=asset_mgr)
install_mgr = InstallManager(runner, registry)
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
        len(registry.list_categories()),
        len(safety.disabled_categories),
        len(safety.require_confirmation_categories),
    )

    return mcp
