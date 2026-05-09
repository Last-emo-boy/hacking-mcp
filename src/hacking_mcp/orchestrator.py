"""ToolOrchestrator — centralized execution coordinator.

Consolidates the pipeline that was duplicated across 7 MCP tool modules:
resolve → validate → execute → format.

Also provides ToolRequest/ToolResponse dataclasses for clean data flow.
"""

import logging
import shlex
from dataclasses import dataclass, field
from typing import Optional

from hacking_mcp.models import HackingToolDef, RunResult
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.runner import ToolRunner
from hacking_mcp.formatters import OutputFormatter, OutputFormat

logger = logging.getLogger("hacking-mcp.orchestrator")


@dataclass
class ToolRequest:
    """A request to execute a security tool.

    Captures all parameters needed for the full pipeline:
    resolve → validate → execute → format.
    """

    tool_name: str
    target: str = ""
    options: str = ""
    # Allowlist: if set, tool must be in this set
    allowed_tools: set[str] = field(default_factory=set)
    # User-facing label for allowlist errors
    category_label: str = ""
    # Whether a target is required
    target_required: bool = True
    # Whether to validate target against scope policy
    validate_scope: bool = True
    # Force safety check even for non-DANGEROUS tools (e.g. exploit module)
    force_safety_check: bool = False
    # Confirmation warning configuration
    require_confirmation: bool = False
    confirm_authorized: bool = False
    confirmation_message: str = ""
    # Output format
    output_format: OutputFormat = OutputFormat.MARKDOWN
    # Some CLIs require options before the positional target.
    options_before_target: bool = False


@dataclass
class ToolResponse:
    """Result of executing a tool through the orchestrator."""

    tool_name: str
    result: Optional[RunResult] = None
    error: str = ""
    formatted: str = ""

    def format(self, fmt: Optional[OutputFormat] = None) -> str:
        """Return the formatted output string."""
        if self.error:
            return self.error
        if self.result is not None:
            from hacking_mcp.formatters import OutputFormatter
            formatter = OutputFormatter()
            return formatter.format(self.result, fmt or OutputFormat.MARKDOWN)
        if self.formatted:
            return self.formatted
        return ""


class ToolOrchestrator:
    """Central coordinator for all tool execution.

    Consolidates the 20+ lines of duplicated validation logic from
    every MCP tool module into a single execute() pipeline:

        resolve → validate → execute → format

    Each step can short-circuit with an error ToolResponse.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        safety: SafetyPolicy,
        runner: ToolRunner,
        formatter: Optional[OutputFormatter] = None,
        asset_manager: "AssetManager | None" = None,
    ):
        self.registry = registry
        self.safety = safety
        self.runner = runner
        self.formatter = formatter or OutputFormatter()
        self.asset_mgr = asset_manager

    async def execute(self, request: ToolRequest, ctx=None) -> ToolResponse:
        """Execute a tool end-to-end through the full pipeline.

        Args:
            request: ToolRequest with tool_name, target, options, allowlist, etc.
            ctx: Optional MCP Context for progress reporting

        Returns:
            ToolResponse with formatted output
        """
        # ── Step 1: Resolve ──────────────────────────────────────────
        tool = self.registry.get_tool(request.tool_name)
        if not tool:
            self._audit_request(request, allowed=False, reason="Unknown tool", action="resolve")
            return ToolResponse(
                tool_name=request.tool_name,
                error=self._unknown_tool_message(request.tool_name),
            )

        if request.allowed_tools and request.tool_name not in request.allowed_tools:
            label = request.category_label or "this category"
            self._audit_request(
                request,
                allowed=False,
                reason=f"Tool is not in the {label} allowlist",
                action="allowlist_reject",
            )
            return ToolResponse(
                tool_name=request.tool_name,
                error=f"'{request.tool_name}' is not a {label} tool. "
                "Use security_list_tools to find available tools.",
            )

        # ── Step 2: Safety gate ──────────────────────────────────────
        allowed, reason = self.safety.check_tool(tool)
        if not allowed:
            self._audit_request(request, allowed=False, reason=reason, action="policy_block")
            return ToolResponse(
                tool_name=request.tool_name,
                error=f"⛔ **BLOCKED:** {reason}",
            )

        # ── Step 3: Target validation ────────────────────────────────
        if request.target_required and not request.target:
            self._audit_request(
                request,
                allowed=False,
                reason="Target is required",
                action="missing_target",
            )
            return ToolResponse(
                tool_name=request.tool_name,
                error=f"'{request.tool_name}' requires a target.",
            )

        # ── Step 4: Confirmation gate ────────────────────────────────
        needs_confirmation = (
            request.require_confirmation
            or request.force_safety_check
            or self.safety.requires_confirmation(tool)
        )
        if needs_confirmation and not request.confirm_authorized:
            msg = request.confirmation_message or (
                f"Tool '{request.tool_name}' ({tool.category}) requires explicit "
                "authorization confirmation."
            )
            self._audit_request(request, allowed=False, reason=msg, action="confirmation_required")
            return ToolResponse(
                tool_name=request.tool_name,
                error=(
                    f"⚠️ **CONFIRMATION REQUIRED:** {msg}\n\n"
                    "Re-run with `confirm_authorized=True` only if you own the target "
                    "or have explicit written authorization to test it."
                ),
            )

        # ── Step 5: Availability ─────────────────────────────────────
        if not self.registry.is_available(request.tool_name):
            self._audit_request(
                request,
                allowed=False,
                reason="Tool is not installed",
                action="not_installed",
            )
            return ToolResponse(
                tool_name=request.tool_name,
                error=self._not_installed_message(request.tool_name),
            )

        if request.validate_scope and request.target:
            scope_ok, scope_reason = self.safety.validate_target(request.target)
            if not scope_ok:
                self._audit_request(
                    request,
                    allowed=False,
                    reason=scope_reason,
                    action="scope_reject",
                )
                return ToolResponse(
                    tool_name=request.tool_name,
                    error=f"⛔ Target rejected by scope policy: {scope_reason}",
                )

        # ── Step 6: Confirmation warning ─────────────────────────────
        if needs_confirmation and ctx:
            tool_obj = tool
            msg = request.confirmation_message or (
                f"Tool '{request.tool_name}' ({tool_obj.category}) requires confirmation. "
                "Ensure you have authorization."
            )
            await ctx.warning(msg)

        # ── Step 7: Progress notification ────────────────────────────
        if ctx:
            target_str = f" against {request.target}" if request.target else ""
            await ctx.info(f"Running {request.tool_name}{target_str}...")

        # ── Step 8: Execute ──────────────────────────────────────────
        args = []
        if request.target:
            args.append(request.target)
        if request.options:
            try:
                args.extend(shlex.split(request.options))
            except ValueError as e:
                self._audit_request(
                    request,
                    allowed=False,
                    reason=f"Invalid options syntax: {e}",
                    action="invalid_options",
                )
                return ToolResponse(
                    tool_name=request.tool_name,
                    error=f"Invalid options syntax: {e}",
                )

        result = await self.runner.run(
            request.tool_name,
            args,
            confirm_authorized=request.confirm_authorized,
            options_before_target=request.options_before_target,
        )

        # ── Step 9: Save to asset manager ────────────────────────────
        if self.asset_mgr and request.target and not result.was_blocked:
            try:
                scan_id = self.asset_mgr.save_result(
                    target=request.target,
                    tool_name=request.tool_name,
                    options=request.options,
                    result=result,
                )
                result.output_file = str(
                    self.asset_mgr._asset_dir(request.target) / f"{scan_id}.json"
                )
            except Exception as e:
                logger.warning("Failed to save asset result for %s: %s", request.tool_name, e)

        # ── Step 10: Format ──────────────────────────────────────────
        formatted = self.formatter.format(result, request.output_format)

        return ToolResponse(
            tool_name=request.tool_name,
            result=result,
            formatted=formatted,
        )

    def _unknown_tool_message(self, tool_name: str) -> str:
        """Build 'unknown tool' message with suggestions."""
        similar = [t.name for t in self.registry.search_tools(tool_name)[:5]]
        msg = f"Unknown tool: '{tool_name}'."
        if similar:
            msg += f"\nDid you mean: {', '.join(similar)}?"
        return msg

    def _not_installed_message(self, tool_name: str) -> str:
        """Build 'not installed' message with install instructions."""
        install_cmds = self.registry.get_install_commands(tool_name)
        msg = f"Tool '{tool_name}' is not installed.\n\n"
        if install_cmds:
            msg += "**Install commands (run manually):**\n"
            for cmd in install_cmds:
                msg += f"```bash\n{cmd}\n```\n"
        return msg

    def _audit_request(
        self,
        request: ToolRequest,
        allowed: bool,
        reason: str,
        action: str,
    ) -> None:
        """Audit decisions that short-circuit before ToolRunner.run()."""
        self.safety.log_invocation(
            tool_name=request.tool_name,
            target=request.target,
            args=self._audit_args(request),
            allowed=allowed,
            reason=reason,
            action=action,
        )

    @staticmethod
    def _audit_args(request: ToolRequest) -> list[str]:
        args = []
        if request.target:
            args.append(request.target)
        if request.options:
            try:
                args.extend(shlex.split(request.options))
            except ValueError:
                args.append(request.options)
        return args

    def dry_run(self, tool_name: str, target: str = "", options: str = "") -> str:
        """Preview the command that would be executed."""
        args = []
        if target:
            args.append(target)
        if options:
            try:
                args.extend(shlex.split(options))
            except ValueError as e:
                return f"# Invalid options syntax: {e}"
        return self.runner.dry_run(tool_name, args)
