"""Safety policy — tier-based allow/deny, scope validation, audit logging."""

import ipaddress
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from hacking_mcp.models import HackingToolDef, SafetyTier

logger = logging.getLogger("hacking-mcp.safety")


class SafetyPolicy:
    """Enforces safety tiers, scope boundaries, and disabled tool rules.

    Loads configuration from a YAML file and provides methods to check
    whether a tool invocation should be allowed, confirmed, or blocked.
    """

    def __init__(
        self,
        disabled_categories: Optional[list[str]] = None,
        disabled_tools: Optional[list[str]] = None,
        require_confirmation_categories: Optional[list[str]] = None,
        max_timeout_seconds: int = 300,
        max_output_bytes: int = 52_428_800,
        allowed_cidrs: Optional[list[str]] = None,
        allowed_domains: Optional[list[str]] = None,
    ):
        self.disabled_categories: set[str] = set(
            disabled_categories or []
        )
        self.disabled_tools: set[str] = set(disabled_tools or [])
        self.require_confirmation_categories: set[str] = set(
            require_confirmation_categories or []
        )
        self.max_timeout_seconds = max_timeout_seconds
        self.max_output_bytes = max_output_bytes
        self._allowed_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in allowed_cidrs or []:
            try:
                self._allowed_cidrs.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid CIDR in scope: %s", cidr)
        self._allowed_domains: list[str] = allowed_domains or []

        # Audit log: list of invocation records
        self._audit_log: list[dict] = []

    @classmethod
    def from_yaml(cls, path: Path) -> "SafetyPolicy":
        """Load safety policy from a YAML configuration file."""
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        scope = config.get("scope", {})
        return cls(
            disabled_categories=config.get("disabled_categories", []),
            disabled_tools=config.get("disabled_tools", []),
            require_confirmation_categories=config.get(
                "require_confirmation_categories", []
            ),
            max_timeout_seconds=config.get("max_execution_timeout_seconds", 300),
            max_output_bytes=config.get("max_output_bytes", 52_428_800),
            allowed_cidrs=scope.get("allowed_cidrs", []),
            allowed_domains=scope.get("allowed_domains", []),
        )

    def check_tool(self, tool: HackingToolDef) -> tuple[bool, str]:
        """Check if a tool is allowed to run. Returns (allowed, reason)."""
        # Check if category is disabled
        if tool.category in self.disabled_categories:
            return False, f"Category '{tool.category}' is disabled by safety policy."

        # Check if tool is individually disabled
        if tool.name in self.disabled_tools:
            return False, f"Tool '{tool.name}' is disabled by safety policy."

        # Check if tool is DANGEROUS tier
        if tool.safety_tier == SafetyTier.DANGEROUS:
            return (
                False,
                f"Tool '{tool.name}' is classified DANGEROUS and excluded from MCP.",
            )

        # Check if archived
        if tool.archived:
            return False, f"Tool '{tool.name}' is archived: {tool.archived_reason}"

        return True, ""

    def requires_confirmation(self, tool: HackingToolDef) -> bool:
        """Check if this tool requires explicit user confirmation."""
        return tool.category in self.require_confirmation_categories

    def validate_target(self, target: str) -> tuple[bool, str]:
        """Validate a target against defined scope.

        If scope is empty (no CIDRs, no domains), all targets are allowed.
        Otherwise the target must match at least one scope entry.
        """
        # No scope defined = allow all
        if not self._allowed_cidrs and not self._allowed_domains:
            return True, ""

        # Try to parse as IP
        try:
            addr = ipaddress.ip_address(target)
            for net in self._allowed_cidrs:
                if addr in net:
                    return True, ""
            return False, f"Target '{target}' is not in the authorized IP scope."
        except ValueError:
            pass

        # Try to match as domain
        for domain in self._allowed_domains:
            # Support wildcard: *.example.com
            if domain.startswith("*."):
                if target.endswith(domain[1:]) or target == domain[2:]:
                    return True, ""
            elif target == domain:
                return True, ""

        return False, f"Target '{target}' is not in the authorized domain scope."

    def log_invocation(
        self,
        tool_name: str,
        target: str,
        args: list[str],
        allowed: bool,
    ) -> None:
        """Record a tool invocation in the audit log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool_name,
            "target": target,
            "args": args,
            "allowed": allowed,
        }
        self._audit_log.append(entry)
        logger.info("AUDIT: %s", entry)

    def get_audit_log(self) -> list[dict]:
        """Return the audit log."""
        return list(self._audit_log)

    def get_policy_summary(self) -> dict:
        """Return a human-readable summary of the current policy."""
        return {
            "disabled_categories": sorted(self.disabled_categories),
            "disabled_tools": sorted(self.disabled_tools),
            "confirmation_categories": sorted(self.require_confirmation_categories),
            "max_timeout_seconds": self.max_timeout_seconds,
            "max_output_mb": self.max_output_bytes // (1024 * 1024),
            "scope_active": bool(self._allowed_cidrs or self._allowed_domains),
            "scope_cidr_count": len(self._allowed_cidrs),
            "scope_domain_count": len(self._allowed_domains),
        }
