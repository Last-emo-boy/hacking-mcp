"""Safety policy — tier-based allow/deny, scope validation, audit logging."""

import ipaddress
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

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
        _proxy_config: Optional[dict] = None,
        _mirrors_config: Optional[dict] = None,
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

        # Proxy config (only used for tool installation downloads)
        self._proxy_config: dict = _proxy_config or {}
        # Mirror config (pip, go, gem, apt sources)
        self._mirrors_config: dict = _mirrors_config or {}

        # Audit log: list of invocation records
        self._audit_log: list[dict] = []

    @classmethod
    def from_yaml(cls, path: Path) -> "SafetyPolicy":
        """Load safety policy from a YAML configuration file."""
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        scope = config.get("scope", {})
        proxy = config.get("proxy", {})
        mirrors = config.get("mirrors", {})
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
            _proxy_config=proxy,
            _mirrors_config=mirrors,
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
        return (
            tool.safety_tier == SafetyTier.CAUTION
            or tool.category in self.require_confirmation_categories
        )

    def validate_target(self, target: str) -> tuple[bool, str]:
        """Validate a target against defined scope.

        If scope is empty (no CIDRs, no domains), all targets are allowed.
        Otherwise the target must match at least one scope entry.
        """
        # No scope defined = allow all
        if not self._allowed_cidrs and not self._allowed_domains:
            return True, ""

        candidates = self._scope_candidates(target)
        if not candidates:
            return False, f"Target '{target}' could not be parsed for scope validation."

        for candidate in candidates:
            ok, is_ip_like = self._validate_ip_or_network(candidate)
            if ok:
                return True, ""
            if is_ip_like:
                continue

            if self._domain_allowed(candidate):
                return True, ""

        return False, f"Target '{target}' is not in the authorized scope."

    def _validate_ip_or_network(self, value: str) -> tuple[bool, bool]:
        """Return (allowed, was_ip_like) for an IP address or CIDR."""
        try:
            addr = ipaddress.ip_address(value)
            return any(addr in net for net in self._allowed_cidrs), True
        except ValueError:
            pass

        try:
            target_net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False, False

        return any(target_net.subnet_of(net) for net in self._allowed_cidrs), True

    def _domain_allowed(self, value: str) -> bool:
        target = value.rstrip(".").lower()
        for domain in self._allowed_domains:
            allowed = domain.rstrip(".").lower()
            if allowed.startswith("*."):
                suffix = allowed[1:]
                if target.endswith(suffix) or target == allowed[2:]:
                    return True
            elif target == allowed:
                return True
        return False

    @staticmethod
    def _scope_candidates(target: str) -> list[str]:
        """Extract scope-checkable host/IP/CIDR candidates from a user target."""
        raw = target.strip()
        if not raw:
            return []

        candidates: list[str] = []

        # Preserve bare IP/CIDR targets before URL parsing turns CIDR into a path.
        candidates.append(raw)

        try:
            parsed = urlsplit(raw if "://" in raw else f"//{raw}")
            if parsed.hostname:
                candidates.append(parsed.hostname)
        except ValueError:
            pass

        # Deduplicate while preserving order.
        seen: set[str] = set()
        result: list[str] = []
        for candidate in candidates:
            normalized = candidate.strip().strip("[]")
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            result.append(normalized)
        return result

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

    def get_proxy_config(self) -> dict:
        """Return proxy configuration for install downloads."""
        return dict(self._proxy_config)

    def get_proxy_env(self) -> dict[str, str]:
        """Return proxy settings as environment variables for subprocess.

        Only HTTP_PROXY/HTTPS_PROXY/NO_PROXY are passed.
        Returns empty dict if no proxy configured.
        """
        env: dict[str, str] = {}
        p = self._proxy_config
        if p.get("http"):
            env["HTTP_PROXY"] = p["http"]
            env["http_proxy"] = p["http"]
        if p.get("https"):
            env["HTTPS_PROXY"] = p["https"]
            env["https_proxy"] = p["https"]
        if p.get("no_proxy"):
            env["NO_PROXY"] = p["no_proxy"]
            env["no_proxy"] = p["no_proxy"]
        return env

    def get_mirrors_config(self) -> dict:
        """Return mirror configuration for install sources."""
        return dict(self._mirrors_config)

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
