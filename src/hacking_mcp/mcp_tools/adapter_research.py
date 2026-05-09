"""Research-state tracking for dedicated per-tool MCP adapters.

This module does not execute tools or fetch upstream repositories. It records
what evidence currently backs each generated adapter so gaps are explicit.
"""

from collections import Counter
from dataclasses import dataclass

from hacking_mcp.mcp_tools.tool_adapters import (
    NAMED_OVERRIDE_TOOL_NAMES,
    adapter_parameter_names,
    build_adapter_specs,
)
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy


SOURCE_STATUS_REGISTRY_DERIVED = "registry-derived"
SOURCE_STATUS_NAMED_OVERRIDE = "named-override"
SOURCE_STATUS_SOURCE_REVIEWED = "source-reviewed"

@dataclass(frozen=True)
class SourceReview:
    """Manual upstream-source review evidence for one adapter."""

    note: str
    references: tuple[str, ...]


SOURCE_REVIEWED_TOOLS: dict[str, SourceReview] = {
    "nmap": SourceReview(
        note=(
            "Reviewed against the official Nmap reference guide for target "
            "syntax and adapter flags: -p, -sS, -sT, -sU, -sn, -sV, -O, -sC, "
            "-T, --top-ports, --min-rate, --script, --script-args, --exclude."
        ),
        references=(
            "https://nmap.org/book/man.html",
            "https://nmap.org/book/man-briefoptions.html",
        ),
    ),
    "nuclei": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery Nuclei docs for "
            "template path/workflow, tags, severity, rate-limit, proxy, "
            "headless, and exclude-template flags."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/nuclei/running",
        ),
    ),
    "ffuf": SourceReview(
        note=(
            "Reviewed against the upstream ffuf README usage/help for target "
            "URL, wordlist, thread, extension, redirect, proxy, match/filter, "
            "and recursion flags."
        ),
        references=(
            "https://github.com/ffuf/ffuf",
        ),
    ),
}


@dataclass(frozen=True)
class AdapterResearchRecord:
    """Evidence summary for one generated adapter."""

    tool_name: str
    title: str
    category: str
    safety_tier: str
    endpoint: str
    execution_state: str
    source_status: str
    named_override: bool
    source_reviewed: bool
    parameter_count: int
    project_url: str
    evidence: tuple[str, ...]
    gap: str


def build_adapter_research_records(
    registry: ToolRegistry,
    safety: SafetyPolicy,
) -> list[AdapterResearchRecord]:
    """Build per-tool adapter research records from concrete registry data."""
    specs = {spec.tool_name: spec for spec in build_adapter_specs(registry, safety)}
    records: list[AdapterResearchRecord] = []

    for tool in registry.list_all_tools():
        spec = specs[tool.name]
        params = adapter_parameter_names(tool, spec)
        source_review = SOURCE_REVIEWED_TOOLS.get(tool.name)
        source_reviewed = source_review is not None
        named_override = tool.name in NAMED_OVERRIDE_TOOL_NAMES

        if source_reviewed:
            source_status = SOURCE_STATUS_SOURCE_REVIEWED
        elif named_override:
            source_status = SOURCE_STATUS_NAMED_OVERRIDE
        else:
            source_status = SOURCE_STATUS_REGISTRY_DERIVED

        evidence = [
            "registry metadata: category, tags, run_command, install_commands, project_url",
            f"generated adapter parameter schema with {len(params)} parameters",
        ]
        if named_override:
            evidence.append("tool-specific named override exists in tool_adapters.py")
        else:
            evidence.append("parameters are derived from category/tag adapter rules")
        if tool.project_url:
            evidence.append(f"registry project_url: {tool.project_url}")
        if source_review:
            evidence.append(f"source review note: {source_review.note}")
            evidence.extend(
                f"source reference: {reference}"
                for reference in source_review.references
            )

        gap = ""
        if not source_reviewed:
            gap = (
                "upstream source/docs have not been manually reviewed for exact "
                "CLI parity"
            )

        records.append(
            AdapterResearchRecord(
                tool_name=tool.name,
                title=tool.title,
                category=tool.category,
                safety_tier=tool.safety_tier.value,
                endpoint=spec.mcp_name,
                execution_state="executable" if spec.exposed else "policy/info-only",
                source_status=source_status,
                named_override=named_override,
                source_reviewed=source_reviewed,
                parameter_count=len(params),
                project_url=tool.project_url,
                evidence=tuple(evidence),
                gap=gap,
            )
        )

    return records


def summarize_adapter_research(records: list[AdapterResearchRecord]) -> dict[str, int]:
    """Return aggregate research-status counts."""
    by_status = Counter(record.source_status for record in records)
    return {
        "total": len(records),
        "registry_derived": by_status[SOURCE_STATUS_REGISTRY_DERIVED],
        "named_override": by_status[SOURCE_STATUS_NAMED_OVERRIDE],
        "source_reviewed": by_status[SOURCE_STATUS_SOURCE_REVIEWED],
        "source_review_gaps": sum(1 for record in records if not record.source_reviewed),
    }


def find_adapter_research_record(
    registry: ToolRegistry,
    safety: SafetyPolicy,
    tool_name: str,
) -> AdapterResearchRecord | None:
    """Find one adapter research record by tool name."""
    normalized = tool_name.strip()
    if not normalized:
        return None
    for record in build_adapter_research_records(registry, safety):
        if record.tool_name == normalized:
            return record
    return None
