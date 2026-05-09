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
    verified_parameters: tuple[str, ...]


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
        verified_parameters=(
            "ports",
            "scan_type",
            "service_version",
            "os_detection",
            "default_scripts",
            "timing",
            "top_ports",
            "rate",
            "scripts",
            "script_args",
            "exclude_hosts",
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
        verified_parameters=(
            "severity",
            "tags",
            "template_path",
            "rate_limit",
            "proxy",
            "workflows",
            "exclude_templates",
            "headless",
            "interactsh",
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
        verified_parameters=(
            "wordlist",
            "threads",
            "extensions",
            "match_codes",
            "recursive",
            "follow_redirects",
            "proxy",
            "fuzz_keyword",
            "host_header",
            "recursion_depth",
            "filter_codes",
            "filter_size",
            "filter_words",
            "add_slash",
        ),
    ),
    "httpx": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery httpx usage docs for "
            "single URL/list input, probes, match/filter codes, rate/thread "
            "controls, proxy/header/method, timeout, output, and JSON flags."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/httpx/usage",
        ),
        verified_parameters=(
            "input_file",
            "status_code",
            "title",
            "tech_detect",
            "content_length",
            "match_codes",
            "filter_codes",
            "threads",
            "rate_limit",
            "ports",
            "path",
            "follow_redirects",
            "proxy",
            "headers",
            "method",
            "timeout",
            "output_file",
            "json_output",
            "silent",
        ),
    ),
    "subfinder": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery Subfinder usage docs "
            "for domain list input, source selection/filtering, recursive and "
            "active modes, resolver/rate controls, output formats, config, "
            "proxy, and debug/output controls."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/subfinder/usage",
        ),
        verified_parameters=(
            "input_file",
            "sources",
            "exclude_sources",
            "all_sources",
            "recursive",
            "active",
            "match",
            "filter",
            "resolvers",
            "resolver_file",
            "rate_limit",
            "rate_limits",
            "threads",
            "timeout",
            "max_time",
            "output_file",
            "json_output",
            "output_dir",
            "collect_sources",
            "include_ip",
            "exclude_ip",
            "config_file",
            "provider_config",
            "proxy",
            "silent",
            "verbose",
        ),
    ),
    "gitleaks": SourceReview(
        note=(
            "Reviewed against the upstream Gitleaks README usage/options for "
            "redaction, git log options, config/baseline/ignore files, rule "
            "selection, limits, report output, logging, banner/color, and "
            "verbose flags."
        ),
        references=(
            "https://github.com/gitleaks/gitleaks",
        ),
        verified_parameters=(
            "redact",
            "log_opts",
            "config_path",
            "baseline_path",
            "ignore_path",
            "enable_rule",
            "exit_code",
            "follow_symlinks",
            "ignore_allow",
            "max_decode_depth",
            "max_archive_depth",
            "max_target_mb",
            "report_format",
            "report_path",
            "report_template",
            "log_level",
            "no_banner",
            "no_color",
            "verbose",
        ),
    ),
    "trufflehog": SourceReview(
        note=(
            "Reviewed against the upstream TruffleHog README for filesystem "
            "scans and global flags covering JSON/GitHub output, concurrency, "
            "verification controls, result filtering, entropy/config/logging, "
            "and fail-on-result behavior."
        ),
        references=(
            "https://github.com/trufflesecurity/trufflehog",
        ),
        verified_parameters=(
            "json_output",
            "github_actions",
            "concurrency",
            "no_verification",
            "results",
            "no_color",
            "allow_verification_overlap",
            "filter_unverified",
            "filter_entropy",
            "config_path",
            "print_avg_detector_time",
            "fail",
            "log_level",
        ),
    ),
}

BASE_ADAPTER_PARAMETERS = {"target", "options", "confirm_authorized"}


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
    verified_parameters: tuple[str, ...]
    unverified_parameters: tuple[str, ...]
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
        reviewable_params = sorted(set(params) - BASE_ADAPTER_PARAMETERS)
        source_review = SOURCE_REVIEWED_TOOLS.get(tool.name)
        source_reviewed = source_review is not None
        named_override = tool.name in NAMED_OVERRIDE_TOOL_NAMES
        verified_params = sorted(source_review.verified_parameters) if source_review else []
        unverified_params = (
            sorted(set(reviewable_params) - set(verified_params))
            if source_review
            else reviewable_params
        )

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
            evidence.append(
                "source-verified parameters: " + ", ".join(verified_params)
            )
            evidence.extend(
                f"source reference: {reference}"
                for reference in source_review.references
            )

        gap = ""
        if source_reviewed and unverified_params:
            gap = (
                "source review does not yet verify exposed parameters: "
                + ", ".join(unverified_params)
            )
        elif not source_reviewed:
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
                verified_parameters=tuple(verified_params),
                unverified_parameters=tuple(unverified_params),
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
        "fully_source_verified": sum(
            1 for record in records
            if record.source_reviewed and not record.unverified_parameters
        ),
        "source_review_gaps": sum(1 for record in records if record.gap),
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
