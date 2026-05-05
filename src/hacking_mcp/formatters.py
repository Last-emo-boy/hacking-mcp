"""Output formatters — convert RunResult into display-ready strings.

Supports Markdown (rich CLI display), JSON (machine-readable), and
Structured (future: per-tool output parsers for nmap XML, etc.).
"""

import json
from enum import Enum

from hacking_mcp.models import RunResult


class OutputFormat(Enum):
    MARKDOWN = "markdown"
    JSON = "json"
    STRUCTURED = "structured"


class OutputFormatter:
    """Format RunResult into the requested output format."""

    def __init__(self, max_stdout: int = 15000, max_stderr: int = 3000):
        self.max_stdout = max_stdout
        self.max_stderr = max_stderr

    def format(self, result: RunResult, fmt: OutputFormat = OutputFormat.MARKDOWN) -> str:
        if fmt == OutputFormat.JSON:
            return self._format_json(result)
        if fmt == OutputFormat.STRUCTURED:
            return self._format_structured(result)
        return self._format_markdown(result)

    def _format_markdown(self, result: RunResult) -> str:
        """Format as rich Markdown for display."""
        if result.was_blocked:
            return f"⛔ **{result.tool_name}** was blocked: {result.block_reason}"

        lines = [
            f"## {result.tool_name} Results",
            f"**Exit code:** {result.return_code} | **Duration:** {result.duration_ms}ms",
        ]

        if result.timed_out:
            lines.append("⚠️ **Command timed out.**")

        if result.stdout:
            stdout = result.stdout
            if len(stdout) > self.max_stdout:
                stdout = stdout[:self.max_stdout] + "\n... (output truncated)"
            lines.append(f"\n### Output\n```\n{stdout}\n```")

        if result.stderr:
            stderr = result.stderr
            if len(stderr) > self.max_stderr:
                stderr = stderr[:self.max_stderr] + "\n... (truncated)"
            lines.append(f"\n### Stderr\n```\n{stderr}\n```")

        if result.return_code != 0:
            lines.append(f"\n⚠️ Command exited with non-zero code: {result.return_code}")

        return "\n".join(lines)

    def _format_json(self, result: RunResult) -> str:
        """Format as JSON for machine consumption."""
        return json.dumps(
            {
                "tool_name": result.tool_name,
                "command": " ".join(result.command),
                "return_code": result.return_code,
                "duration_ms": result.duration_ms,
                "timed_out": result.timed_out,
                "was_blocked": result.was_blocked,
                "block_reason": result.block_reason if result.was_blocked else None,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            indent=2,
            ensure_ascii=False,
        )

    def _format_structured(self, result: RunResult) -> str:
        """Format as structured data (future: per-tool parsers).

        Currently falls back to JSON with a header indicating structured mode.
        """
        return self._format_json(result)
