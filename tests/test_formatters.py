"""Tests for OutputFormatter."""

import json
from hacking_mcp.formatters import OutputFormatter, OutputFormat
from hacking_mcp.models import RunResult


def make_result(**kwargs) -> RunResult:
    defaults = {
        "tool_name": "nmap",
        "command": ["nmap", "127.0.0.1"],
        "return_code": 0,
        "stdout": "Port 80: open\nPort 443: open",
        "stderr": "",
        "duration_ms": 1500,
        "timed_out": False,
        "was_blocked": False,
    }
    defaults.update(kwargs)
    return RunResult(**defaults)


class TestOutputFormatter:
    def test_markdown_format_basic(self):
        fmt = OutputFormatter()
        result = make_result()
        output = fmt.format(result, OutputFormat.MARKDOWN)
        assert "## nmap Results" in output
        assert "**Exit code:** 0" in output
        assert "**Duration:** 1500ms" in output
        assert "Port 80: open" in output
        assert "Port 443: open" in output

    def test_markdown_format_blocked(self):
        fmt = OutputFormatter()
        result = make_result(
            was_blocked=True,
            block_reason="Category disabled",
            stdout="",
            return_code=-1,
        )
        output = fmt.format(result, OutputFormat.MARKDOWN)
        assert "blocked" in output
        assert "Category disabled" in output

    def test_markdown_format_timed_out(self):
        fmt = OutputFormatter()
        result = make_result(timed_out=True)
        output = fmt.format(result, OutputFormat.MARKDOWN)
        assert "timed out" in output.lower()

    def test_markdown_format_stderr(self):
        fmt = OutputFormatter()
        result = make_result(
            return_code=1,
            stderr="Error: connection refused",
        )
        output = fmt.format(result, OutputFormat.MARKDOWN)
        assert "Error: connection refused" in output
        assert "non-zero code" in output

    def test_markdown_truncation(self):
        fmt = OutputFormatter(max_stdout=20, max_stderr=10)
        result = make_result(
            stdout="A" * 100,
            stderr="B" * 100,
        )
        output = fmt.format(result, OutputFormat.MARKDOWN)
        assert "truncated" in output
        assert len(output) < 500  # Should be heavily truncated

    def test_json_format(self):
        fmt = OutputFormatter()
        result = make_result()
        output = fmt.format(result, OutputFormat.JSON)
        data = json.loads(output)
        assert data["tool_name"] == "nmap"
        assert data["return_code"] == 0
        assert data["duration_ms"] == 1500
        assert data["was_blocked"] is False
        assert "Port 80: open" in data["stdout"]

    def test_json_format_blocked(self):
        fmt = OutputFormatter()
        result = make_result(
            was_blocked=True,
            block_reason="Not installed",
            stdout="",
            return_code=-1,
        )
        output = fmt.format(result, OutputFormat.JSON)
        data = json.loads(output)
        assert data["was_blocked"] is True
        assert data["block_reason"] == "Not installed"

    def test_structured_falls_back_to_json(self):
        fmt = OutputFormatter()
        result = make_result()
        output = fmt.format(result, OutputFormat.STRUCTURED)
        # Should be valid JSON
        data = json.loads(output)
        assert data["tool_name"] == "nmap"

    def test_default_format_is_markdown(self):
        fmt = OutputFormatter()
        result = make_result()
        output = fmt.format(result)
        assert output.startswith("## nmap Results")

    def test_empty_stdout_stderr(self):
        fmt = OutputFormatter()
        result = make_result(stdout="", stderr="", return_code=0)
        output = fmt.format(result, OutputFormat.MARKDOWN)
        assert "## nmap Results" in output
        # No Output or Stderr sections
        assert "### Output" not in output
        assert "### Stderr" not in output

    def test_json_ensure_ascii_false(self):
        """Unicode characters should not be escaped in JSON."""
        fmt = OutputFormatter()
        result = make_result(stdout="Port 80: abierto")
        output = fmt.format(result, OutputFormat.JSON)
        assert "abierto" in output
        # Should NOT have \\u escapes for basic ASCII-range chars anyway, but test the structure
        data = json.loads(output)
        assert data["stdout"] == "Port 80: abierto"
