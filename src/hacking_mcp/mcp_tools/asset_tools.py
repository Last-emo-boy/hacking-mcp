"""Asset management MCP tools — per-target scan output and comparison."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.assets import AssetManager


def register(mcp: FastMCP, asset_mgr: AssetManager):
    @mcp.tool(
        name="security_asset_list",
        description="List all tracked assets (targets) with their scan summaries. "
        "Each target that has been scanned is automatically tracked. "
        "Shows target name, scan count, first/last scan times.",
    )
    async def security_asset_list(ctx: Context = None) -> str:
        """List all scanned assets."""
        assets = asset_mgr.list_assets()
        if not assets:
            return (
                "# Assets\n\n"
                "No assets tracked yet. "
                "Run a scan against a target to automatically track it."
            )

        lines = [f"# Assets ({len(assets)})\n"]
        for a in sorted(assets, key=lambda x: x.last_scanned, reverse=True):
            lines.append(f"## {a.target}")
            lines.append(f"- **Scans:** {a.scan_count}")
            if a.first_seen:
                lines.append(f"- **First seen:** {a.first_seen}")
            if a.last_scanned:
                lines.append(f"- **Last scanned:** {a.last_scanned}")
            if a.scans:
                # Show last 3 scans
                recent = sorted(a.scans, key=lambda s: s["timestamp"], reverse=True)[:3]
                for s in recent:
                    rc = s.get("return_code", "")
                    status = f" (exit {rc})" if rc else ""
                    lines.append(f"  - `{s['scan_id']}` — {s['tool_name']}{status}")
            lines.append("")

        return "\n".join(lines)

    @mcp.tool(
        name="security_asset_history",
        description="Get scan history for a specific asset (target). "
        "Shows all scans run against this target, with timestamps and exit codes. "
        "Optionally filter by tool name. "
        "Use to see what's been done against a target over time.",
    )
    async def security_asset_history(
        target: str,
        tool_name: str = "",
        limit: int = 20,
        ctx: Context = None,
    ) -> str:
        """Get scan history for an asset.

        Args:
            target: Target IP, domain, or URL
            tool_name: Optional filter by tool name (e.g., 'nmap')
            limit: Maximum number of scans to show (default 20)
        """
        scans = asset_mgr.get_history(target, tool_name=tool_name, limit=limit)
        if not scans:
            filter_msg = f" for tool '{tool_name}'" if tool_name else ""
            return f"No scans found for '{target}'{filter_msg}."

        lines = [
            f"# Scan History: {target}",
            f"**{len(scans)} scans**" + (f" (filtered by '{tool_name}')" if tool_name else ""),
            "",
        ]
        for s in scans:
            rc = s.get("return_code", "")
            status = "✅" if rc == 0 else f"❌ (exit {rc})"
            lines.append(
                f"- {status} **`{s['scan_id']}`** — {s['tool_name']} "
                f"({s['timestamp']})"
            )

        return "\n".join(lines)

    @mcp.tool(
        name="security_asset_scan",
        description="Get the full result (stdout, stderr, exit code, timing) "
        "of a specific scan for an asset. "
        "Use the scan_id from security_asset_history. "
        "Returns the complete tool output.",
    )
    async def security_asset_scan(
        target: str,
        scan_id: str,
        ctx: Context = None,
    ) -> str:
        """Get a full scan result.

        Args:
            target: Target IP, domain, or URL
            scan_id: Scan ID from security_asset_history (e.g., '2026-05-05T103000Z_nmap')
        """
        scan = asset_mgr.get_scan(target, scan_id)
        if not scan:
            return f"Scan '{scan_id}' not found for target '{target}'."

        r = scan["result"]
        lines = [
            f"# {scan_id}",
            f"**Target:** {scan['target']}",
            f"**Tool:** {scan['tool_name']}",
            f"**Timestamp:** {scan['timestamp']}",
        ]
        if scan.get("options"):
            lines.append(f"**Options:** `{scan['options']}`")
        lines.extend([
            f"**Command:** `{scan['command']}`",
            f"**Exit code:** {r['return_code']}",
            f"**Duration:** {r['duration_ms']}ms",
        ])
        if r.get("timed_out"):
            lines.append("⚠️ **Timed out**")
        if r.get("was_blocked"):
            lines.append(f"⛔ **Blocked:** {r.get('block_reason', '')}")

        stdout = r.get("stdout", "")
        if stdout:
            if len(stdout) > 15000:
                stdout = stdout[:15000] + "\n... (output truncated)"
            lines.append(f"\n### Output\n```\n{stdout}\n```")

        stderr = r.get("stderr", "")
        if stderr:
            if len(stderr) > 3000:
                stderr = stderr[:3000] + "\n... (truncated)"
            lines.append(f"\n### Stderr\n```\n{stderr}\n```")

        return "\n".join(lines)

    @mcp.tool(
        name="security_asset_compare",
        description="Compare two scan results for the same target. "
        "Shows a unified diff of stdout between the two scans — useful for "
        "seeing what changed (new open ports, different responses, etc.). "
        "Use security_asset_history to find scan_ids to compare.",
    )
    async def security_asset_compare(
        target: str,
        scan_id_1: str,
        scan_id_2: str,
        ctx: Context = None,
    ) -> str:
        """Compare two scan results.

        Args:
            target: Target IP, domain, or URL
            scan_id_1: First scan ID
            scan_id_2: Second scan ID
        """
        comparison = asset_mgr.compare_scans(target, scan_id_1, scan_id_2)
        if not comparison:
            return (
                f"Could not compare scans for '{target}'.\n"
                f"Ensure both scan IDs exist: `{scan_id_1}`, `{scan_id_2}`"
            )

        s1 = comparison["scan_1"]
        s2 = comparison["scan_2"]
        d = comparison["diff"]

        lines = [
            f"# Scan Comparison: {target}",
            "",
            "## Scan 1 (Before)",
            f"- **ID:** `{s1['scan_id']}`",
            f"- **Timestamp:** {s1['timestamp']}",
            f"- **Exit code:** {s1['return_code']}",
            f"- **Duration:** {s1['duration_ms']}ms",
            "",
            "## Scan 2 (After)",
            f"- **ID:** `{s2['scan_id']}`",
            f"- **Timestamp:** {s2['timestamp']}",
            f"- **Exit code:** {s2['return_code']}",
            f"- **Duration:** {s2['duration_ms']}ms",
            "",
            "## Changes",
            f"- Exit code: {d['return_code']['before']} → {d['return_code']['after']}",
            f"- Duration delta: {d['duration_ms_delta']}ms",
            f"- Lines added: {d['lines_added']}",
            f"- Lines removed: {d['lines_removed']}",
        ]

        diff_content = d.get("unified_diff", [])
        if diff_content:
            lines.append("\n### Diff\n```diff")
            for line in diff_content[:200]:  # Limit diff lines
                lines.append(line)
            if len(diff_content) > 200:
                lines.append(f"... ({len(diff_content) - 200} more lines)")
            lines.append("```")

        return "\n".join(lines)
