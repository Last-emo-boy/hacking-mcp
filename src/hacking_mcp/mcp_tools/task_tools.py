"""Background task MCP tools — start, monitor, cancel background scans."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.tasks import TaskManager


def register(mcp: FastMCP, task_mgr: TaskManager):
    @mcp.tool(
        name="security_task_start",
        description="Start a security tool as a background task. "
        "Returns a task_id immediately — the tool runs in the background. "
        "Use security_task_status(task_id) to check progress and get results. "
        "Use security_list_tasks to see all tasks. "
        "Perfect for long-running scans that shouldn't block.",
    )
    async def security_task_start(
        tool_name: str,
        target: str,
        options: str = "",
        category: str = "",
        confirm_authorized: bool = False,
        ctx: Context = None,
    ) -> str:
        """Start a background security scan.

        Args:
            tool_name: Tool to run (e.g., 'nmap', 'nuclei', 'ffuf')
            target: Target IP, domain, or URL
            options: Additional CLI options
            category: Category hint for validation (recon, scanner, etc.)
            confirm_authorized: Set true only when the selected tool requires explicit authorization confirmation.
        """
        record = await task_mgr.start_task(
            tool_name=tool_name,
            target=target,
            options=options,
            category=category,
            confirm_authorized=confirm_authorized,
            ctx=ctx,
        )

        lines = [
            f"## Task Started: {record.task_id}",
            "",
            f"**Tool:** `{record.tool_name}`",
            f"**Target:** `{record.target}`",
        ]
        if record.options:
            lines.append(f"**Options:** `{record.options}`")
        if record.confirm_authorized:
            lines.append("**Authorization confirmed:** true")
        lines.extend([
            f"**Status:** {record.status.value}",
            f"**Created:** {record.created_at}",
            "",
            "Use `security_task_status('{0}')` to check progress.".format(record.task_id),
            "Use `security_list_tasks` to see all tasks.",
        ])

        if ctx:
            await ctx.info(f"Background task {record.task_id} started: {tool_name} against {target}")

        return "\n".join(lines)

    @mcp.tool(
        name="security_task_status",
        description="Check the status and get results of a background task. "
        "Shows status (pending/running/completed/failed/cancelled), "
        "execution time, and the full output once completed. "
        "Use the task_id returned by security_task_start.",
    )
    async def security_task_status(
        task_id: str,
        ctx: Context = None,
    ) -> str:
        """Get task status and results.

        Args:
            task_id: The task ID from security_task_start
        """
        record = task_mgr.get_task(task_id)
        if not record:
            return f"Task not found: '{task_id}'. Use `security_list_tasks` to see all tasks."

        status_emoji = {
            "pending": "⏳",
            "running": "🔄",
            "completed": "✅",
            "failed": "❌",
            "cancelled": "🚫",
        }
        emoji = status_emoji.get(record.status.value, "❓")

        lines = [
            f"## {emoji} Task: {record.task_id}",
            "",
            f"**Status:** {record.status.value.upper()}",
            f"**Tool:** `{record.tool_name}`",
            f"**Target:** `{record.target}`",
        ]
        if record.options:
            lines.append(f"**Options:** `{record.options}`")
        lines.extend([
            f"**Created:** {record.created_at}",
        ])
        if record.started_at:
            lines.append(f"**Started:** {record.started_at}")
        if record.completed_at:
            lines.append(f"**Completed:** {record.completed_at}")
        if record.duration_ms:
            lines.append(f"**Duration:** {record.duration_ms}ms")

        if record.error:
            lines.append(f"\n**Error:** {record.error}")

        if record.status.value == "completed" and record.result:
            r = record.result
            lines.append(f"\n**Exit code:** {r.return_code}")
            if r.timed_out:
                lines.append("⚠️ **Command timed out.**")
            if r.was_blocked:
                lines.append(f"⛔ **Blocked:** {r.block_reason}")
            if r.stdout:
                stdout = r.stdout
                if len(stdout) > 15000:
                    stdout = stdout[:15000] + "\n... (output truncated)"
                lines.append(f"\n### Output\n```\n{stdout}\n```")
            if r.stderr:
                stderr = r.stderr
                if len(stderr) > 3000:
                    stderr = stderr[:3000] + "\n... (truncated)"
                lines.append(f"\n### Stderr\n```\n{stderr}\n```")

        if record.asset_scan_id:
            lines.append(f"\n💾 **Saved to asset:** `{record.asset_scan_id}`")

        return "\n".join(lines)

    @mcp.tool(
        name="security_cancel_task",
        description="Cancel a running background task. "
        "Kills the tool's process and marks the task as cancelled. "
        "Use the task_id from security_task_start.",
    )
    async def security_cancel_task(
        task_id: str,
        ctx: Context = None,
    ) -> str:
        """Cancel a running task.

        Args:
            task_id: The task ID to cancel
        """
        record = task_mgr.get_task(task_id)
        if not record:
            return f"Task not found: '{task_id}'."

        if record.status.value not in ("pending", "running"):
            return f"Cannot cancel task '{task_id}' — status is '{record.status.value}'."

        success = await task_mgr.cancel_task(task_id)
        if success:
            if ctx:
                await ctx.info(f"Task {task_id} cancelled")
            return f"✅ Task '{task_id}' has been cancelled."
        return f"❌ Could not cancel task '{task_id}'."

    @mcp.tool(
        name="security_list_tasks",
        description="List all background tasks with their status. "
        "Optionally filter by status (pending, running, completed, failed, cancelled). "
        "Use to monitor all background execution activity.",
    )
    async def security_list_tasks(
        status: str = "",
        ctx: Context = None,
    ) -> str:
        """List all tasks.

        Args:
            status: Optional filter — pending, running, completed, failed, cancelled
        """
        tasks = task_mgr.list_tasks(status)
        if not tasks:
            filter_msg = f" with status '{status}'" if status else ""
            return f"No tasks found{filter_msg}. Use `security_task_start` to start one."

        status_emoji = {
            "pending": "⏳",
            "running": "🔄",
            "completed": "✅",
            "failed": "❌",
            "cancelled": "🚫",
        }

        lines = [f"# Background Tasks ({len(tasks)})\n"]
        for r in tasks:
            emoji = status_emoji.get(r.status.value, "❓")
            duration = f" | {r.duration_ms}ms" if r.duration_ms else ""
            target = f" → `{r.target}`" if r.target else ""
            lines.append(
                f"{emoji} **`{r.task_id}`** [{r.status.value.upper()}] "
                f"{r.tool_name}{target}{duration}"
            )

        return "\n".join(lines)
