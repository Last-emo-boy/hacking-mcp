"""TaskManager — background task execution with persistent state.

Wraps ToolOrchestrator.execute() in asyncio.Task for non-blocking execution.
Each task is persisted to ~/.hacking-mcp/tasks/{task_id}.json on every
state transition.

Lifecycle: PENDING → RUNNING → COMPLETED | FAILED | CANCELLED
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from hacking_mcp.models import TaskStatus, TaskRecord, RunResult
from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest
from hacking_mcp.runner import ToolRunner
from hacking_mcp.environment import get_tasks_dir

logger = logging.getLogger("hacking-mcp.tasks")


class TaskManager:
    """Manages background task execution with persistent state.

    On startup, loads existing task files from disk. Tasks that were
    RUNNING at shutdown are marked FAILED (server restart).

    Each task goes through the full orchestrator pipeline (safety gates,
    scope validation, etc.) synchronously before spawning as a background
    asyncio.Task for the subprocess execution.
    """

    def __init__(self, orchestrator: ToolOrchestrator, asset_mgr: "AssetManager | None" = None):
        self._orchestrator = orchestrator
        self._asset_mgr = asset_mgr
        self._tasks: dict[str, asyncio.Task] = {}
        self._task_runners: dict[str, ToolRunner] = {}
        self._records: dict[str, TaskRecord] = {}
        self._proc_map: dict[str, "asyncio.subprocess.Process"] = {}
        self._load_existing()

    @property
    def tasks_dir(self) -> Path:
        return get_tasks_dir()

    def _generate_task_id(self) -> str:
        return f"task-{uuid.uuid4().hex[:12]}"

    def _task_path(self, task_id: str) -> Path:
        return self.tasks_dir / f"{task_id}.json"

    def _load_existing(self) -> None:
        """Load existing task records from disk on startup."""
        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        for f in sorted(self.tasks_dir.glob("*.json")):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue

            task_id = data.get("task_id", f.stem)
            status_str = data.get("status", "pending")

            # Reconstruct RunResult if present
            result = None
            if data.get("result"):
                r = data["result"]
                result = RunResult(
                    tool_name=r.get("tool_name", ""),
                    command=r.get("command", []),
                    return_code=r.get("return_code", -1),
                    stdout=r.get("stdout", ""),
                    stderr=r.get("stderr", ""),
                    duration_ms=r.get("duration_ms", 0),
                    timed_out=r.get("timed_out", False),
                    was_blocked=r.get("was_blocked", False),
                    block_reason=r.get("block_reason", ""),
                    output_file=r.get("output_file", ""),
                )

            record = TaskRecord(
                task_id=task_id,
                tool_name=data.get("tool_name", ""),
                target=data.get("target", ""),
                options=data.get("options", ""),
                category=data.get("category", ""),
                confirm_authorized=data.get("confirm_authorized", False),
                status=TaskStatus(status_str),
                created_at=data.get("created_at", ""),
                started_at=data.get("started_at", ""),
                completed_at=data.get("completed_at", ""),
                duration_ms=data.get("duration_ms", 0),
                result=result,
                error=data.get("error", ""),
                asset_scan_id=data.get("asset_scan_id", ""),
            )

            # Tasks that were running at shutdown are failed
            if record.status == TaskStatus.RUNNING:
                record.status = TaskStatus.FAILED
                record.completed_at = datetime.now(timezone.utc).isoformat()
                record.error = "Server shutdown while task was running"
                self._save_record(record)

            self._records[task_id] = record
            logger.debug("Loaded task: %s (%s)", task_id, record.status.value)

    def _save_record(self, record: TaskRecord) -> None:
        """Persist a single task record to disk."""
        path = self._task_path(record.task_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "task_id": record.task_id,
            "tool_name": record.tool_name,
            "target": record.target,
            "options": record.options,
            "category": record.category,
            "confirm_authorized": record.confirm_authorized,
            "status": record.status.value,
            "created_at": record.created_at,
            "started_at": record.started_at,
            "completed_at": record.completed_at,
            "duration_ms": record.duration_ms,
            "error": record.error,
            "asset_scan_id": record.asset_scan_id,
            "result": None,
        }
        if record.result:
            doc["result"] = {
                "tool_name": record.result.tool_name,
                "command": record.result.command,
                "return_code": record.result.return_code,
                "stdout": record.result.stdout,
                "stderr": record.result.stderr,
                "duration_ms": record.result.duration_ms,
                "timed_out": record.result.timed_out,
                "was_blocked": record.result.was_blocked,
                "block_reason": record.result.block_reason,
                "output_file": record.result.output_file,
            }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)

    async def start_task(
        self,
        tool_name: str,
        target: str,
        options: str = "",
        category: str = "",
        confirm_authorized: bool = False,
        ctx=None,
    ) -> TaskRecord:
        """Start a background task. Returns immediately with a TaskRecord.

        The task is spawned as an asyncio.Task and runs in the background.
        Use get_task() or list_tasks() to check status.
        """
        task_id = self._generate_task_id()
        now = datetime.now(timezone.utc).isoformat()

        record = TaskRecord(
            task_id=task_id,
            tool_name=tool_name,
            target=target,
            options=options,
            category=category,
            confirm_authorized=confirm_authorized,
            status=TaskStatus.PENDING,
            created_at=now,
        )
        self._records[task_id] = record
        self._save_record(record)

        # Spawn background task
        async_task = asyncio.create_task(self._run_task(record, ctx))
        self._tasks[task_id] = async_task

        logger.info("Task started: %s (%s %s)", task_id, tool_name, target)
        return record

    async def _run_task(self, record: TaskRecord, ctx=None) -> None:
        """Background coroutine that executes the tool and updates state."""
        task_id = record.task_id

        # Transition to RUNNING
        now = datetime.now(timezone.utc).isoformat()
        record.status = TaskStatus.RUNNING
        record.started_at = now
        self._save_record(record)

        try:
            task_orchestrator = self._build_task_orchestrator(task_id)
            # Build a ToolRequest — goes through the full orchestrator pipeline
            # Safety gates run synchronously here (in the background task)
            request = ToolRequest(
                tool_name=record.tool_name,
                target=record.target,
                options=record.options,
                confirm_authorized=record.confirm_authorized,
            )
            response = await task_orchestrator.execute(request, ctx=ctx)

            record.result = response.result
            record.error = response.error

            if response.result and not response.result.was_blocked:
                record.status = TaskStatus.COMPLETED
                record.duration_ms = response.result.duration_ms

                if record.result and record.result.output_file:
                    record.asset_scan_id = Path(record.result.output_file).stem
                # Save to asset manager only if the orchestrator is not already doing it.
                elif self._asset_mgr and not getattr(self._orchestrator, "asset_mgr", None):
                    try:
                        scan_id = self._asset_mgr.save_result(
                            target=record.target,
                            tool_name=record.tool_name,
                            options=record.options,
                            result=response.result,
                        )
                        record.asset_scan_id = scan_id
                        if record.result:
                            record.result.output_file = str(
                                self._asset_mgr._asset_dir(record.target)
                                / f"{scan_id}.json"
                            )
                    except Exception as e:
                        logger.warning("Failed to save asset result for %s: %s", task_id, e)
            elif response.error:
                record.status = TaskStatus.FAILED
            else:
                record.status = TaskStatus.COMPLETED  # blocked = completed (known outcome)

        except asyncio.CancelledError:
            record.status = TaskStatus.CANCELLED
            record.error = "Task cancelled by user"
            # Kill only this task's runner/process.
            runner = self._task_runners.get(task_id)
            if runner is not None:
                runner.kill_current()
            else:
                self._orchestrator.runner.kill_current()
            raise

        except Exception as e:
            logger.exception("Task %s failed", task_id)
            record.status = TaskStatus.FAILED
            record.error = str(e)

        finally:
            record.completed_at = datetime.now(timezone.utc).isoformat()
            self._save_record(record)
            self._task_runners.pop(task_id, None)
            # Clean up the asyncio.Task reference
            self._tasks.pop(task_id, None)

    def _build_task_orchestrator(self, task_id: str) -> ToolOrchestrator:
        """Create an isolated runner/orchestrator for one background task."""
        if not isinstance(self._orchestrator, ToolOrchestrator):
            return self._orchestrator

        task_runner = ToolRunner(self._orchestrator.registry, self._orchestrator.safety)
        self._task_runners[task_id] = task_runner
        return ToolOrchestrator(
            registry=self._orchestrator.registry,
            safety=self._orchestrator.safety,
            runner=task_runner,
            formatter=self._orchestrator.formatter,
            asset_manager=self._orchestrator.asset_mgr,
        )

    def get_task(self, task_id: str) -> Optional[TaskRecord]:
        """Get a task record by ID."""
        return self._records.get(task_id)

    def list_tasks(self, status_filter: str = "") -> list[TaskRecord]:
        """List all tasks, optionally filtered by status.

        Args:
            status_filter: Optional status filter (pending/running/completed/failed/cancelled)
        """
        records = list(self._records.values())
        if status_filter:
            try:
                status = TaskStatus(status_filter.lower())
                records = [r for r in records if r.status == status]
            except ValueError:
                pass
        # Sort by created_at descending
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a running or pending task.

        Returns True if the task was found and cancellation was attempted.
        """
        record = self._records.get(task_id)
        if not record:
            return False

        if record.status not in (TaskStatus.PENDING, TaskStatus.RUNNING):
            return False

        async_task = self._tasks.get(task_id)
        if async_task and not async_task.done():
            async_task.cancel()
            logger.info("Task cancelled: %s", task_id)
            return True

        # Task was pending but asyncio.Task not found (edge case)
        if record.status == TaskStatus.PENDING:
            record.status = TaskStatus.CANCELLED
            record.error = "Task cancelled before execution"
            record.completed_at = datetime.now(timezone.utc).isoformat()
            self._save_record(record)
            return True

        return False
