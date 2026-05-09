"""Tests for TaskManager."""

import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from hacking_mcp.tasks import TaskManager
from hacking_mcp.models import TaskStatus, TaskRecord, RunResult, HackingToolDef, SafetyTier
from hacking_mcp.orchestrator import ToolOrchestrator, ToolResponse
from hacking_mcp.formatters import OutputFormatter
from hacking_mcp.safety import SafetyPolicy


@pytest.fixture
def mock_orchestrator():
    orch = MagicMock()
    orch.execute = AsyncMock(return_value=ToolResponse(
        tool_name="mock",
        result=RunResult(
            tool_name="mock",
            command=["mock"],
            return_code=0,
            stdout="mock output",
            stderr="",
            duration_ms=100,
        ),
        formatted="## mock Results\nmock output",
    ))
    orch.runner = MagicMock()
    orch.runner.kill_current = MagicMock()
    orch.asset_mgr = None
    return orch


@pytest.fixture
def task_mgr(mock_orchestrator, tmp_path):
    """Create a TaskManager that uses tmp_path for persistence."""
    with patch("hacking_mcp.tasks.get_tasks_dir", return_value=Path(tmp_path / "tasks")):
        mgr = TaskManager(mock_orchestrator)
        yield mgr


class TestTaskManager:
    @pytest.mark.asyncio
    async def test_start_task(self, task_mgr):
        record = await task_mgr.start_task("nmap", "192.168.1.1", "-sV")
        assert record.task_id.startswith("task-")
        assert record.tool_name == "nmap"
        assert record.target == "192.168.1.1"
        assert record.options == "-sV"
        assert record.status == TaskStatus.PENDING

    @pytest.mark.asyncio
    async def test_start_task_persists_authorization_confirmation(self, task_mgr, tmp_path):
        record = await task_mgr.start_task(
            "sqlmap",
            "http://127.0.0.1:8000",
            confirm_authorized=True,
        )
        assert record.confirm_authorized is True

        task_file = Path(tmp_path) / "tasks" / f"{record.task_id}.json"
        with open(task_file, "r") as f:
            data = json.load(f)
        assert data["confirm_authorized"] is True

    @pytest.mark.asyncio
    async def test_get_task(self, task_mgr):
        record = await task_mgr.start_task("nmap", "192.168.1.1")
        fetched = task_mgr.get_task(record.task_id)
        assert fetched is not None
        assert fetched.task_id == record.task_id

    def test_get_task_not_found(self, task_mgr):
        assert task_mgr.get_task("nonexistent") is None

    def test_list_tasks_empty(self, task_mgr):
        tasks = task_mgr.list_tasks()
        assert tasks == []

    @pytest.mark.asyncio
    async def test_list_tasks(self, task_mgr):
        await task_mgr.start_task("nmap", "1.1.1.1")
        await task_mgr.start_task("amass", "example.com")

        tasks = task_mgr.list_tasks()
        assert len(tasks) == 2
        # Sorted by created_at descending
        assert tasks[0].tool_name == "amass"
        assert tasks[1].tool_name == "nmap"

    @pytest.mark.asyncio
    async def test_list_tasks_filtered(self, task_mgr):
        await task_mgr.start_task("nmap", "1.1.1.1")
        await task_mgr.start_task("amass", "example.com")

        pending = task_mgr.list_tasks("pending")
        assert len(pending) == 2

        completed = task_mgr.list_tasks("completed")
        assert len(completed) == 0

    @pytest.mark.asyncio
    async def test_task_lifecycle(self, task_mgr, mock_orchestrator):
        """Test full pending → running → completed lifecycle."""
        mock_orchestrator.execute.return_value = ToolResponse(
            tool_name="nmap",
            result=RunResult(
                tool_name="nmap",
                command=["nmap", "127.0.0.1"],
                return_code=0,
                stdout="Port 80 open",
                stderr="",
                duration_ms=1500,
            ),
            formatted="## nmap Results\n...",
        )

        record = await task_mgr.start_task("nmap", "127.0.0.1")

        # Should be pending immediately
        pending = task_mgr.get_task(record.task_id)
        assert pending.status == TaskStatus.PENDING

        # Wait for background task to complete
        await asyncio.sleep(0.2)

        completed = task_mgr.get_task(record.task_id)
        assert completed is not None
        assert completed.status == TaskStatus.COMPLETED
        assert completed.result is not None
        assert completed.result.return_code == 0
        assert "Port 80 open" in completed.result.stdout

    @pytest.mark.asyncio
    async def test_task_failure(self, task_mgr, mock_orchestrator):
        """Test that execution errors result in FAILED status."""
        mock_orchestrator.execute.side_effect = RuntimeError("Simulated failure")

        record = await task_mgr.start_task("nmap", "127.0.0.1")
        await asyncio.sleep(0.2)

        failed = task_mgr.get_task(record.task_id)
        assert failed.status == TaskStatus.FAILED
        assert "Simulated failure" in failed.error

    @pytest.mark.asyncio
    async def test_cancel_task(self, task_mgr, mock_orchestrator):
        """Test cancelling a pending task."""
        # Make execute() block so the task stays pending
        async def slow_execute(*args, **kwargs):
            await asyncio.sleep(10)
            return ToolResponse(tool_name="nmap", formatted="done")

        mock_orchestrator.execute = slow_execute

        record = await task_mgr.start_task("nmap", "127.0.0.1")

        # Give it a moment to start transitioning
        await asyncio.sleep(0.05)

        success = await task_mgr.cancel_task(record.task_id)
        assert success is True

    @pytest.mark.asyncio
    async def test_cancel_one_task_does_not_kill_another_task_runner(self, tmp_path):
        """Each real background task gets an isolated runner for cancellation."""
        tool = HackingToolDef(
            name="sleepy",
            title="Sleepy",
            description="Long-running test tool",
            category="Information Gathering",
            run_command="sleepy {target}",
            safety_tier=SafetyTier.SAFE,
            supported_os=["windows", "linux", "macos"],
        )

        class FakeRegistry:
            def get_tool(self, name):
                return tool if name == "sleepy" else None

            def is_available(self, name):
                return name == "sleepy"

            def get_install_commands(self, name):
                return []

        class FakeRunner:
            instances = []

            def __init__(self, registry, safety):
                self.started = asyncio.Event()
                self.release = asyncio.Event()
                self.killed = False
                self.target = ""
                FakeRunner.instances.append(self)

            async def run(self, tool_name, args=None, **kwargs):
                self.target = (args or [""])[0]
                self.started.set()
                await self.release.wait()
                return RunResult(
                    tool_name=tool_name,
                    command=["sleepy", self.target],
                    return_code=0,
                    stdout="done",
                    stderr="",
                    duration_ms=1,
                )

            def kill_current(self):
                self.killed = True
                self.release.set()

        safety = SafetyPolicy(_audit_path=tmp_path / "audit" / "audit.jsonl")
        base_orchestrator = ToolOrchestrator(
            registry=FakeRegistry(),
            safety=safety,
            runner=MagicMock(),
            formatter=OutputFormatter(),
        )

        with (
            patch("hacking_mcp.tasks.get_tasks_dir", return_value=Path(tmp_path / "tasks")),
            patch("hacking_mcp.tasks.ToolRunner", FakeRunner),
        ):
            mgr = TaskManager(base_orchestrator)
            first_record = await mgr.start_task("sleepy", "127.0.0.1")
            second_record = await mgr.start_task("sleepy", "127.0.0.2")

            for _ in range(50):
                if len(FakeRunner.instances) == 2 and all(r.started.is_set() for r in FakeRunner.instances):
                    break
                await asyncio.sleep(0.01)

            assert len(FakeRunner.instances) == 2
            first_runner = next(r for r in FakeRunner.instances if r.target == "127.0.0.1")
            second_runner = next(r for r in FakeRunner.instances if r.target == "127.0.0.2")

            assert await mgr.cancel_task(first_record.task_id) is True
            await asyncio.sleep(0.05)

            assert first_runner.killed is True
            assert second_runner.killed is False
            assert mgr.get_task(first_record.task_id).status == TaskStatus.CANCELLED
            assert mgr.get_task(second_record.task_id).status == TaskStatus.RUNNING

            assert await mgr.cancel_task(second_record.task_id) is True
            await asyncio.sleep(0.05)

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_task(self, task_mgr):
        success = await task_mgr.cancel_task("nonexistent")
        assert success is False

    @pytest.mark.asyncio
    async def test_cancel_completed_task(self, task_mgr, mock_orchestrator):
        """Cannot cancel a task that already completed."""
        mock_orchestrator.execute.return_value = ToolResponse(
            tool_name="nmap",
            result=RunResult(
                tool_name="nmap",
                command=["nmap"],
                return_code=0,
                stdout="done",
                stderr="",
                duration_ms=100,
            ),
            formatted="done",
        )

        record = await task_mgr.start_task("nmap", "127.0.0.1")
        await asyncio.sleep(0.2)  # Wait for completion

        success = await task_mgr.cancel_task(record.task_id)
        assert success is False  # Already completed

    @pytest.mark.asyncio
    async def test_persistence(self, task_mgr, tmp_path):
        """Test that tasks are persisted to disk."""
        record = await task_mgr.start_task("nmap", "192.168.1.1", "-sV")

        # Check that a JSON file was created
        task_file = Path(tmp_path) / "tasks" / f"{record.task_id}.json"
        assert task_file.exists()

        # Verify content
        with open(task_file, "r") as f:
            data = json.load(f)
        assert data["tool_name"] == "nmap"
        assert data["target"] == "192.168.1.1"
        assert data["options"] == "-sV"

    @pytest.mark.asyncio
    async def test_orchestrator_asset_output_is_not_saved_twice(self, mock_orchestrator, tmp_path):
        asset_mgr = MagicMock()
        mock_orchestrator.asset_mgr = MagicMock()
        output_file = str(Path(tmp_path) / "assets" / "127.0.0.1" / "scan-123.json")
        mock_orchestrator.execute.return_value = ToolResponse(
            tool_name="nmap",
            result=RunResult(
                tool_name="nmap",
                command=["nmap", "127.0.0.1"],
                return_code=0,
                stdout="done",
                stderr="",
                duration_ms=100,
                output_file=output_file,
            ),
            formatted="done",
        )

        with patch("hacking_mcp.tasks.get_tasks_dir", return_value=Path(tmp_path / "tasks")):
            mgr = TaskManager(mock_orchestrator, asset_mgr=asset_mgr)
            record = await mgr.start_task("nmap", "127.0.0.1")
            await asyncio.sleep(0.2)

        completed = mgr.get_task(record.task_id)
        assert completed.asset_scan_id == "scan-123"
        asset_mgr.save_result.assert_not_called()

    def test_load_existing_tasks(self, mock_orchestrator, tmp_path):
        """Test that existing tasks are loaded on startup."""
        from hacking_mcp.models import TaskStatus as TS

        # Create a pre-existing task file
        tasks_dir = Path(tmp_path) / "tasks"
        tasks_dir.mkdir(parents=True)
        task_data = {
            "task_id": "task-old12345678",
            "tool_name": "oldscan",
            "target": "10.0.0.1",
            "options": "",
            "category": "",
            "status": "completed",
            "created_at": "2026-01-01T00:00:00Z",
            "started_at": "2026-01-01T00:00:01Z",
            "completed_at": "2026-01-01T00:05:00Z",
            "duration_ms": 299000,
            "error": "",
            "asset_scan_id": "",
            "result": {
                "tool_name": "oldscan",
                "command": ["oldscan", "10.0.0.1"],
                "return_code": 0,
                "stdout": "Results here",
                "stderr": "",
                "duration_ms": 299000,
                "timed_out": False,
                "was_blocked": False,
                "block_reason": "",
                "output_file": "",
            },
        }
        with open(tasks_dir / "task-old12345678.json", "w") as f:
            json.dump(task_data, f)

        # Also create a "running" task (should be marked failed on load)
        running_task = dict(task_data)
        running_task["task_id"] = "task-running99999"
        running_task["status"] = "running"
        with open(tasks_dir / "task-running99999.json", "w") as f:
            json.dump(running_task, f)

        with patch("hacking_mcp.tasks.get_tasks_dir", return_value=tasks_dir):
            mgr = TaskManager(mock_orchestrator)

        # Completed task should be loaded
        old = mgr.get_task("task-old12345678")
        assert old is not None
        assert old.status == TaskStatus.COMPLETED
        assert old.result is not None
        assert old.result.stdout == "Results here"

        # Running task should be marked failed
        running = mgr.get_task("task-running99999")
        assert running is not None
        assert running.status == TaskStatus.FAILED
        assert "Server shutdown" in running.error
