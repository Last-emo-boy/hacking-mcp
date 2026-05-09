"""Tests for environment detection and path translation."""

import platform
import pytest
from hacking_mcp.environment import (
    detect_environment,
    ExecBackend,
    Environment,
    to_wsl_path,
    to_win_path,
    get_tools_dir,
    get_audit_dir,
)


class TestEnvironmentDetection:
    def test_detect_returns_environment(self):
        """detect_environment() should return an Environment instance."""
        env = detect_environment()
        assert isinstance(env, Environment)
        assert env.system in ("windows", "linux", "macos")
        assert env.backend in (ExecBackend.NATIVE, ExecBackend.WSL2)

    def test_system_matches_platform(self):
        """Detected system should match platform.system()."""
        env = detect_environment()
        assert env.system == platform.system().lower()

    def test_linux_is_native_backend(self):
        """On Linux, backend should always be NATIVE."""
        env = detect_environment()
        if env.system == "linux":
            assert env.backend == ExecBackend.NATIVE

    def test_macos_is_native_backend(self):
        """On macOS, backend should always be NATIVE."""
        env = detect_environment()
        if env.system == "macos":
            assert env.backend == ExecBackend.NATIVE


class TestPathTranslation:
    def test_windows_to_wsl_path_c_drive(self):
        result = to_wsl_path("C:\\Users\\test\\tools")
        assert result == "/mnt/c/Users/test/tools"

    def test_windows_to_wsl_path_e_drive(self):
        result = to_wsl_path("E:\\Playground\\data")
        assert result == "/mnt/e/Playground/data"

    def test_wsl_to_win_path(self):
        result = to_win_path("/mnt/c/Users/test/tools")
        assert result == "C:\\Users\\test\\tools"

    def test_wsl_to_win_path_other_drive(self):
        result = to_win_path("/mnt/e/Playground")
        assert "E:" in result
        assert "Playground" in result

    def test_non_mnt_path_unchanged(self):
        """Paths not under /mnt/ should be returned as-is."""
        result = to_win_path("/home/user/tools")
        assert result == "/home/user/tools"

    def test_forward_slash_windows_path(self):
        """Windows paths with forward slashes should still translate."""
        result = to_wsl_path("C:/Users/test/tools")
        assert result == "/mnt/c/Users/test/tools"


class TestToolsDir:
    def test_get_tools_dir_returns_path(self):
        """get_tools_dir() should return a Path."""
        from pathlib import Path
        d = get_tools_dir()
        assert isinstance(d, Path)

    def test_get_tools_dir_in_home(self):
        """Tools directory should be under user's home."""
        from pathlib import Path
        d = get_tools_dir()
        home = Path.home()
        assert str(home) in str(d)

    def test_get_audit_dir_in_home(self):
        """Audit directory should be under user's home."""
        from pathlib import Path
        d = get_audit_dir()
        home = Path.home()
        assert str(home) in str(d)
