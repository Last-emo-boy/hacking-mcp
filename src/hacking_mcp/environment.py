"""Execution environment detection — OS, WSL2, path translation, data directories.

Detects the current platform and available execution backends.
On Windows, all Linux tools are executed through WSL2.
On Linux/macOS, tools run natively.

All persistent data lives under ~/.hacking-mcp/:
  tools/    — cloned tool repositories
  installs/ — install state tracking
  tasks/    — background task persistence
  assets/   — per-target scan output
  audit/    — persistent JSONL audit log
"""

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class ExecBackend(Enum):
    NATIVE = "native"
    WSL2 = "wsl2"


@dataclass
class Environment:
    """Current execution environment info."""

    system: str  # "windows", "linux", "macos"
    backend: ExecBackend  # how to execute Linux tools
    wsl_available: bool = False
    wsl_distro: str = ""  # default WSL distro name

    @property
    def is_windows(self) -> bool:
        return self.system == "windows"

    @property
    def is_linux(self) -> bool:
        return self.system == "linux"

    @property
    def is_macos(self) -> bool:
        return self.system == "macos"


def detect_environment() -> Environment:
    """Detect the current OS and available execution backends."""
    system = platform.system().lower()

    if system == "windows":
        wsl_available, wsl_distro = _check_wsl2()
        if wsl_available:
            return Environment(
                system="windows",
                backend=ExecBackend.WSL2,
                wsl_available=True,
                wsl_distro=wsl_distro,
            )
        return Environment(
            system="windows",
            backend=ExecBackend.NATIVE,
            wsl_available=False,
        )

    return Environment(
        system=system,
        backend=ExecBackend.NATIVE,
    )


def _check_wsl2() -> tuple[bool, str]:
    """Check if WSL2 is available and get default distro name.

    wsl.exe may output UTF-8 or UTF-16 LE depending on the system locale.
    We capture raw bytes and auto-detect the encoding.
    """
    wsl_exe = shutil.which("wsl")
    if not wsl_exe:
        return False, ""

    # Try multiple flag combinations — some WSL versions don't support --quiet
    flag_sets = [
        ["--list", "--verbose"],             # most common, shows version column
        ["--list", "--verbose", "--quiet"],  # newer WSL, suppresses extra output
        ["--list"],                          # minimal fallback
    ]

    for flags in flag_sets:
        try:
            result = subprocess.run(
                [wsl_exe] + flags,
                capture_output=True,
                timeout=3,
            )
            if result.returncode != 0:
                continue

            # Auto-detect encoding: try UTF-8 first, then UTF-16 LE
            # (wsl.exe on Chinese/Japanese Windows outputs UTF-16 LE)
            stdout = _decode_wsl_output(result.stdout)
            if not stdout:
                continue

            # Parse default distro — look for the line with "*"
            for line in stdout.split("\n"):
                stripped = line.strip()
                if stripped.startswith("*"):
                    parts = stripped.lstrip("*").strip().split()
                    if parts:
                        distro = parts[0]
                        if distro and not distro.startswith("("):
                            return True, distro

            # WSL installed but no default distro set
            return False, ""
        except (subprocess.TimeoutExpired, OSError):
            continue

    return False, ""


def _decode_wsl_output(data: bytes) -> str:
    """Decode wsl.exe output, which may be UTF-8 or UTF-16 LE depending on locale."""
    # Try UTF-8 first (common on English Windows and newer WSL)
    try:
        text = data.decode("utf-8")
        # If we can find a '*' line, this is probably correct
        for line in text.split("\n"):
            if line.strip().startswith("*"):
                return text
    except UnicodeDecodeError:
        pass

    # Try UTF-16 LE (common on Chinese/Japanese/Korean Windows)
    try:
        text = data.decode("utf-16-le")
        for line in text.split("\n"):
            if line.strip().startswith("*"):
                return text
    except UnicodeDecodeError:
        pass

    # Last resort: UTF-8 with replacement
    return data.decode("utf-8", errors="replace")


# ---- Path Translation ----


def to_wsl_path(windows_path: str) -> str:
    """Convert a Windows path to its WSL2 equivalent.

    C:\\Users\\user\\tools  →  /mnt/c/Users/user/tools
    E:\\Playground\\data     →  /mnt/e/Playground/data
    """
    p = Path(windows_path)
    if p.drive:
        drive_letter = p.drive[0].lower()  # "C:" → "c"
        # Strip the drive prefix (e.g. "C:") from the posix path
        posix = p.as_posix()  # "C:/Users/test"
        if posix.lower().startswith(f"{drive_letter}:"):
            posix = posix[len(drive_letter) + 1:]  # "/Users/test"
        parts = posix.lstrip("/")
        return f"/mnt/{drive_letter}/{parts}"
    return windows_path.replace("\\", "/")


def to_win_path(wsl_path: str) -> str:
    """Convert a WSL2 /mnt/ path back to Windows format.

    /mnt/c/Users/user  →  C:\\Users\\user
    """
    if wsl_path.startswith("/mnt/"):
        parts = wsl_path.split("/")
        if len(parts) >= 3:
            drive = parts[2].upper() + ":"
            rest = "/".join(parts[3:])
            return f"{drive}\\{rest.replace('/', os.sep)}"
    return wsl_path


# ---- Tools Directory ----


def get_data_dir() -> Path:
    """Get the hacking-mcp data directory root.

    Returns ~/.hacking-mcp/ on all platforms.
    """
    return Path.home() / ".hacking-mcp"


def get_tools_dir() -> Path:
    """Get the hacking-mcp tools directory (where git clones live).

    On Linux: ~/.hacking-mcp/tools
    On Windows+WSL2: ~/.hacking-mcp/tools (in WSL filesystem)
    """
    return get_data_dir() / "tools"


def get_installs_dir() -> Path:
    """Get the install state directory."""
    return get_data_dir() / "installs"


def get_tasks_dir() -> Path:
    """Get the background task persistence directory."""
    return get_data_dir() / "tasks"


def get_assets_dir() -> Path:
    """Get the per-asset scan output directory."""
    return get_data_dir() / "assets"


def get_audit_dir() -> Path:
    """Get the persistent audit log directory."""
    return get_data_dir() / "audit"


def ensure_data_dirs() -> None:
    """Create all data subdirectories if they don't exist."""
    for d in [
        get_tools_dir(),
        get_installs_dir(),
        get_tasks_dir(),
        get_assets_dir(),
        get_audit_dir(),
    ]:
        d.mkdir(parents=True, exist_ok=True)
