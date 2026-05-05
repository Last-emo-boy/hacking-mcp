"""AssetManager — structured per-target scan output.

Each asset (target IP, domain, CIDR) gets its own directory under
~/.hacking-mcp/assets/<sanitized_target>/ containing JSON scan results
and an index.json tracking all scans.

Scan ID format: {ISO_UTC_Z}_{tool_name} (e.g., 2026-05-05T103000Z_nmap)
"""

import difflib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from hacking_mcp.models import RunResult, AssetRecord
from hacking_mcp.environment import get_assets_dir

logger = logging.getLogger("hacking-mcp.assets")


class AssetManager:
    """Manages per-target scan output with indexing and comparison."""

    def __init__(self, max_scans_per_asset: int = 100):
        self.max_scans_per_asset = max_scans_per_asset

    @property
    def assets_dir(self) -> Path:
        return get_assets_dir()

    @staticmethod
    def sanitize_target(target: str) -> str:
        """Convert a target to a filesystem-safe directory name.

        Rules:
        - Strip protocol prefix (https://, http://)
        - Strip trailing slash
        - Replace ':' with '_' (IPv6)
        - Replace '/' with '_' (CIDR)
        - Replace any non-alphanumeric (except _, -, .) with '_'
        - Collapse multiple '_' to single '_'
        - Strip leading/trailing '_' and '.'
        - Max 200 chars
        """
        s = target.strip()
        # Remove protocol
        s = re.sub(r'^https?://', '', s)
        # Remove trailing slash
        s = s.rstrip('/')
        # Replace problematic chars
        s = s.replace(':', '_')
        s = s.replace('/', '_')
        # Replace any remaining non-safe chars
        s = re.sub(r'[^a-zA-Z0-9_\-.]', '_', s)
        # Collapse underscores
        s = re.sub(r'_+', '_', s)
        # Strip leading/trailing unsafe
        s = s.strip('_.')
        # Max length
        if len(s) > 200:
            s = s[:200]
        return s or "unnamed"

    def _asset_dir(self, target: str) -> Path:
        """Get the per-target directory, creating if needed."""
        d = self.assets_dir / self.sanitize_target(target)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _index_path(self, asset_dir: Path) -> Path:
        return asset_dir / "index.json"

    def _load_index(self, target: str) -> AssetRecord:
        """Load or create the asset index."""
        asset_dir = self._asset_dir(target)
        ip = self._index_path(asset_dir)
        if ip.exists():
            try:
                with open(ip, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return AssetRecord(
                    target=data.get("target", target),
                    sanitized=data.get("sanitized", self.sanitize_target(target)),
                    first_seen=data.get("first_seen", ""),
                    last_scanned=data.get("last_scanned", ""),
                    scan_count=data.get("scan_count", 0),
                    scans=data.get("scans", []),
                )
            except (json.JSONDecodeError, OSError):
                pass
        return AssetRecord(
            target=target,
            sanitized=self.sanitize_target(target),
        )

    def _save_index(self, record: AssetRecord) -> None:
        """Write the asset index."""
        asset_dir = self._asset_dir(record.target)
        ip = self._index_path(asset_dir)
        with open(ip, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "target": record.target,
                    "sanitized": record.sanitized,
                    "first_seen": record.first_seen,
                    "last_scanned": record.last_scanned,
                    "scan_count": record.scan_count,
                    "scans": record.scans,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

    _scan_counter: int = 0

    @classmethod
    def _generate_scan_id(cls, tool_name: str) -> str:
        """Generate a unique scan ID.

        Format: {ISO_UTC_micro}_{tool_name} (e.g., 2026-05-05T103000.123456Z_nmap)
        Uses microsecond UTC time plus a counter to guarantee uniqueness.
        """
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S.%fZ")
        cls._scan_counter += 1
        return f"{ts}_{tool_name}"

    def save_result(
        self,
        target: str,
        tool_name: str,
        options: str,
        result: RunResult,
    ) -> str:
        """Save a scan result to the asset directory.

        Returns the scan_id.
        """
        asset_dir = self._asset_dir(target)
        scan_id = self._generate_scan_id(tool_name)
        scan_path = asset_dir / f"{scan_id}.json"
        timestamp = datetime.now(timezone.utc).isoformat()

        doc = {
            "scan_id": scan_id,
            "target": target,
            "tool_name": tool_name,
            "options": options,
            "timestamp": timestamp,
            "command": " ".join(result.command) if result.command else "",
            "result": {
                "return_code": result.return_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration_ms": result.duration_ms,
                "timed_out": result.timed_out,
                "was_blocked": result.was_blocked,
                "block_reason": result.block_reason,
            },
        }

        with open(scan_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)

        # Update index
        record = self._load_index(target)
        if not record.first_seen:
            record.first_seen = timestamp
        record.last_scanned = timestamp
        record.scan_count = len(record.scans) + 1
        record.scans.append({
            "scan_id": scan_id,
            "tool_name": tool_name,
            "timestamp": timestamp,
            "options": options,
            "return_code": result.return_code,
        })

        # Enforce max scans limit
        if len(record.scans) > self.max_scans_per_asset:
            removed = record.scans[:-self.max_scans_per_asset]
            record.scans = record.scans[-self.max_scans_per_asset:]
            for old in removed:
                old_path = asset_dir / f"{old['scan_id']}.json"
                if old_path.exists():
                    old_path.unlink()
            logger.info("Cleaned up %d old scans for %s", len(removed), target)

        self._save_index(record)
        logger.info("Saved scan %s for asset %s", scan_id, target)
        return scan_id

    def list_assets(self) -> list[AssetRecord]:
        """List all tracked assets."""
        assets = []
        if not self.assets_dir.exists():
            return assets
        for d in sorted(self.assets_dir.iterdir()):
            if d.is_dir():
                record = self._load_index(d.name)
                assets.append(record)
        return assets

    def get_asset(self, target: str) -> Optional[AssetRecord]:
        """Get a single asset's record."""
        asset_dir = self._asset_dir(target)
        if not asset_dir.exists() or not self._index_path(asset_dir).exists():
            return None
        return self._load_index(target)

    def get_history(
        self,
        target: str,
        tool_name: str = "",
        limit: int = 20,
    ) -> list[dict]:
        """Get scan history for an asset, optionally filtered by tool.

        Returns scan summaries without full stdout/stderr.
        """
        record = self._load_index(target)
        scans = record.scans
        if tool_name:
            scans = [s for s in scans if s["tool_name"] == tool_name]
        # Return newest first
        scans.sort(key=lambda s: s["timestamp"], reverse=True)
        return scans[:limit]

    def get_scan(self, target: str, scan_id: str) -> Optional[dict]:
        """Get a full scan result."""
        asset_dir = self._asset_dir(target)
        scan_path = asset_dir / f"{scan_id}.json"
        if not scan_path.exists():
            return None
        try:
            with open(scan_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def compare_scans(
        self,
        target: str,
        scan_id_1: str,
        scan_id_2: str,
    ) -> Optional[dict]:
        """Compare two scan results for the same target.

        Returns a diff summary including line-level stdout diff.
        """
        scan1 = self.get_scan(target, scan_id_1)
        scan2 = self.get_scan(target, scan_id_2)
        if not scan1 or not scan2:
            return None

        r1 = scan1["result"]
        r2 = scan2["result"]

        # Compute line-level diff
        lines1 = r1.get("stdout", "").splitlines(keepends=True)
        lines2 = r2.get("stdout", "").splitlines(keepends=True)
        diff = list(
            difflib.unified_diff(
                lines1,
                lines2,
                fromfile=scan_id_1,
                tofile=scan_id_2,
                lineterm="",
            )
        )

        return {
            "scan_1": {
                "scan_id": scan_id_1,
                "timestamp": scan1["timestamp"],
                "return_code": r1["return_code"],
                "duration_ms": r1["duration_ms"],
            },
            "scan_2": {
                "scan_id": scan_id_2,
                "timestamp": scan2["timestamp"],
                "return_code": r2["return_code"],
                "duration_ms": r2["duration_ms"],
            },
            "diff": {
                "return_code": {"before": r1["return_code"], "after": r2["return_code"]},
                "duration_ms_delta": r2["duration_ms"] - r1["duration_ms"],
                "lines_added": sum(1 for line in diff if line.startswith("+")),
                "lines_removed": sum(1 for line in diff if line.startswith("-")),
                "unified_diff": diff,
            },
        }

    def cleanup_old_scans(self, target: str, keep: int = 50) -> int:
        """Remove oldest scan files exceeding the keep limit."""
        record = self._load_index(target)
        if len(record.scans) <= keep:
            return 0
        asset_dir = self._asset_dir(target)
        removed_count = 0
        to_remove = record.scans[:-keep]
        record.scans = record.scans[-keep:]
        for old in to_remove:
            old_path = asset_dir / f"{old['scan_id']}.json"
            if old_path.exists():
                old_path.unlink()
                removed_count += 1
        self._save_index(record)
        return removed_count
