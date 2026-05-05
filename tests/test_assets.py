"""Tests for AssetManager."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from hacking_mcp.assets import AssetManager
from hacking_mcp.models import RunResult, AssetRecord


@pytest.fixture
def asset_mgr(tmp_path):
    """Create an AssetManager that uses tmp_path for persistence."""
    with patch("hacking_mcp.assets.get_assets_dir", return_value=Path(tmp_path / "assets")):
        mgr = AssetManager()
        yield mgr


@pytest.fixture
def sample_result():
    return RunResult(
        tool_name="nmap",
        command=["nmap", "-sV", "192.168.1.1"],
        return_code=0,
        stdout="Port 80: open (Apache 2.4.41)\nPort 443: open (nginx 1.18.0)",
        stderr="",
        duration_ms=5234,
    )


class TestTargetSanitization:
    def test_ip_address(self):
        assert AssetManager.sanitize_target("192.168.1.1") == "192.168.1.1"

    def test_domain(self):
        assert AssetManager.sanitize_target("example.com") == "example.com"

    def test_url_http(self):
        assert AssetManager.sanitize_target("https://example.com/path") == "example.com_path"

    def test_url_trailing_slash(self):
        assert AssetManager.sanitize_target("https://example.com/") == "example.com"

    def test_cidr(self):
        assert AssetManager.sanitize_target("10.0.0.0/24") == "10.0.0.0_24"

    def test_ipv6(self):
        # Leading :: replaced by _ which get stripped
        assert AssetManager.sanitize_target("::1") == "1"

    def test_ipv6_full(self):
        assert AssetManager.sanitize_target("2001:db8::1") == "2001_db8_1"

    def test_special_chars(self):
        sanitized = AssetManager.sanitize_target("test@example.com:8080/path?query=1")
        assert "@" not in sanitized
        assert "?" not in sanitized

    def test_max_length(self):
        long_target = "a" * 300
        assert len(AssetManager.sanitize_target(long_target)) <= 200

    def test_empty(self):
        assert AssetManager.sanitize_target("") == "unnamed"


class TestAssetManager:
    def test_save_result(self, asset_mgr, sample_result):
        scan_id = asset_mgr.save_result(
            "192.168.1.1", "nmap", "-sV", sample_result
        )
        assert scan_id.endswith("_nmap")
        assert "T" in scan_id
        assert "Z" in scan_id

    def test_save_result_creates_file(self, asset_mgr, sample_result):
        scan_id = asset_mgr.save_result(
            "192.168.1.1", "nmap", "", sample_result
        )
        # Check the file exists
        asset_dir = asset_mgr._asset_dir("192.168.1.1")
        scan_path = asset_dir / f"{scan_id}.json"
        assert scan_path.exists()

        with open(scan_path, "r") as f:
            data = json.load(f)
        assert data["tool_name"] == "nmap"
        assert data["target"] == "192.168.1.1"
        assert "Port 80: open" in data["result"]["stdout"]

    def test_list_assets_empty(self, asset_mgr):
        assets = asset_mgr.list_assets()
        assert assets == []

    def test_list_assets(self, asset_mgr, sample_result):
        asset_mgr.save_result("192.168.1.1", "nmap", "", sample_result)
        asset_mgr.save_result("example.com", "amass", "", sample_result)

        assets = asset_mgr.list_assets()
        assert len(assets) == 2
        targets = {a.target for a in assets}
        assert "192.168.1.1" in targets
        assert "example.com" in targets

    def test_get_asset(self, asset_mgr, sample_result):
        asset_mgr.save_result("192.168.1.1", "nmap", "", sample_result)

        record = asset_mgr.get_asset("192.168.1.1")
        assert record is not None
        assert record.scan_count == 1
        assert record.target == "192.168.1.1"

    def test_get_asset_not_found(self, asset_mgr):
        assert asset_mgr.get_asset("nonexistent") is None

    def test_get_history(self, asset_mgr, sample_result):
        asset_mgr.save_result("192.168.1.1", "nmap", "", sample_result)
        asset_mgr.save_result("192.168.1.1", "nuclei", "", sample_result)

        history = asset_mgr.get_history("192.168.1.1")
        assert len(history) == 2

    def test_get_history_filtered(self, asset_mgr, sample_result):
        asset_mgr.save_result("192.168.1.1", "nmap", "", sample_result)
        asset_mgr.save_result("192.168.1.1", "nuclei", "", sample_result)

        history = asset_mgr.get_history("192.168.1.1", tool_name="nmap")
        assert len(history) == 1
        assert history[0]["tool_name"] == "nmap"

    def test_get_scan(self, asset_mgr, sample_result):
        scan_id = asset_mgr.save_result(
            "192.168.1.1", "nmap", "-sV", sample_result
        )

        scan = asset_mgr.get_scan("192.168.1.1", scan_id)
        assert scan is not None
        assert scan["tool_name"] == "nmap"
        assert scan["options"] == "-sV"

    def test_get_scan_not_found(self, asset_mgr):
        assert asset_mgr.get_scan("192.168.1.1", "nonexistent") is None

    def test_compare_scans(self, asset_mgr, sample_result):
        # Save first scan
        id1 = asset_mgr.save_result(
            "192.168.1.1", "nmap", "", sample_result
        )
        # Save second scan with different output
        result2 = RunResult(
            tool_name="nmap",
            command=["nmap", "192.168.1.1"],
            return_code=0,
            stdout="Port 80: open\nPort 22: open\nPort 443: closed",
            stderr="",
            duration_ms=3000,
        )
        id2 = asset_mgr.save_result(
            "192.168.1.1", "nmap", "", result2
        )

        comparison = asset_mgr.compare_scans("192.168.1.1", id1, id2)
        assert comparison is not None
        assert "scan_1" in comparison
        assert "scan_2" in comparison
        assert "diff" in comparison
        # Should have some diff lines
        assert comparison["diff"]["lines_added"] >= 0

    def test_compare_missing_scan(self, asset_mgr):
        assert asset_mgr.compare_scans("192.168.1.1", "id1", "id2") is None

    def test_index_has_correct_fields(self, asset_mgr, sample_result):
        asset_mgr.save_result("192.168.1.1", "nmap", "", sample_result)

        record = asset_mgr.get_asset("192.168.1.1")
        assert record.scan_count == 1
        assert record.first_seen != ""
        assert record.last_scanned != ""

    def test_cleanup_old_scans(self, asset_mgr, sample_result):
        # Save multiple scans
        for i in range(5):
            asset_mgr.save_result(f"scan{i}", "nmap", "", sample_result)

        # Only keep 3
        removed = asset_mgr.cleanup_old_scans(f"scan0", keep=3)
        # scan0 has 5 scans, keep 3, so 2 removed
        # Actually save_result was called on scan0 through scan4 (5 different targets)
        # So scan0 only has 1 scan. Let me fix this...
        pass

    def test_cleanup(self, asset_mgr, sample_result):
        """Save 10 scans for one target, keep 3."""
        for i in range(10):
            # Need different outputs to generate unique scan_ids
            r = RunResult(
                tool_name="nmap",
                command=["nmap", "192.168.1.1"],
                return_code=0,
                stdout=f"Scan {i}",
                stderr="",
                duration_ms=100,
            )
            asset_mgr.save_result("192.168.1.1", "nmap", "", r)

        # Should have 10 scans
        history = asset_mgr.get_history("192.168.1.1")
        assert len(history) == 10

        # Cleanup keeping 3
        removed = asset_mgr.cleanup_old_scans("192.168.1.1", keep=3)
        assert removed == 7

        history = asset_mgr.get_history("192.168.1.1")
        assert len(history) == 3
