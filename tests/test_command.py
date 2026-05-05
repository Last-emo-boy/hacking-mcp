"""Tests for command parsing and building."""

import pytest
from hacking_mcp.command import (
    ParsedCommand,
    parse_command,
    build_native_command,
    build_wsl_command,
    build_command,
    needs_sudo,
)
from hacking_mcp.environment import ExecBackend


class TestParseCommand:
    def test_simple_binary_with_target(self):
        parsed = parse_command("nmap {target}", "192.168.1.1")
        assert parsed.executable == "nmap"
        assert parsed.args == ["192.168.1.1"]
        assert parsed.sudo is False
        assert parsed.chdir is None

    def test_simple_binary_without_target(self):
        parsed = parse_command("nmap {target}", "")
        assert parsed.executable == "nmap"
        assert "{target}" in parsed.args or parsed.args == ["{target}"]

    def test_binary_with_options(self):
        parsed = parse_command("nmap -sV -p 80 {target}", "10.0.0.1")
        assert parsed.executable == "nmap"
        assert "-sV" in parsed.args
        assert "-p" in parsed.args
        assert "80" in parsed.args
        assert "10.0.0.1" in parsed.args

    def test_sudo_prefix(self):
        parsed = parse_command("sudo nmap -O -Pn {target}", "10.0.0.1")
        assert parsed.sudo is True
        assert parsed.executable == "nmap"
        assert parsed.args == ["-O", "-Pn", "10.0.0.1"]

    def test_cd_with_sudo(self):
        parsed = parse_command("cd Dracnmap && sudo ./dracnmap-v2.2.sh", "")
        assert parsed.chdir == "Dracnmap"
        assert parsed.sudo is True
        assert parsed.executable == "./dracnmap-v2.2.sh"
        assert parsed.args == []

    def test_cd_with_python(self):
        parsed = parse_command("cd sherlock && python3 sherlock {target}", "user123")
        assert parsed.chdir == "sherlock"
        assert parsed.sudo is False
        assert parsed.executable == "python3"
        assert parsed.args == ["sherlock", "user123"]

    def test_cd_with_sudo_and_python(self):
        parsed = parse_command(
            "cd commix && sudo python3 commix.py --url {target}",
            "https://example.com"
        )
        assert parsed.chdir == "commix"
        assert parsed.sudo is True
        assert parsed.executable == "python3"
        assert "commix.py" in parsed.args
        assert "--url" in parsed.args
        assert "https://example.com" in parsed.args

    def test_subcommand_binary(self):
        parsed = parse_command("amass enum -d {target}", "example.com")
        assert parsed.executable == "amass"
        assert parsed.args == ["enum", "-d", "example.com"]

    def test_local_script(self):
        parsed = parse_command("./linpeas.sh", "")
        assert parsed.executable == "./linpeas.sh"
        assert parsed.args == []
        assert parsed.chdir is None

    def test_empty_command(self):
        parsed = parse_command("", "")
        assert parsed.executable == ""
        assert parsed.args == []
        assert parsed.raw == ""

    def test_raw_preserved(self):
        parsed = parse_command("nmap {target}", "1.2.3.4")
        assert parsed.raw == "nmap {target}"

    def test_hashcat_help(self):
        parsed = parse_command("hashcat --help", "")
        assert parsed.executable == "hashcat"
        assert parsed.args == ["--help"]


class TestBuildNativeCommand:
    def test_simple_binary(self):
        parsed = parse_command("nmap {target}", "192.168.1.1")
        cmd = build_native_command(parsed)
        assert cmd == ["nmap", "192.168.1.1"]

    def test_sudo_command(self):
        parsed = parse_command("sudo nmap -O -Pn {target}", "10.0.0.1")
        cmd = build_native_command(parsed)
        assert cmd == ["sudo", "nmap", "-O", "-Pn", "10.0.0.1"]

    def test_cd_ignored_in_native(self):
        """Native commands don't include cd; chdir is handled by runner cwd."""
        parsed = parse_command("cd foo && python3 bar.py {target}", "arg1")
        cmd = build_native_command(parsed)
        assert "cd" not in cmd
        assert "foo" not in cmd
        assert cmd == ["python3", "bar.py", "arg1"]

    def test_empty_returns_empty(self):
        parsed = parse_command("", "")
        cmd = build_native_command(parsed)
        assert cmd == []


class TestBuildWslCommand:
    def test_simple_binary_wsl(self):
        parsed = parse_command("nmap {target}", "192.168.1.1")
        cmd = build_wsl_command(parsed)
        assert cmd[:3] == ["wsl", "bash", "-c"]
        assert "nmap 192.168.1.1" in cmd[3]

    def test_cd_and_sudo_wsl(self):
        parsed = parse_command("cd Dracnmap && sudo ./dracnmap-v2.2.sh", "")
        cmd = build_wsl_command(parsed)
        assert cmd[:3] == ["wsl", "bash", "-c"]
        bash_cmd = cmd[3]
        assert bash_cmd.startswith("cd Dracnmap")
        assert "sudo" in bash_cmd
        assert "./dracnmap-v2.2.sh" in bash_cmd
        # Must NOT have "sudo &&" — only cd should be &&-separated
        assert "sudo &&" not in bash_cmd

    def test_cd_python_wsl(self):
        parsed = parse_command("cd sherlock && python3 sherlock {target}", "user123")
        cmd = build_wsl_command(parsed)
        bash_cmd = cmd[3]
        assert bash_cmd == "cd sherlock && python3 sherlock user123"

    def test_sudo_wsl(self):
        parsed = parse_command("sudo nmap -O -Pn {target}", "10.0.0.1")
        cmd = build_wsl_command(parsed)
        bash_cmd = cmd[3]
        assert bash_cmd == "sudo nmap -O -Pn 10.0.0.1"

    def test_with_distro(self):
        parsed = parse_command("nmap {target}", "192.168.1.1")
        cmd = build_wsl_command(parsed, distro="Ubuntu-22.04")
        assert cmd[:2] == ["wsl", "-d"]
        assert cmd[2] == "Ubuntu-22.04"
        assert cmd[3:5] == ["bash", "-c"]

    def test_empty_returns_empty(self):
        parsed = parse_command("", "")
        cmd = build_wsl_command(parsed)
        assert cmd == []


class TestBuildCommand:
    def test_native_backend(self):
        parsed = parse_command("nmap {target}", "192.168.1.1")
        cmd = build_command(parsed, ExecBackend.NATIVE)
        assert cmd == ["nmap", "192.168.1.1"]

    def test_wsl2_backend(self):
        parsed = parse_command("nmap {target}", "192.168.1.1")
        cmd = build_command(parsed, ExecBackend.WSL2)
        assert cmd[:3] == ["wsl", "bash", "-c"]


class TestNeedsSudo:
    def test_with_sudo(self):
        parsed = parse_command("sudo nmap -O {target}", "1.2.3.4")
        assert needs_sudo(parsed) is True

    def test_without_sudo(self):
        parsed = parse_command("nmap {target}", "1.2.3.4")
        assert needs_sudo(parsed) is False
