"""Dedicated adapter metadata for pixiewps."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters():
    return [
        AdapterParameterSpec("pke", str, "", "Enrollee public key."),
        AdapterParameterSpec("pkr", str, "", "Registrar public key."),
        AdapterParameterSpec("e_hash1", str, "", "Enrollee hash 1."),
        AdapterParameterSpec("e_hash2", str, "", "Enrollee hash 2."),
        AdapterParameterSpec("authkey", str, "", "Authentication session key."),
        AdapterParameterSpec("e_nonce", str, "", "Enrollee nonce."),
        AdapterParameterSpec("r_nonce", str, "", "Registrar nonce."),
        AdapterParameterSpec("e_bssid", str, "", "Enrollee BSSID."),
        AdapterParameterSpec("verbosity", int, 0, "Verbosity level 1-3; 0 leaves upstream default."),
        AdapterParameterSpec("output_file", str, "", "Write output to file."),
        AdapterParameterSpec("jobs", int, 0, "Number of parallel threads; 0 leaves upstream default."),
        AdapterParameterSpec("mode", str, "", "Mode selection, comma-separated."),
        AdapterParameterSpec("start", str, "", "Starting date for mode 3, for example mm/yyyy."),
        AdapterParameterSpec("end", str, "", "Ending date for mode 3, for example mm/yyyy."),
        AdapterParameterSpec("force", bool, False, "Bruteforce full range for mode 3."),
        AdapterParameterSpec("m7_enc", str, "", "Recover encrypted settings from M7 for mode 3."),
        AdapterParameterSpec("m5_enc", str, "", "Recover secret nonce from M5 for mode 3."),
        AdapterParameterSpec("help", bool, False, "Show verbose help."),
        AdapterParameterSpec("version", bool, False, "Show version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "pke", "--pke")
    add_value(tokens, kwargs, "pkr", "--pkr")
    add_value(tokens, kwargs, "e_hash1", "--e-hash1")
    add_value(tokens, kwargs, "e_hash2", "--e-hash2")
    add_value(tokens, kwargs, "authkey", "--authkey")
    add_value(tokens, kwargs, "e_nonce", "--e-nonce")
    add_value(tokens, kwargs, "r_nonce", "--r-nonce")
    add_value(tokens, kwargs, "e_bssid", "--e-bssid")
    add_value(tokens, kwargs, "verbosity", "--verbosity")
    add_value(tokens, kwargs, "output_file", "--output")
    add_value(tokens, kwargs, "jobs", "--jobs")
    add_value(tokens, kwargs, "mode", "--mode")
    add_value(tokens, kwargs, "start", "--start")
    add_value(tokens, kwargs, "end", "--end")
    add_bool(tokens, kwargs, "force", "--force")
    add_value(tokens, kwargs, "m7_enc", "--m7-enc")
    add_value(tokens, kwargs, "m5_enc", "--m5-enc")
    add_bool(tokens, kwargs, "help", "--help")
    add_bool(tokens, kwargs, "version", "--version")
    return tokens
