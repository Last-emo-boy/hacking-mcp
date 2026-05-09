"""Dedicated adapter metadata for hashcat."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("hash_type", str, "", "Hash mode number, for example 0 for MD5 or 1000 for NTLM."),
        AdapterParameterSpec("attack_mode", str, "", "Attack mode number, for example 0 wordlist or 3 mask brute force."),
        AdapterParameterSpec("wordlist", str, "", "First dictionary, mask, directory, or candidate input after the hash target."),
        AdapterParameterSpec("wordlist2", str, "", "Second dictionary or candidate input for combinator/hybrid modes."),
        AdapterParameterSpec("mask", str, "", "Mask candidate pattern, for example ?a?a?a?a?a?a."),
        AdapterParameterSpec("rules", str, "", "Rules file applied to wordlists."),
        AdapterParameterSpec("rule_left", str, "", "Single rule applied to each word from the left wordlist."),
        AdapterParameterSpec("rule_right", str, "", "Single rule applied to each word from the right wordlist."),
        AdapterParameterSpec("generate_rules", int, 0, "Generate this many random rules; 0 disables."),
        AdapterParameterSpec("session", str, "", "Session name."),
        AdapterParameterSpec("restore", bool, False, "Restore a session."),
        AdapterParameterSpec("restore_disable", bool, False, "Do not write a restore file."),
        AdapterParameterSpec("restore_file_path", str, "", "Specific restore file path."),
        AdapterParameterSpec("output_file", str, "", "Recovered-hash output file."),
        AdapterParameterSpec("outfile_format", str, "", "Comma-separated outfile format numbers."),
        AdapterParameterSpec("outfile_json", bool, False, "Force JSON format in outfile output."),
        AdapterParameterSpec("outfile_autohex_disable", bool, False, "Disable $HEX[] encoding in output plains."),
        AdapterParameterSpec("separator", str, "", "Separator character for hashlists and outfile."),
        AdapterParameterSpec("show", bool, False, "Show cracked hashes from the potfile."),
        AdapterParameterSpec("left", bool, False, "Show uncracked hashes from the potfile comparison."),
        AdapterParameterSpec("username", bool, False, "Ignore usernames in the hash file."),
        AdapterParameterSpec("remove", bool, False, "Remove hashes once they are cracked."),
        AdapterParameterSpec("remove_timer", int, 0, "Seconds between input hash file updates; 0 leaves default."),
        AdapterParameterSpec("potfile_disable", bool, False, "Do not write the potfile."),
        AdapterParameterSpec("potfile_path", str, "", "Specific potfile path."),
        AdapterParameterSpec("increment", bool, False, "Enable mask increment mode."),
        AdapterParameterSpec("increment_inverse", bool, False, "Increment masks from right to left."),
        AdapterParameterSpec("increment_min", int, 0, "Mask increment start length; 0 leaves default."),
        AdapterParameterSpec("increment_max", int, 0, "Mask increment stop length; 0 leaves default."),
        AdapterParameterSpec("custom_charset1", str, "", "Custom charset ?1."),
        AdapterParameterSpec("custom_charset2", str, "", "Custom charset ?2."),
        AdapterParameterSpec("custom_charset3", str, "", "Custom charset ?3."),
        AdapterParameterSpec("custom_charset4", str, "", "Custom charset ?4."),
        AdapterParameterSpec("hex_charset", bool, False, "Treat charsets as hex."),
        AdapterParameterSpec("hex_salt", bool, False, "Treat salts as hex."),
        AdapterParameterSpec("hex_wordlist", bool, False, "Treat wordlist entries as hex."),
        AdapterParameterSpec("workload_profile", int, 0, "Workload profile 1-4; 0 leaves default."),
        AdapterParameterSpec("optimized_kernel", bool, False, "Enable optimized kernels."),
        AdapterParameterSpec("backend_devices", str, "", "Backend device IDs, comma-separated."),
        AdapterParameterSpec("opencl_device_types", str, "", "OpenCL device types, comma-separated."),
        AdapterParameterSpec("backend_info", bool, False, "Show backend API and device information."),
        AdapterParameterSpec("status", bool, False, "Enable automatic status screen updates."),
        AdapterParameterSpec("status_json", bool, False, "Use JSON format for status output."),
        AdapterParameterSpec("status_timer", int, 0, "Seconds between status updates; 0 leaves default."),
        AdapterParameterSpec("runtime", int, 0, "Abort after this many seconds; 0 leaves default."),
        AdapterParameterSpec("skip", int, 0, "Skip this many candidates from the start; 0 leaves default."),
        AdapterParameterSpec("limit", int, 0, "Limit candidates after skipped words; 0 leaves default."),
        AdapterParameterSpec("benchmark", bool, False, "Run benchmark for selected hash modes."),
        AdapterParameterSpec("benchmark_all", bool, False, "Run benchmark for all hash modes; requires benchmark."),
        AdapterParameterSpec("benchmark_min", str, "", "Minimum benchmark hash mode."),
        AdapterParameterSpec("benchmark_max", str, "", "Maximum benchmark hash mode."),
        AdapterParameterSpec("hash_info", bool, False, "Show hash-mode information."),
        AdapterParameterSpec("example_hashes", bool, False, "Alias for hash-mode information."),
        AdapterParameterSpec("identify", bool, False, "Identify possible algorithms for input hashes."),
        AdapterParameterSpec("stdout_candidates", bool, False, "Print candidates instead of cracking."),
        AdapterParameterSpec("quiet", bool, False, "Suppress output."),
        AdapterParameterSpec("force", bool, False, "Ignore warnings."),
        AdapterParameterSpec("version", bool, False, "Print version and exit."),
        AdapterParameterSpec("help", bool, False, "Print help and exit."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    benchmark_requested = (
        kwargs.get("benchmark")
        or kwargs.get("benchmark_all")
        or kwargs.get("benchmark_min") not in (None, "", False)
        or kwargs.get("benchmark_max") not in (None, "", False)
    )
    add_value(tokens, kwargs, "hash_type", "-m")
    add_value(tokens, kwargs, "attack_mode", "-a")
    add_value(tokens, kwargs, "rules", "-r")
    add_value(tokens, kwargs, "rule_left", "-j")
    add_value(tokens, kwargs, "rule_right", "-k")
    add_value(tokens, kwargs, "generate_rules", "-g")
    add_value(tokens, kwargs, "session", "--session")
    add_bool(tokens, kwargs, "restore", "--restore")
    add_bool(tokens, kwargs, "restore_disable", "--restore-disable")
    add_value(tokens, kwargs, "restore_file_path", "--restore-file-path")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "outfile_format", "--outfile-format")
    add_bool(tokens, kwargs, "outfile_json", "--outfile-json")
    add_bool(tokens, kwargs, "outfile_autohex_disable", "--outfile-autohex-disable")
    add_value(tokens, kwargs, "separator", "-p")
    add_bool(tokens, kwargs, "show", "--show")
    add_bool(tokens, kwargs, "left", "--left")
    add_bool(tokens, kwargs, "username", "--username")
    add_bool(tokens, kwargs, "remove", "--remove")
    add_value(tokens, kwargs, "remove_timer", "--remove-timer")
    add_bool(tokens, kwargs, "potfile_disable", "--potfile-disable")
    add_value(tokens, kwargs, "potfile_path", "--potfile-path")
    add_bool(tokens, kwargs, "increment", "-i")
    add_bool(tokens, kwargs, "increment_inverse", "--increment-inverse")
    add_value(tokens, kwargs, "increment_min", "--increment-min")
    add_value(tokens, kwargs, "increment_max", "--increment-max")
    add_value(tokens, kwargs, "custom_charset1", "-1")
    add_value(tokens, kwargs, "custom_charset2", "-2")
    add_value(tokens, kwargs, "custom_charset3", "-3")
    add_value(tokens, kwargs, "custom_charset4", "-4")
    add_bool(tokens, kwargs, "hex_charset", "--hex-charset")
    add_bool(tokens, kwargs, "hex_salt", "--hex-salt")
    add_bool(tokens, kwargs, "hex_wordlist", "--hex-wordlist")
    add_value(tokens, kwargs, "workload_profile", "-w")
    add_bool(tokens, kwargs, "optimized_kernel", "-O")
    add_value(tokens, kwargs, "backend_devices", "-d")
    add_value(tokens, kwargs, "opencl_device_types", "-D")
    add_bool(tokens, kwargs, "backend_info", "-I")
    add_bool(tokens, kwargs, "status", "--status")
    add_bool(tokens, kwargs, "status_json", "--status-json")
    add_value(tokens, kwargs, "status_timer", "--status-timer")
    add_value(tokens, kwargs, "runtime", "--runtime")
    add_value(tokens, kwargs, "skip", "-s")
    add_value(tokens, kwargs, "limit", "-l")
    if benchmark_requested:
        tokens.append("-b")
    add_bool(tokens, kwargs, "benchmark_all", "--benchmark-all")
    add_value(tokens, kwargs, "benchmark_min", "--benchmark-min")
    add_value(tokens, kwargs, "benchmark_max", "--benchmark-max")
    add_bool(tokens, kwargs, "hash_info", "-H")
    add_bool(tokens, kwargs, "example_hashes", "--example-hashes")
    add_bool(tokens, kwargs, "identify", "--identify")
    add_bool(tokens, kwargs, "stdout_candidates", "--stdout")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_bool(tokens, kwargs, "force", "--force")
    add_bool(tokens, kwargs, "version", "--version")
    add_bool(tokens, kwargs, "help", "--help")

    for key in ("wordlist", "wordlist2", "mask"):
        value = kwargs.get(key)
        if value:
            tokens.append(str(value))

    return tokens
