"""Dedicated adapter metadata for John the Ripper."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("single", bool, False, "Enable single crack mode with default rules."),
        AdapterParameterSpec("single_rules", str, "", "Single crack rule section or immediate rule."),
        AdapterParameterSpec("single_seed", str, "", "Static seed words for single mode."),
        AdapterParameterSpec("single_wordlist", str, "", "Short wordlist with static seed words for single mode."),
        AdapterParameterSpec("wordlist", str, "", "Wordlist file for wordlist mode."),
        AdapterParameterSpec("wordlist_default", bool, False, "Enable wordlist mode using john.conf default wordlist."),
        AdapterParameterSpec("stdin", bool, False, "Read wordlist candidates from stdin."),
        AdapterParameterSpec("pipe", bool, False, "Read candidates from a pipe while allowing rules."),
        AdapterParameterSpec("rules", str, "", "Rules section or immediate rule for wordlist mode."),
        AdapterParameterSpec("rules_default", bool, False, "Enable default wordlist rules."),
        AdapterParameterSpec("rules_stack", str, "", "Stacked rules section or immediate rule."),
        AdapterParameterSpec("rules_skip_nop", bool, False, "Skip no-op rules."),
        AdapterParameterSpec("incremental", str, "", "Incremental mode name or charset file."),
        AdapterParameterSpec("incremental_default", bool, False, "Enable default incremental mode."),
        AdapterParameterSpec("mask", str, "", "Mask mode expression."),
        AdapterParameterSpec("custom_charset1", str, "", "Custom mask charset ?1."),
        AdapterParameterSpec("custom_charset2", str, "", "Custom mask charset ?2."),
        AdapterParameterSpec("custom_charset3", str, "", "Custom mask charset ?3."),
        AdapterParameterSpec("custom_charset4", str, "", "Custom mask charset ?4."),
        AdapterParameterSpec("markov", str, "", "Markov mode parameter."),
        AdapterParameterSpec("external", str, "", "External mode or word filter."),
        AdapterParameterSpec("stdout_candidates", bool, False, "Output candidate passwords instead of cracking."),
        AdapterParameterSpec("stdout_length", int, 0, "Candidate stdout significant length; 0 leaves default."),
        AdapterParameterSpec("restore", bool, False, "Restore default interrupted session."),
        AdapterParameterSpec("restore_session", str, "", "Restore a named interrupted session."),
        AdapterParameterSpec("session", str, "", "Name a new cracking session."),
        AdapterParameterSpec("status", bool, False, "Print status for the default session."),
        AdapterParameterSpec("status_session", str, "", "Print status for a named session."),
        AdapterParameterSpec("show", bool, False, "Show cracked passwords."),
        AdapterParameterSpec("show_mode", str, "", "Show variant: left, formats, types, or invalid."),
        AdapterParameterSpec("make_charset", str, "", "Generate a charset file."),
        AdapterParameterSpec("test", bool, False, "Run tests and benchmarks."),
        AdapterParameterSpec("test_time", str, "", "Benchmark seconds per format; 0 runs a quick self-test."),
        AdapterParameterSpec("stress_test", bool, False, "Run continuous self-test."),
        AdapterParameterSpec("no_mask", bool, False, "Benchmark using regular test vectors instead of mask mode."),
        AdapterParameterSpec("skip_self_tests", bool, False, "Skip self-tests."),
        AdapterParameterSpec("users", str, "", "Load only matching users or UIDs."),
        AdapterParameterSpec("groups", str, "", "Load only matching groups."),
        AdapterParameterSpec("shells", str, "", "Load only matching shells."),
        AdapterParameterSpec("salts", str, "", "Salt selection expression."),
        AdapterParameterSpec("costs", str, "", "Tunable cost selection expression."),
        AdapterParameterSpec("format", str, "", "Hash format name, class, wildcard, or include/exclude list."),
        AdapterParameterSpec("subformat", str, "", "Subformat selector for formats that support it."),
        AdapterParameterSpec("pot", str, "", "Pot file path."),
        AdapterParameterSpec("list_option", str, "", "Capability listing selector, for example formats or help."),
        AdapterParameterSpec("config", str, "", "Configuration file path."),
        AdapterParameterSpec("field_separator_char", str, "", "Input/pot field separator character."),
        AdapterParameterSpec("min_length", int, 0, "Minimum candidate length; 0 leaves default."),
        AdapterParameterSpec("max_length", int, 0, "Maximum candidate length; 0 leaves default."),
        AdapterParameterSpec("length", int, 0, "Exact candidate length; 0 leaves default."),
        AdapterParameterSpec("max_run_time", str, "", "Graceful runtime limit in seconds; may be negative."),
        AdapterParameterSpec("max_candidates", str, "", "Graceful candidate limit; may be negative."),
        AdapterParameterSpec("progress_every", int, 0, "Emit status every N seconds; 0 leaves default."),
        AdapterParameterSpec("fork", int, 0, "Fork N processes; 0 leaves default."),
        AdapterParameterSpec("node", str, "", "Distributed node range, for example 1-4/16."),
        AdapterParameterSpec("devices", str, "", "Accelerator device list."),
        AdapterParameterSpec("lws", str, "", "OpenCL local work size."),
        AdapterParameterSpec("gws", str, "", "OpenCL global work size."),
        AdapterParameterSpec("verbosity", int, 0, "Verbosity level; 0 leaves default."),
        AdapterParameterSpec("no_log", bool, False, "Disable log file."),
        AdapterParameterSpec("log_stderr", bool, False, "Log to stderr."),
        AdapterParameterSpec("crack_status", bool, False, "Show status on every crack."),
        AdapterParameterSpec("keep_guessing", bool, False, "Search for alternative plaintexts."),
        AdapterParameterSpec("reject_printable", bool, False, "Reject printable binary hashes."),
        AdapterParameterSpec("force_tty", bool, False, "Force terminal status/quit handling."),
        AdapterParameterSpec("help", bool, False, "Print usage summary."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    _add_optional(tokens, kwargs, "single", "single_rules", "--single")
    add_value(tokens, kwargs, "single_seed", "--single-seed")
    add_value(tokens, kwargs, "single_wordlist", "--single-wordlist")
    if kwargs.get("wordlist"):
        tokens.append(f"--wordlist={kwargs['wordlist']}")
    elif kwargs.get("wordlist_default"):
        tokens.append("--wordlist")
    add_bool(tokens, kwargs, "stdin", "--stdin")
    add_bool(tokens, kwargs, "pipe", "--pipe")
    _add_optional(tokens, kwargs, "rules_default", "rules", "--rules")
    add_value(tokens, kwargs, "rules_stack", "--rules-stack")
    add_bool(tokens, kwargs, "rules_skip_nop", "--rules-skip-nop")
    _add_optional(tokens, kwargs, "incremental_default", "incremental", "--incremental")
    add_value(tokens, kwargs, "mask", "--mask")
    add_value(tokens, kwargs, "custom_charset1", "--1")
    add_value(tokens, kwargs, "custom_charset2", "--2")
    add_value(tokens, kwargs, "custom_charset3", "--3")
    add_value(tokens, kwargs, "custom_charset4", "--4")
    add_value(tokens, kwargs, "markov", "--markov")
    add_value(tokens, kwargs, "external", "--external")
    _add_optional(tokens, kwargs, "stdout_candidates", "stdout_length", "--stdout")
    _add_optional(tokens, kwargs, "restore", "restore_session", "--restore")
    add_value(tokens, kwargs, "session", "--session")
    _add_optional(tokens, kwargs, "status", "status_session", "--status")
    _add_optional(tokens, kwargs, "show", "show_mode", "--show")
    add_value(tokens, kwargs, "make_charset", "--make-charset")
    _add_optional(tokens, kwargs, "test", "test_time", "--test")
    add_bool(tokens, kwargs, "stress_test", "--stress-test")
    add_bool(tokens, kwargs, "no_mask", "--no-mask")
    add_bool(tokens, kwargs, "skip_self_tests", "--skip-self-tests")
    add_value(tokens, kwargs, "users", "--users")
    add_value(tokens, kwargs, "groups", "--groups")
    add_value(tokens, kwargs, "shells", "--shells")
    add_value(tokens, kwargs, "salts", "--salts")
    add_value(tokens, kwargs, "costs", "--costs")
    add_value(tokens, kwargs, "format", "--format")
    add_value(tokens, kwargs, "subformat", "--subformat")
    add_value(tokens, kwargs, "pot", "--pot")
    add_value(tokens, kwargs, "list_option", "--list")
    add_value(tokens, kwargs, "config", "--config")
    add_value(tokens, kwargs, "field_separator_char", "--field-separator-char")
    add_value(tokens, kwargs, "min_length", "--min-length")
    add_value(tokens, kwargs, "max_length", "--max-length")
    add_value(tokens, kwargs, "length", "--length")
    add_value(tokens, kwargs, "max_run_time", "--max-run-time")
    add_value(tokens, kwargs, "max_candidates", "--max-candidates")
    add_value(tokens, kwargs, "progress_every", "--progress-every")
    add_value(tokens, kwargs, "fork", "--fork")
    add_value(tokens, kwargs, "node", "--node")
    add_value(tokens, kwargs, "devices", "--devices")
    add_value(tokens, kwargs, "lws", "--lws")
    add_value(tokens, kwargs, "gws", "--gws")
    add_value(tokens, kwargs, "verbosity", "--verbosity")
    add_bool(tokens, kwargs, "no_log", "--no-log")
    add_bool(tokens, kwargs, "log_stderr", "--log-stderr")
    add_bool(tokens, kwargs, "crack_status", "--crack-status")
    add_bool(tokens, kwargs, "keep_guessing", "--keep-guessing")
    add_bool(tokens, kwargs, "reject_printable", "--reject-printable")
    add_bool(tokens, kwargs, "force_tty", "--force-tty")
    add_bool(tokens, kwargs, "help", "--help")
    return tokens


def _add_optional(
    tokens: list[str],
    kwargs: dict,
    bool_key: str,
    value_key: str,
    flag: str,
) -> None:
    value = kwargs.get(value_key)
    if value not in (None, "", 0, False):
        tokens.append(f"{flag}={value}")
    elif kwargs.get(bool_key):
        tokens.append(flag)
