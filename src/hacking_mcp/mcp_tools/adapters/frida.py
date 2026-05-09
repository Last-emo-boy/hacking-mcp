"""Dedicated adapter metadata for Frida CLI."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("device_id", str, "", "Connect to device with the given ID."),
        AdapterParameterSpec("usb", bool, False, "Connect to a USB device."),
        AdapterParameterSpec("remote", bool, False, "Connect to a remote frida-server."),
        AdapterParameterSpec("host", str, "", "Connect to remote frida-server on HOST."),
        AdapterParameterSpec("certificate", str, "", "TLS certificate expected from HOST."),
        AdapterParameterSpec("origin", str, "", "Origin header for a remote server connection."),
        AdapterParameterSpec("token", str, "", "Authentication token for HOST."),
        AdapterParameterSpec("keepalive_interval", int, -1, "Keepalive interval in seconds; -1 leaves default, 0 disables."),
        AdapterParameterSpec("device_option", str, "", "Backend-specific device option such as key=(type)value."),
        AdapterParameterSpec("p2p", bool, False, "Establish a peer-to-peer connection with target."),
        AdapterParameterSpec("stun_server", str, "", "STUN server address used with --p2p."),
        AdapterParameterSpec("relay", str, "", "Relay descriptor used with --p2p."),
        AdapterParameterSpec("spawn_file", str, "", "Spawn FILE before attaching."),
        AdapterParameterSpec("attach_frontmost", bool, False, "Attach to the frontmost application."),
        AdapterParameterSpec("attach_name", str, "", "Attach to process NAME."),
        AdapterParameterSpec("attach_identifier", str, "", "Attach to application identifier."),
        AdapterParameterSpec("attach_pid", int, 0, "Attach to process PID; 0 leaves unset."),
        AdapterParameterSpec("await_spawn", str, "", "Await spawn matching NAME before attaching."),
        AdapterParameterSpec("stdio", str, "", "Stdio behavior when spawning: inherit or pipe."),
        AdapterParameterSpec("aux", str, "", "Aux option when spawning, such as uid=(int)42."),
        AdapterParameterSpec("realm", str, "", "Realm to attach in: native or emulated."),
        AdapterParameterSpec("runtime", str, "", "Script runtime to use: qjs or v8."),
        AdapterParameterSpec("debug", bool, False, "Enable the Node.js-compatible script debugger."),
        AdapterParameterSpec("squelch_crash", bool, False, "Do not dump crash reports to console."),
        AdapterParameterSpec("options_file", str, "", "Text file containing additional command-line options."),
        AdapterParameterSpec("load_script", str, "", "Load SCRIPT before entering the REPL."),
        AdapterParameterSpec("parameters_json", str, "", "JSON parameters passed to loaded scripts."),
        AdapterParameterSpec("cmodule", str, "", "Load CMODULE."),
        AdapterParameterSpec("toolchain", str, "", "CModule toolchain: any, internal, or external."),
        AdapterParameterSpec("codeshare", str, "", "Load CODESHARE_URI."),
        AdapterParameterSpec("eval_code", str, "", "Evaluate CODE before entering the REPL."),
        AdapterParameterSpec("quiet", bool, False, "Quiet mode; no prompt and quit after -l and -e."),
        AdapterParameterSpec("timeout", int, 0, "Seconds to wait before giving up; 0 leaves default."),
        AdapterParameterSpec("pause", bool, False, "Leave main thread paused after spawning program."),
        AdapterParameterSpec("output_file", str, "", "Output log file."),
        AdapterParameterSpec("eternalize", bool, False, "Eternalize the script before exit."),
        AdapterParameterSpec("exit_on_error", bool, False, "Exit with code 1 after script exceptions."),
        AdapterParameterSpec("kill_on_exit", bool, False, "Kill spawned program when Frida exits."),
        AdapterParameterSpec("auto_perform", bool, False, "Wrap entered code with Java.perform."),
        AdapterParameterSpec("auto_reload", bool, False, "Enable auto reload of provided scripts and C module."),
        AdapterParameterSpec("no_auto_reload", bool, False, "Disable auto reload of provided scripts and C module."),
        AdapterParameterSpec("version", bool, False, "Print Frida version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "device_id", "-D")
    add_bool(tokens, kwargs, "usb", "-U")
    add_bool(tokens, kwargs, "remote", "-R")
    add_value(tokens, kwargs, "host", "-H")
    add_value(tokens, kwargs, "certificate", "--certificate")
    add_value(tokens, kwargs, "origin", "--origin")
    add_value(tokens, kwargs, "token", "--token")
    _add_keepalive_interval(tokens, kwargs)
    add_value(tokens, kwargs, "device_option", "--device-option")
    add_bool(tokens, kwargs, "p2p", "--p2p")
    add_value(tokens, kwargs, "stun_server", "--stun-server")
    add_value(tokens, kwargs, "relay", "--relay")
    add_value(tokens, kwargs, "spawn_file", "-f")
    add_bool(tokens, kwargs, "attach_frontmost", "-F")
    add_value(tokens, kwargs, "attach_name", "-n")
    add_value(tokens, kwargs, "attach_identifier", "-N")
    add_value(tokens, kwargs, "attach_pid", "-p")
    add_value(tokens, kwargs, "await_spawn", "-W")
    add_value(tokens, kwargs, "stdio", "--stdio")
    add_value(tokens, kwargs, "aux", "--aux")
    add_value(tokens, kwargs, "realm", "--realm")
    add_value(tokens, kwargs, "runtime", "--runtime")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "squelch_crash", "--squelch-crash")
    add_value(tokens, kwargs, "options_file", "-O")
    add_value(tokens, kwargs, "load_script", "-l")
    add_value(tokens, kwargs, "parameters_json", "-P")
    add_value(tokens, kwargs, "cmodule", "-C")
    add_value(tokens, kwargs, "toolchain", "--toolchain")
    add_value(tokens, kwargs, "codeshare", "-c")
    add_value(tokens, kwargs, "eval_code", "-e")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_value(tokens, kwargs, "timeout", "-t")
    add_bool(tokens, kwargs, "pause", "--pause")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "eternalize", "--eternalize")
    add_bool(tokens, kwargs, "exit_on_error", "--exit-on-error")
    add_bool(tokens, kwargs, "kill_on_exit", "--kill-on-exit")
    add_bool(tokens, kwargs, "auto_perform", "--auto-perform")
    add_bool(tokens, kwargs, "auto_reload", "--auto-reload")
    add_bool(tokens, kwargs, "no_auto_reload", "--no-auto-reload")
    add_bool(tokens, kwargs, "version", "--version")
    return tokens


def _add_keepalive_interval(tokens: list[str], kwargs: dict) -> None:
    value = kwargs.get("keepalive_interval", -1)
    if value in (None, "", -1):
        return
    tokens.extend(["--keepalive-interval", str(value)])
