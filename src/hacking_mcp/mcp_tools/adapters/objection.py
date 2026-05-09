"""Dedicated adapter metadata for Objection."""

import shlex

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("command", str, "start", "Objection subcommand: start, run, api, version, patchapk, patchipa, or signapk."),
        AdapterParameterSpec("network", bool, False, "Connect using a network connection instead of USB."),
        AdapterParameterSpec("local", bool, False, "Connect using a local connection, for example iOS Simulator."),
        AdapterParameterSpec("host", str, "", "Frida server host for network connections."),
        AdapterParameterSpec("port", int, 0, "Frida server port; 0 leaves Objection default."),
        AdapterParameterSpec("api_host", str, "", "Objection API bind host."),
        AdapterParameterSpec("api_port", int, 0, "Objection API bind port; 0 leaves default."),
        AdapterParameterSpec("name", str, "", "Name or bundle identifier to attach to; target is used when empty."),
        AdapterParameterSpec("serial", str, "", "Device serial to connect to."),
        AdapterParameterSpec("debug", bool, False, "Enable Objection debug mode with verbose output."),
        AdapterParameterSpec("spawn", bool, False, "Spawn the target."),
        AdapterParameterSpec("no_pause", bool, False, "Resume the target immediately."),
        AdapterParameterSpec("foremost", bool, False, "Use the current foremost application."),
        AdapterParameterSpec("debugger", bool, False, "Enable the Chrome debug port."),
        AdapterParameterSpec("uid", int, 0, "Android uid to run as; 0 leaves unset."),
        AdapterParameterSpec("plugin_folder", str, "", "Folder to load Objection plugins from for start/explore."),
        AdapterParameterSpec("quiet", bool, False, "Run start/explore in quiet mode."),
        AdapterParameterSpec("startup_command", str, "", "Command to run before REPL device polling."),
        AdapterParameterSpec("file_commands", str, "", "File containing Objection commands separated by newlines."),
        AdapterParameterSpec("startup_script", str, "", "Script to import and run before REPL device polling."),
        AdapterParameterSpec("enable_api", bool, False, "Start the Objection API server during start/explore."),
        AdapterParameterSpec("hook_debug", bool, False, "Print compiled hooks during the run subcommand."),
        AdapterParameterSpec("runtime_command", str, "", "Single Objection REPL command used by the run subcommand."),
        AdapterParameterSpec("source", str, "", "Source APK/IPA path for patchapk or patchipa; target is used when empty."),
        AdapterParameterSpec("architecture", str, "", "Patched APK architecture."),
        AdapterParameterSpec("gadget_version", str, "", "Frida Gadget version to use."),
        AdapterParameterSpec("codesign_signature", str, "", "iOS codesigning identity for patchipa."),
        AdapterParameterSpec("provision_file", str, "", "iOS .mobileprovision file for patchipa."),
        AdapterParameterSpec("binary_name", str, "", "Mach-O binary name in the IPA."),
        AdapterParameterSpec("skip_cleanup", bool, False, "Do not clean temporary patching/signing files."),
        AdapterParameterSpec("pause", bool, False, "Pause patcher before rebuilding the APK/IPA."),
        AdapterParameterSpec("unzip_unicode", bool, False, "Unzip IPA files containing Unicode characters."),
        AdapterParameterSpec("enable_debug", bool, False, "Set android:debuggable to true while patching APK."),
        AdapterParameterSpec("network_security_config", bool, False, "Add Android network security config for user CAs."),
        AdapterParameterSpec("skip_resources", bool, False, "Skip APK resource decoding."),
        AdapterParameterSpec("skip_signing", bool, False, "Skip signing patched APK."),
        AdapterParameterSpec("target_class", str, "", "Android class to patch."),
        AdapterParameterSpec("use_aapt2", bool, False, "Use aapt2 during APK processing."),
        AdapterParameterSpec("gadget_config", str, "", "Frida Gadget configuration file."),
        AdapterParameterSpec("script_source", str, "", "Script file used with Frida Gadget path config."),
        AdapterParameterSpec("ignore_nativelibs", bool, False, "Do not change extractNativeLibs in AndroidManifest.xml."),
        AdapterParameterSpec("manifest", str, "", "Decoded AndroidManifest.xml path."),
        AdapterParameterSpec("only_main_classes", bool, False, "Only patch classes in the main dex file."),
        AdapterParameterSpec("fix_concurrency_to", int, 0, "Thread count for repackaging; 0 leaves unset."),
        AdapterParameterSpec("bundle_id", str, "", "Bundle identifier to set when codesigning IPA."),
        AdapterParameterSpec("sources", str, "", "APK paths for signapk, parsed like shell words."),
    ]


def build_options(kwargs: dict) -> list[str]:
    command = _command(kwargs)
    tokens: list[str] = []
    _add_global_options(tokens, kwargs, command)
    tokens.append(command)
    if command in {"start", "explore"}:
        _add_start_options(tokens, kwargs)
    elif command == "run":
        _add_run_options(tokens, kwargs)
    elif command == "patchapk":
        _add_patchapk_options(tokens, kwargs)
    elif command == "patchipa":
        _add_patchipa_options(tokens, kwargs)
    elif command == "signapk":
        _add_signapk_args(tokens, kwargs)
    return tokens


def _command(kwargs: dict) -> str:
    return str(kwargs.get("command") or "start").strip() or "start"


def _target(kwargs: dict) -> str:
    return str(kwargs.get("target") or "").strip()


def _add_global_options(tokens: list[str], kwargs: dict, command: str) -> None:
    add_bool(tokens, kwargs, "network", "--network")
    add_bool(tokens, kwargs, "local", "--local")
    add_value(tokens, kwargs, "host", "--host")
    add_value(tokens, kwargs, "port", "--port")
    add_value(tokens, kwargs, "api_host", "--api-host")
    add_value(tokens, kwargs, "api_port", "--api-port")
    name = str(kwargs.get("name") or "").strip()
    if not name and command in {"api", "start", "explore", "run"}:
        name = _target(kwargs)
    if name:
        tokens.extend(["--name", name])
    add_value(tokens, kwargs, "serial", "--serial")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "spawn", "--spawn")
    add_bool(tokens, kwargs, "no_pause", "--no-pause")
    add_bool(tokens, kwargs, "foremost", "--foremost")
    add_bool(tokens, kwargs, "debugger", "--debugger")
    add_value(tokens, kwargs, "uid", "--uid")


def _add_start_options(tokens: list[str], kwargs: dict) -> None:
    add_value(tokens, kwargs, "plugin_folder", "--plugin-folder")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_value(tokens, kwargs, "startup_command", "--startup-command")
    add_value(tokens, kwargs, "file_commands", "--file-commands")
    add_value(tokens, kwargs, "startup_script", "--startup-script")
    add_bool(tokens, kwargs, "enable_api", "--enable-api")


def _add_run_options(tokens: list[str], kwargs: dict) -> None:
    add_bool(tokens, kwargs, "hook_debug", "--hook-debug")
    runtime_command = str(kwargs.get("runtime_command") or "").strip()
    if runtime_command:
        tokens.append(runtime_command)


def _add_patchapk_options(tokens: list[str], kwargs: dict) -> None:
    _add_source(tokens, kwargs)
    add_value(tokens, kwargs, "architecture", "--architecture")
    add_value(tokens, kwargs, "gadget_version", "--gadget-version")
    add_bool(tokens, kwargs, "pause", "--pause")
    add_bool(tokens, kwargs, "skip_cleanup", "--skip-cleanup")
    add_bool(tokens, kwargs, "enable_debug", "--enable-debug")
    add_bool(tokens, kwargs, "network_security_config", "--network-security-config")
    add_bool(tokens, kwargs, "skip_resources", "--skip-resources")
    add_bool(tokens, kwargs, "skip_signing", "--skip-signing")
    add_value(tokens, kwargs, "target_class", "--target-class")
    add_bool(tokens, kwargs, "use_aapt2", "--use-aapt2")
    add_value(tokens, kwargs, "gadget_config", "--gadget-config")
    add_value(tokens, kwargs, "script_source", "--script-source")
    add_bool(tokens, kwargs, "ignore_nativelibs", "--ignore-nativelibs")
    add_value(tokens, kwargs, "manifest", "--manifest")
    add_bool(tokens, kwargs, "only_main_classes", "--only-main-classes")
    add_value(tokens, kwargs, "fix_concurrency_to", "--fix-concurrency-to")


def _add_patchipa_options(tokens: list[str], kwargs: dict) -> None:
    _add_source(tokens, kwargs)
    add_value(tokens, kwargs, "gadget_version", "--gadget-version")
    add_value(tokens, kwargs, "codesign_signature", "--codesign-signature")
    add_value(tokens, kwargs, "provision_file", "--provision-file")
    add_value(tokens, kwargs, "binary_name", "--binary-name")
    add_bool(tokens, kwargs, "skip_cleanup", "--skip-cleanup")
    add_bool(tokens, kwargs, "pause", "--pause")
    add_bool(tokens, kwargs, "unzip_unicode", "--unzip-unicode")
    add_value(tokens, kwargs, "gadget_config", "--gadget-config")
    add_value(tokens, kwargs, "script_source", "--script-source")
    add_value(tokens, kwargs, "bundle_id", "--bundle-id")


def _add_source(tokens: list[str], kwargs: dict) -> None:
    source = str(kwargs.get("source") or "").strip() or _target(kwargs)
    if source:
        tokens.extend(["--source", source])


def _add_signapk_args(tokens: list[str], kwargs: dict) -> None:
    sources = str(kwargs.get("sources") or "").strip() or _target(kwargs)
    if not sources:
        return
    try:
        tokens.extend(shlex.split(sources))
    except ValueError:
        tokens.append(sources)
