"""Dedicated adapter metadata for radare2."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("arch", str, "", "Set asm.arch."),
        AdapterParameterSpec("bits", str, "", "Set asm.bits."),
        AdapterParameterSpec("base_addr", str, "", "Set base address for PIE binaries."),
        AdapterParameterSpec("map_addr", str, "", "Map file at the given load address."),
        AdapterParameterSpec("seek_addr", str, "", "Initial seek address."),
        AdapterParameterSpec("command", str, "", "Radare command to execute with -c."),
        AdapterParameterSpec("eval_config", str, "", "Evaluate config variable as key=value."),
        AdapterParameterSpec("script", str, "", "Run r2 script, rlang program, or load plugin after open."),
        AdapterParameterSpec("pre_script", str, "", "Run script before the file is opened."),
        AdapterParameterSpec("project", str, "", "Use or load project name."),
        AdapterParameterSpec("patch_file", str, "", "Apply rapatch file and quit."),
        AdapterParameterSpec("rarun_profile", str, "", "Load rarun2 profile."),
        AdapterParameterSpec("rarun_directive", str, "", "Custom rarun2 directive."),
        AdapterParameterSpec("debug", bool, False, "Debug the executable or running process."),
        AdapterParameterSpec("debug_backend", str, "", "Enable debug mode with backend."),
        AdapterParameterSpec("analyze", bool, False, "Run aaa to analyze all referenced code."),
        AdapterParameterSpec("write", bool, False, "Open file in write mode."),
        AdapterParameterSpec("quiet", bool, False, "Quiet mode with no prompt."),
        AdapterParameterSpec("quit_after_commands", bool, False, "Quit after running all -c and -i commands."),
        AdapterParameterSpec("quick_quiet", bool, False, "Quiet mode with quickLeak=true."),
        AdapterParameterSpec("json", bool, False, "Use JSON for version, plugin listing, and supported outputs."),
        AdapterParameterSpec("version", bool, False, "Show radare2 version."),
        AdapterParameterSpec("lib_version", bool, False, "Show radare2 library versions."),
        AdapterParameterSpec("help", bool, False, "Show short help."),
        AdapterParameterSpec("long_help", bool, False, "Show long help."),
        AdapterParameterSpec("sandbox", bool, False, "Start r2 in sandbox mode."),
        AdapterParameterSpec("no_user_config", bool, False, "Do not load user settings and scripts."),
        AdapterParameterSpec("no_scripts_plugins", bool, False, "Do not load any script or plugin."),
        AdapterParameterSpec("no_bin_info", bool, False, "Do not load RBin info."),
        AdapterParameterSpec("bin_structures_only", bool, False, "Only load binary structures."),
        AdapterParameterSpec("full_file", bool, False, "Set block size to file size."),
        AdapterParameterSpec("force_bin_plugin", str, "", "Force use of an rbin plugin."),
        AdapterParameterSpec("asm_os", str, "", "Set asm.os."),
        AdapterParameterSpec("raw_names", bool, False, "Set bin.filter=false to preserve raw names."),
        AdapterParameterSpec("no_demangle", bool, False, "Do not demangle symbol names."),
        AdapterParameterSpec("list_io_plugins", bool, False, "List supported IO plugins."),
        AdapterParameterSpec("list_core_plugins", bool, False, "List supported core plugins."),
        AdapterParameterSpec("no_exec", bool, False, "Open without exec flag."),
        AdapterParameterSpec("no_extr", bool, False, "Disable bin.usextr."),
        AdapterParameterSpec("no_strings", bool, False, "Do not load strings."),
        AdapterParameterSpec("load_strings", bool, False, "Load strings even in raw mode."),
        AdapterParameterSpec("connect_mode", bool, False, "Treat file as host:port command server."),
        AdapterParameterSpec("zero_sep", bool, False, "Print NUL after init and every command."),
        AdapterParameterSpec("stderr_to_stdout", bool, False, "Redirect stderr to stdout."),
        AdapterParameterSpec("no_stderr", bool, False, "Close stderr file descriptor."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "zero_sep", "-0")
    add_bool(tokens, kwargs, "stderr_to_stdout", "-1")
    add_bool(tokens, kwargs, "no_stderr", "-2")
    add_value(tokens, kwargs, "arch", "-a")
    add_bool(tokens, kwargs, "analyze", "-A")
    add_value(tokens, kwargs, "bits", "-b")
    add_value(tokens, kwargs, "base_addr", "-B")
    add_value(tokens, kwargs, "command", "-c")
    add_bool(tokens, kwargs, "connect_mode", "-C")
    add_bool(tokens, kwargs, "debug", "-d")
    add_value(tokens, kwargs, "debug_backend", "-D")
    add_value(tokens, kwargs, "eval_config", "-e")
    add_bool(tokens, kwargs, "full_file", "-f")
    add_value(tokens, kwargs, "force_bin_plugin", "-F")
    _add_help(tokens, kwargs)
    add_value(tokens, kwargs, "script", "-i")
    add_value(tokens, kwargs, "pre_script", "-I")
    add_bool(tokens, kwargs, "json", "-j")
    add_value(tokens, kwargs, "asm_os", "-k")
    _add_plugin_listing(tokens, kwargs)
    add_value(tokens, kwargs, "map_addr", "-m")
    add_bool(tokens, kwargs, "no_demangle", "-M")
    _add_no_load(tokens, kwargs)
    add_value(tokens, kwargs, "project", "-p")
    add_value(tokens, kwargs, "patch_file", "-P")
    _add_quiet(tokens, kwargs)
    add_value(tokens, kwargs, "rarun_profile", "-r")
    add_value(tokens, kwargs, "rarun_directive", "-R")
    add_value(tokens, kwargs, "seek_addr", "-s")
    add_bool(tokens, kwargs, "sandbox", "-S")
    add_bool(tokens, kwargs, "raw_names", "-u")
    add_bool(tokens, kwargs, "version", "-v")
    add_bool(tokens, kwargs, "lib_version", "-V")
    add_bool(tokens, kwargs, "write", "-w")
    add_bool(tokens, kwargs, "no_exec", "-x")
    add_bool(tokens, kwargs, "no_extr", "-X")
    _add_strings(tokens, kwargs)
    return tokens


def _add_help(tokens: list[str], kwargs: dict) -> None:
    if kwargs.get("long_help"):
        tokens.append("-hh")
    else:
        add_bool(tokens, kwargs, "help", "-h")


def _add_plugin_listing(tokens: list[str], kwargs: dict) -> None:
    if kwargs.get("list_core_plugins"):
        tokens.append("-LL")
    else:
        add_bool(tokens, kwargs, "list_io_plugins", "-L")


def _add_no_load(tokens: list[str], kwargs: dict) -> None:
    if kwargs.get("no_scripts_plugins"):
        tokens.append("-NN")
    elif kwargs.get("no_user_config"):
        tokens.append("-N")

    if kwargs.get("bin_structures_only"):
        tokens.append("-nn")
    elif kwargs.get("no_bin_info"):
        tokens.append("-n")


def _add_quiet(tokens: list[str], kwargs: dict) -> None:
    if kwargs.get("quit_after_commands"):
        tokens.append("-qq")
    elif kwargs.get("quick_quiet"):
        tokens.append("-Q")
    else:
        add_bool(tokens, kwargs, "quiet", "-q")


def _add_strings(tokens: list[str], kwargs: dict) -> None:
    if kwargs.get("load_strings"):
        tokens.append("-zz")
    else:
        add_bool(tokens, kwargs, "no_strings", "-z")
