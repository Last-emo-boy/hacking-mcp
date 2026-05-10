"""Dedicated adapter metadata for Androguard."""

import shlex

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("command", str, "analyze", "Androguard subcommand to run."),
        AdapterParameterSpec("input_file", str, "", "APK, DEX, XML, ARSC, or session input file."),
        AdapterParameterSpec("apk_files", str, "", "Multiple APK files, parsed like shell words."),
        AdapterParameterSpec("output_file", str, "", "Output file for axml/arsc/cg results."),
        AdapterParameterSpec("output_dir", str, "", "Output directory for decompile results."),
        AdapterParameterSpec("resource", str, "", "Binary XML resource inside an APK for axml."),
        AdapterParameterSpec("package", str, "", "Resource package name for arsc."),
        AdapterParameterSpec("locale", str, "", "Resource locale for arsc."),
        AdapterParameterSpec("resource_type", str, "", "Resource type for arsc."),
        AdapterParameterSpec("resource_id", str, "", "Hex resource ID to resolve with arsc."),
        AdapterParameterSpec("list_packages", bool, False, "List ARSC package names and exit."),
        AdapterParameterSpec("list_locales", bool, False, "List ARSC locales and exit."),
        AdapterParameterSpec("list_types", bool, False, "List ARSC resource types and exit."),
        AdapterParameterSpec("graph_format", str, "", "Control-flow graph format for decompile."),
        AdapterParameterSpec("jar", bool, False, "Use dex2jar to create a JAR file during decompile."),
        AdapterParameterSpec("limit", str, "", "Regex limiting decompile output to selected methods."),
        AdapterParameterSpec("decompiler", str, "", "Decompiler backend for decompile."),
        AdapterParameterSpec("hash_algo", str, "", "Certificate hash: md5, sha1, sha256, or sha512."),
        AdapterParameterSpec("all_hashes", bool, False, "Print all certificate hashes for sign."),
        AdapterParameterSpec("show", bool, False, "Show certificate or callgraph UI output where supported."),
        AdapterParameterSpec("session", str, "", "Saved session to load for analyze."),
        AdapterParameterSpec("offset", int, 0, "Disassemble offset; 0 leaves default."),
        AdapterParameterSpec("size", int, 0, "Disassemble size; 0 leaves default."),
        AdapterParameterSpec("modules", str, "", "Comma/semicolon-separated trace module list."),
        AdapterParameterSpec("enable_ui", bool, False, "Enable UI for trace."),
        AdapterParameterSpec("package_name", str, "", "Android package name for dynamic trace/dump commands."),
        AdapterParameterSpec("output_type", str, "", "Callgraph output type."),
        AdapterParameterSpec("classname", str, "", "Callgraph class-name regex filter."),
        AdapterParameterSpec("methodname", str, "", "Callgraph method-name regex filter."),
        AdapterParameterSpec("descriptor", str, "", "Callgraph descriptor regex filter."),
        AdapterParameterSpec("accessflag", str, "", "Callgraph access-flag regex filter."),
        AdapterParameterSpec("no_isolated", bool, False, "Do not include isolated methods in callgraph output."),
        AdapterParameterSpec("verbose", bool, False, "Enable Androguard verbose/debug logging."),
    ]


def build_options(kwargs: dict) -> list[str]:
    command = _command(kwargs)
    tokens: list[str] = []
    add_bool(tokens, kwargs, "verbose", "--verbose")
    tokens.append(command)

    if command == "axml":
        _build_axml(tokens, kwargs)
    elif command == "arsc":
        _build_arsc(tokens, kwargs)
    elif command == "decompile":
        _build_decompile(tokens, kwargs)
    elif command == "sign":
        _build_sign(tokens, kwargs)
    elif command == "apkid":
        _append_inputs(tokens, kwargs)
    elif command == "analyze":
        _build_analyze(tokens, kwargs)
    elif command == "disassemble":
        _build_disassemble(tokens, kwargs)
    elif command == "trace":
        _build_trace(tokens, kwargs)
    elif command in {"dtrace", "dump"}:
        _build_dynamic_trace(tokens, kwargs)
    elif command == "cg":
        _build_callgraph(tokens, kwargs)
    else:
        _append_input(tokens, kwargs)
    return tokens


def _command(kwargs: dict) -> str:
    return str(kwargs.get("command") or "analyze").strip() or "analyze"


def _input(kwargs: dict) -> str:
    return str(kwargs.get("input_file") or kwargs.get("target") or "").strip()


def _append_input(tokens: list[str], kwargs: dict) -> None:
    input_file = _input(kwargs)
    if input_file:
        tokens.append(input_file)


def _append_inputs(tokens: list[str], kwargs: dict) -> None:
    value = str(kwargs.get("apk_files") or "").strip()
    if value:
        try:
            tokens.extend(shlex.split(value))
            return
        except ValueError:
            tokens.append(value)
            return
    _append_input(tokens, kwargs)


def _build_axml(tokens: list[str], kwargs: dict) -> None:
    add_value(tokens, kwargs, "output_file", "--output")
    add_value(tokens, kwargs, "resource", "--resource")
    _append_input(tokens, kwargs)


def _build_arsc(tokens: list[str], kwargs: dict) -> None:
    add_value(tokens, kwargs, "output_file", "--output")
    add_value(tokens, kwargs, "package", "--package")
    add_value(tokens, kwargs, "locale", "--locale")
    add_value(tokens, kwargs, "resource_type", "--type")
    add_value(tokens, kwargs, "resource_id", "--id")
    add_bool(tokens, kwargs, "list_packages", "--list-packages")
    add_bool(tokens, kwargs, "list_locales", "--list-locales")
    add_bool(tokens, kwargs, "list_types", "--list-types")
    _append_input(tokens, kwargs)


def _build_decompile(tokens: list[str], kwargs: dict) -> None:
    add_value(tokens, kwargs, "output_dir", "--output")
    add_value(tokens, kwargs, "graph_format", "--format")
    add_bool(tokens, kwargs, "jar", "--jar")
    add_value(tokens, kwargs, "limit", "--limit")
    add_value(tokens, kwargs, "decompiler", "--decompiler")
    _append_input(tokens, kwargs)


def _build_sign(tokens: list[str], kwargs: dict) -> None:
    add_value(tokens, kwargs, "hash_algo", "--hash")
    add_bool(tokens, kwargs, "all_hashes", "--all")
    add_bool(tokens, kwargs, "show", "--show")
    _append_inputs(tokens, kwargs)


def _build_analyze(tokens: list[str], kwargs: dict) -> None:
    add_value(tokens, kwargs, "session", "--session")
    if not kwargs.get("session"):
        _append_input(tokens, kwargs)


def _build_disassemble(tokens: list[str], kwargs: dict) -> None:
    add_value(tokens, kwargs, "offset", "--offset")
    add_value(tokens, kwargs, "size", "--size")
    _append_input(tokens, kwargs)


def _build_trace(tokens: list[str], kwargs: dict) -> None:
    _append_input(tokens, kwargs)
    _add_modules(tokens, kwargs)
    add_bool(tokens, kwargs, "enable_ui", "--enable-ui")


def _build_dynamic_trace(tokens: list[str], kwargs: dict) -> None:
    package_name = str(kwargs.get("package_name") or kwargs.get("target") or "").strip()
    if package_name:
        tokens.append(package_name)
    _add_modules(tokens, kwargs)


def _build_callgraph(tokens: list[str], kwargs: dict) -> None:
    add_value(tokens, kwargs, "output_file", "--output")
    add_value(tokens, kwargs, "output_type", "--output-type")
    add_bool(tokens, kwargs, "show", "--show")
    add_value(tokens, kwargs, "classname", "--classname")
    add_value(tokens, kwargs, "methodname", "--methodname")
    add_value(tokens, kwargs, "descriptor", "--descriptor")
    add_value(tokens, kwargs, "accessflag", "--accessflag")
    add_bool(tokens, kwargs, "no_isolated", "--no-isolated")
    _append_input(tokens, kwargs)


def _add_modules(tokens: list[str], kwargs: dict) -> None:
    value = kwargs.get("modules")
    if not value:
        return
    for item in str(value).replace(";", ",").split(","):
        module = item.strip()
        if module:
            tokens.extend(["--modules", module])
