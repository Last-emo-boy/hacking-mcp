"""Dedicated adapter metadata for JADX."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("output_dir", str, "", "Output directory."),
        AdapterParameterSpec("output_dir_src", str, "", "Output directory for sources."),
        AdapterParameterSpec("output_dir_res", str, "", "Output directory for resources."),
        AdapterParameterSpec("no_resources", bool, False, "Do not decode resources."),
        AdapterParameterSpec("no_sources", bool, False, "Do not decompile source code."),
        AdapterParameterSpec("threads_count", int, 0, "Processing thread count; 0 leaves default."),
        AdapterParameterSpec("single_class", str, "", "Decompile a single class by full, raw, or alias name."),
        AdapterParameterSpec("single_class_output", str, "", "File or directory for single-class output."),
        AdapterParameterSpec("output_format", str, "", "Output format: java or json."),
        AdapterParameterSpec("export_gradle", bool, False, "Export as a Gradle project."),
        AdapterParameterSpec("export_gradle_type", str, "", "Gradle export type: auto, android-app, android-library, or simple-java."),
        AdapterParameterSpec("decompilation_mode", str, "", "Mode: auto, restructure, simple, or fallback."),
        AdapterParameterSpec("show_bad_code", bool, False, "Show inconsistent decompiled code."),
        AdapterParameterSpec("no_xml_pretty_print", bool, False, "Do not prettify XML."),
        AdapterParameterSpec("no_imports", bool, False, "Disable imports and use full package names."),
        AdapterParameterSpec("no_debug_info", bool, False, "Disable debug info parsing and processing."),
        AdapterParameterSpec("add_debug_lines", bool, False, "Add comments with debug line numbers."),
        AdapterParameterSpec("no_inline_anonymous", bool, False, "Disable anonymous class inlining."),
        AdapterParameterSpec("no_inline_methods", bool, False, "Disable method inlining."),
        AdapterParameterSpec("no_move_inner_classes", bool, False, "Disable moving inner classes into parent classes."),
        AdapterParameterSpec("no_inline_kotlin_lambda", bool, False, "Disable Kotlin lambda inlining."),
        AdapterParameterSpec("no_finally", bool, False, "Do not extract finally blocks."),
        AdapterParameterSpec("no_restore_switch_over_string", bool, False, "Do not restore switch over string."),
        AdapterParameterSpec("no_replace_consts", bool, False, "Do not replace constant values with matching fields."),
        AdapterParameterSpec("escape_unicode", bool, False, "Escape non-Latin characters in strings."),
        AdapterParameterSpec("respect_bytecode_access_modifiers", bool, False, "Do not change original access modifiers."),
        AdapterParameterSpec("mappings_path", str, "", "Deobfuscation mappings file or directory."),
        AdapterParameterSpec("mappings_mode", str, "", "Mappings handling mode."),
        AdapterParameterSpec("deobf", bool, False, "Activate deobfuscation."),
        AdapterParameterSpec("deobf_min", int, 0, "Minimum name length for deobfuscation rename; 0 leaves default."),
        AdapterParameterSpec("deobf_max", int, 0, "Maximum name length for deobfuscation rename; 0 leaves default."),
        AdapterParameterSpec("deobf_whitelist", str, "", "Classes or packages excluded from deobfuscation."),
        AdapterParameterSpec("deobf_cfg_file", str, "", "JADX deobfuscation map file path."),
        AdapterParameterSpec("deobf_cfg_file_mode", str, "", "JADX deobfuscation map file handling mode."),
        AdapterParameterSpec("deobf_res_name_source", str, "", "Resource deobfuscation name source."),
        AdapterParameterSpec("use_source_name_as_class_name_alias", str, "", "Source-name alias mode."),
        AdapterParameterSpec("source_name_repeat_limit", int, 0, "Source-name repeat limit; 0 leaves default."),
        AdapterParameterSpec("use_kotlin_methods_for_var_names", str, "", "Kotlin intrinsic method variable-name mode."),
        AdapterParameterSpec("use_headers_for_detect_resource_extensions", bool, False, "Use headers to detect obfuscated resource extensions."),
        AdapterParameterSpec("rename_flags", str, "", "Rename flags: case, valid, printable, none, or all."),
        AdapterParameterSpec("integer_format", str, "", "Integer display format: auto, decimal, or hexadecimal."),
        AdapterParameterSpec("type_update_limit", int, 0, "Type update limit per instruction; 0 leaves default."),
        AdapterParameterSpec("fs_case_sensitive", bool, False, "Treat filesystem as case sensitive."),
        AdapterParameterSpec("cfg", bool, False, "Save method control-flow graphs to dot files."),
        AdapterParameterSpec("raw_cfg", bool, False, "Save raw-instruction control-flow graphs."),
        AdapterParameterSpec("fallback", bool, False, "Use fallback decompilation mode."),
        AdapterParameterSpec("use_dx", bool, False, "Use dx/d8 to convert Java bytecode."),
        AdapterParameterSpec("comments_level", str, "", "Comments level: error, warn, info, debug, user-only, or none."),
        AdapterParameterSpec("log_level", str, "", "Log level: quiet, progress, error, warn, info, or debug."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
        AdapterParameterSpec("quiet", bool, False, "Disable output."),
        AdapterParameterSpec("disable_plugins", str, "", "Comma-separated plugin ids to disable."),
        AdapterParameterSpec("config", str, "", "Configuration file path, short name, or none."),
        AdapterParameterSpec("save_config", str, "", "Save current options into a configuration reference and exit."),
        AdapterParameterSpec("print_files", bool, False, "Print config/cache/temp file locations."),
        AdapterParameterSpec("plugin_options", str, "", "Comma-separated plugin options as key=value entries."),
        AdapterParameterSpec("version", bool, False, "Print JADX version."),
        AdapterParameterSpec("help", bool, False, "Print help."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "output_dir", "-d")
    add_value(tokens, kwargs, "output_dir_src", "-ds")
    add_value(tokens, kwargs, "output_dir_res", "-dr")
    add_bool(tokens, kwargs, "no_resources", "-r")
    add_bool(tokens, kwargs, "no_sources", "-s")
    add_value(tokens, kwargs, "threads_count", "-j")
    add_value(tokens, kwargs, "single_class", "--single-class")
    add_value(tokens, kwargs, "single_class_output", "--single-class-output")
    add_value(tokens, kwargs, "output_format", "--output-format")
    add_bool(tokens, kwargs, "export_gradle", "-e")
    add_value(tokens, kwargs, "export_gradle_type", "--export-gradle-type")
    add_value(tokens, kwargs, "decompilation_mode", "-m")
    add_bool(tokens, kwargs, "show_bad_code", "--show-bad-code")
    add_bool(tokens, kwargs, "no_xml_pretty_print", "--no-xml-pretty-print")
    add_bool(tokens, kwargs, "no_imports", "--no-imports")
    add_bool(tokens, kwargs, "no_debug_info", "--no-debug-info")
    add_bool(tokens, kwargs, "add_debug_lines", "--add-debug-lines")
    add_bool(tokens, kwargs, "no_inline_anonymous", "--no-inline-anonymous")
    add_bool(tokens, kwargs, "no_inline_methods", "--no-inline-methods")
    add_bool(tokens, kwargs, "no_move_inner_classes", "--no-move-inner-classes")
    add_bool(tokens, kwargs, "no_inline_kotlin_lambda", "--no-inline-kotlin-lambda")
    add_bool(tokens, kwargs, "no_finally", "--no-finally")
    add_bool(tokens, kwargs, "no_restore_switch_over_string", "--no-restore-switch-over-string")
    add_bool(tokens, kwargs, "no_replace_consts", "--no-replace-consts")
    add_bool(tokens, kwargs, "escape_unicode", "--escape-unicode")
    add_bool(tokens, kwargs, "respect_bytecode_access_modifiers", "--respect-bytecode-access-modifiers")
    add_value(tokens, kwargs, "mappings_path", "--mappings-path")
    add_value(tokens, kwargs, "mappings_mode", "--mappings-mode")
    add_bool(tokens, kwargs, "deobf", "--deobf")
    add_value(tokens, kwargs, "deobf_min", "--deobf-min")
    add_value(tokens, kwargs, "deobf_max", "--deobf-max")
    add_value(tokens, kwargs, "deobf_whitelist", "--deobf-whitelist")
    add_value(tokens, kwargs, "deobf_cfg_file", "--deobf-cfg-file")
    add_value(tokens, kwargs, "deobf_cfg_file_mode", "--deobf-cfg-file-mode")
    add_value(tokens, kwargs, "deobf_res_name_source", "--deobf-res-name-source")
    add_value(tokens, kwargs, "use_source_name_as_class_name_alias", "--use-source-name-as-class-name-alias")
    add_value(tokens, kwargs, "source_name_repeat_limit", "--source-name-repeat-limit")
    add_value(tokens, kwargs, "use_kotlin_methods_for_var_names", "--use-kotlin-methods-for-var-names")
    add_bool(tokens, kwargs, "use_headers_for_detect_resource_extensions", "--use-headers-for-detect-resource-extensions")
    add_value(tokens, kwargs, "rename_flags", "--rename-flags")
    add_value(tokens, kwargs, "integer_format", "--integer-format")
    add_value(tokens, kwargs, "type_update_limit", "--type-update-limit")
    add_bool(tokens, kwargs, "fs_case_sensitive", "--fs-case-sensitive")
    add_bool(tokens, kwargs, "cfg", "--cfg")
    add_bool(tokens, kwargs, "raw_cfg", "--raw-cfg")
    add_bool(tokens, kwargs, "fallback", "-f")
    add_bool(tokens, kwargs, "use_dx", "--use-dx")
    add_value(tokens, kwargs, "comments_level", "--comments-level")
    add_value(tokens, kwargs, "log_level", "--log-level")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_value(tokens, kwargs, "disable_plugins", "--disable-plugins")
    add_value(tokens, kwargs, "config", "--config")
    add_value(tokens, kwargs, "save_config", "--save-config")
    add_bool(tokens, kwargs, "print_files", "--print-files")
    _add_plugin_options(tokens, kwargs)
    add_bool(tokens, kwargs, "version", "--version")
    add_bool(tokens, kwargs, "help", "--help")
    return tokens


def _add_plugin_options(tokens: list[str], kwargs: dict) -> None:
    value = kwargs.get("plugin_options")
    if not value:
        return
    for item in str(value).replace(";", ",").split(","):
        option = item.strip()
        if option:
            tokens.append(f"-P{option}")
