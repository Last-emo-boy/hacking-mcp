"""Dedicated adapter metadata for Ghidra headless analysis."""

import shlex

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("project_name", str, "", "Ghidra project name, optionally combined with folder_path."),
        AdapterParameterSpec("folder_path", str, "", "Project folder path appended to project_name."),
        AdapterParameterSpec("import_path", str, "", "Directory or file to import."),
        AdapterParameterSpec("process_path", str, "", "Existing project file to process."),
        AdapterParameterSpec("pre_script", str, "", "Pre-script name."),
        AdapterParameterSpec("pre_script_args", str, "", "Arguments for pre_script, parsed like shell words."),
        AdapterParameterSpec("post_script", str, "", "Post-script name."),
        AdapterParameterSpec("post_script_args", str, "", "Arguments for post_script, parsed like shell words."),
        AdapterParameterSpec("script_path", str, "", "Script search path list."),
        AdapterParameterSpec("properties_path", str, "", "Script properties path list."),
        AdapterParameterSpec("script_log", str, "", "Path to script log file."),
        AdapterParameterSpec("log_file", str, "", "Path to Ghidra log file."),
        AdapterParameterSpec("overwrite", bool, False, "Overwrite imported programs."),
        AdapterParameterSpec("mirror", bool, False, "Mirror imported directory layout."),
        AdapterParameterSpec("recursive", bool, False, "Recursively import files."),
        AdapterParameterSpec("recursive_depth", int, 0, "Optional recursive import depth; 0 leaves unset."),
        AdapterParameterSpec("read_only", bool, False, "Process project files read-only."),
        AdapterParameterSpec("delete_project", bool, False, "Delete local project after execution."),
        AdapterParameterSpec("no_analysis", bool, False, "Skip auto-analysis."),
        AdapterParameterSpec("processor", str, "", "Language ID to use while importing."),
        AdapterParameterSpec("cspec", str, "", "Compiler spec ID to use while importing."),
        AdapterParameterSpec("analysis_timeout_per_file", int, 0, "Analysis timeout per file in seconds; 0 leaves unset."),
        AdapterParameterSpec("keystore", str, "", "Keystore path for server authentication."),
        AdapterParameterSpec("connect", bool, False, "Connect to a Ghidra server."),
        AdapterParameterSpec("connect_user", str, "", "Optional user ID for -connect."),
        AdapterParameterSpec("password", bool, False, "Prompt for repository password."),
        AdapterParameterSpec("commit", bool, False, "Commit changes to server repository."),
        AdapterParameterSpec("commit_comment", str, "", "Optional commit comment."),
        AdapterParameterSpec("ok_to_delete", bool, False, "Allow delete operations when requested by scripts."),
        AdapterParameterSpec("max_cpu", int, 0, "Maximum CPU cores to use; 0 leaves unset."),
        AdapterParameterSpec("library_search_paths", str, "", "Library search path list."),
        AdapterParameterSpec("loader", str, "", "Desired loader name."),
        AdapterParameterSpec("loader_args", str, "", "Comma/semicolon-separated loader key=value arguments."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    _add_project_name(tokens, kwargs)
    add_value(tokens, kwargs, "import_path", "-import")
    add_value(tokens, kwargs, "process_path", "-process")
    _add_script(tokens, kwargs, "pre_script", "pre_script_args", "-preScript")
    _add_script(tokens, kwargs, "post_script", "post_script_args", "-postScript")
    add_value(tokens, kwargs, "script_path", "-scriptPath")
    add_value(tokens, kwargs, "properties_path", "-propertiesPath")
    add_value(tokens, kwargs, "script_log", "-scriptlog")
    add_value(tokens, kwargs, "log_file", "-log")
    add_bool(tokens, kwargs, "overwrite", "-overwrite")
    add_bool(tokens, kwargs, "mirror", "-mirror")
    _add_recursive(tokens, kwargs)
    add_bool(tokens, kwargs, "read_only", "-readOnly")
    add_bool(tokens, kwargs, "delete_project", "-deleteProject")
    add_bool(tokens, kwargs, "no_analysis", "-noanalysis")
    add_value(tokens, kwargs, "processor", "-processor")
    add_value(tokens, kwargs, "cspec", "-cspec")
    add_value(tokens, kwargs, "analysis_timeout_per_file", "-analysisTimeoutPerFile")
    add_value(tokens, kwargs, "keystore", "-keystore")
    _add_connect(tokens, kwargs)
    add_bool(tokens, kwargs, "password", "-p")
    _add_commit(tokens, kwargs)
    add_bool(tokens, kwargs, "ok_to_delete", "-okToDelete")
    add_value(tokens, kwargs, "max_cpu", "-max-cpu")
    add_value(tokens, kwargs, "library_search_paths", "-librarySearchPaths")
    add_value(tokens, kwargs, "loader", "-loader")
    _add_loader_args(tokens, kwargs)
    return tokens


def _add_project_name(tokens: list[str], kwargs: dict) -> None:
    project_name = str(kwargs.get("project_name") or "").strip()
    if not project_name:
        return
    folder_path = str(kwargs.get("folder_path") or "").strip().strip("/")
    if folder_path:
        tokens.append(f"{project_name}/{folder_path}")
    else:
        tokens.append(project_name)


def _add_script(tokens: list[str], kwargs: dict, key: str, args_key: str, flag: str) -> None:
    script = str(kwargs.get(key) or "").strip()
    if not script:
        return
    tokens.extend([flag, script])
    args = str(kwargs.get(args_key) or "").strip()
    if not args:
        return
    try:
        tokens.extend(shlex.split(args))
    except ValueError:
        tokens.append(args)


def _add_recursive(tokens: list[str], kwargs: dict) -> None:
    if not kwargs.get("recursive"):
        return
    tokens.append("-recursive")
    depth = kwargs.get("recursive_depth")
    if depth not in (None, "", 0, False):
        tokens.append(str(depth))


def _add_connect(tokens: list[str], kwargs: dict) -> None:
    user = str(kwargs.get("connect_user") or "").strip()
    if user:
        tokens.extend(["-connect", user])
    else:
        add_bool(tokens, kwargs, "connect", "-connect")


def _add_commit(tokens: list[str], kwargs: dict) -> None:
    comment = str(kwargs.get("commit_comment") or "").strip()
    if comment:
        tokens.extend(["-commit", comment])
    else:
        add_bool(tokens, kwargs, "commit", "-commit")


def _add_loader_args(tokens: list[str], kwargs: dict) -> None:
    value = kwargs.get("loader_args")
    if not value:
        return
    for item in str(value).replace(";", ",").split(","):
        if "=" not in item:
            continue
        key, arg_value = item.split("=", 1)
        key = key.strip()
        arg_value = arg_value.strip()
        if key and arg_value:
            tokens.extend([f"-loader-{key}", arg_value])
