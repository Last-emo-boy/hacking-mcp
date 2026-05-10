"""Research-state tracking for dedicated per-tool MCP adapters.

This module does not execute tools or fetch upstream repositories. It records
what evidence currently backs each generated adapter so gaps are explicit.
"""

from collections import Counter
from dataclasses import dataclass

from hacking_mcp.mcp_tools.tool_adapters import (
    NAMED_OVERRIDE_TOOL_NAMES,
    adapter_parameter_names,
    build_adapter_specs,
)
from hacking_mcp.mcp_tools.adapters import has_split_adapter
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy


SOURCE_STATUS_REGISTRY_DERIVED = "registry-derived"
SOURCE_STATUS_NAMED_OVERRIDE = "named-override"
SOURCE_STATUS_SOURCE_REVIEWED = "source-reviewed"

@dataclass(frozen=True)
class SourceReview:
    """Manual upstream-source review evidence for one adapter."""

    note: str
    references: tuple[str, ...]
    verified_parameters: tuple[str, ...]


SOURCE_REVIEWED_TOOLS: dict[str, SourceReview] = {
    "prowler": SourceReview(
        note=(
            "Reviewed against upstream Prowler argparse CLI parser and AWS "
            "provider argument definitions for provider-as-positional usage, "
            "profile/region filters, service/check/severity selectors, "
            "exclusion selectors, output controls, list modes, banner/color, "
            "verbose output, and logging level."
        ),
        references=(
            "https://github.com/prowler-cloud/prowler",
            "https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/lib/cli/parser.py",
            "https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/providers/aws/lib/arguments/arguments.py",
        ),
        verified_parameters=(
            "profile",
            "region",
            "services",
            "severity",
            "checks",
            "excluded_checks",
            "excluded_services",
            "output_formats",
            "output_directory",
            "output_filename",
            "list_checks",
            "list_services",
            "no_banner",
            "no_color",
            "verbose",
            "log_level",
        ),
    ),
    "scoutsuite": SourceReview(
        note=(
            "Reviewed against upstream ScoutSuite CLI parser and run_from_cli "
            "handoff for provider subcommands, AWS profile/region filters, "
            "service include/skip controls, listing, report format/location "
            "controls, local/update modes, rulesets, exceptions, overwrite, "
            "debug/quiet/browser behavior, and API concurrency/rate limits."
        ),
        references=(
            "https://github.com/nccgroup/ScoutSuite",
            "https://raw.githubusercontent.com/nccgroup/ScoutSuite/master/ScoutSuite/core/cli_parser.py",
            "https://raw.githubusercontent.com/nccgroup/ScoutSuite/master/ScoutSuite/__main__.py",
        ),
        verified_parameters=(
            "profile",
            "regions",
            "excluded_regions",
            "services",
            "skipped_services",
            "list_services",
            "result_format",
            "report_dir",
            "report_name",
            "timestamp",
            "fetch_local",
            "update",
            "ruleset",
            "exceptions",
            "force_write",
            "debug",
            "quiet",
            "no_browser",
            "max_workers",
            "max_rate",
        ),
    ),
    "pacu": SourceReview(
        note=(
            "Reviewed against upstream Pacu README and argparse definitions in "
            "pacu/main.py for session management, key import/set actions, "
            "module selection/execution/info, database data queries, module "
            "arguments, module/help listing, region selection, identity lookup, "
            "version output, and quiet startup."
        ),
        references=(
            "https://github.com/RhinoSecurityLabs/pacu",
            "https://raw.githubusercontent.com/RhinoSecurityLabs/pacu/master/README.md",
            "https://raw.githubusercontent.com/RhinoSecurityLabs/pacu/master/pacu/main.py",
        ),
        verified_parameters=(
            "session",
            "activate_session",
            "new_session",
            "set_keys",
            "import_keys",
            "module_name",
            "data",
            "module_args",
            "list_modules",
            "pacu_help",
            "module_info",
            "execute_module",
            "set_regions",
            "whoami",
            "version",
            "quiet",
        ),
    ),
    "trivy": SourceReview(
        note=(
            "Reviewed against upstream Trivy Cobra command setup and flag "
            "definitions for command-before-target usage, reporting flags, "
            "vulnerability filtering, scan controls, global config/cache/"
            "timeout flags, and quiet/debug/insecure modes."
        ),
        references=(
            "https://github.com/aquasecurity/trivy",
            "https://raw.githubusercontent.com/aquasecurity/trivy/main/pkg/commands/app.go",
            "https://raw.githubusercontent.com/aquasecurity/trivy/main/pkg/flag/report_flags.go",
            "https://raw.githubusercontent.com/aquasecurity/trivy/main/pkg/flag/vulnerability_flags.go",
            "https://raw.githubusercontent.com/aquasecurity/trivy/main/pkg/flag/scan_flags.go",
            "https://raw.githubusercontent.com/aquasecurity/trivy/main/pkg/flag/global_flags.go",
        ),
        verified_parameters=(
            "command",
            "severity",
            "output_format",
            "output_file",
            "template",
            "ignorefile",
            "exit_code",
            "ignore_unfixed",
            "scanners",
            "skip_dirs",
            "skip_files",
            "offline_scan",
            "parallel",
            "timeout",
            "config",
            "cache_dir",
            "quiet",
            "debug",
            "insecure",
        ),
    ),
    "bloodhound": SourceReview(
        note=(
            "Reviewed against upstream BloodHound.py argparse CLI and README "
            "for domain-as-target execution, authentication controls, "
            "collection method selection, DNS/DC/GC overrides, worker and "
            "pooling controls, output prefix/zip behavior, cache/computer "
            "allowlist inputs, and LDAP TLS/channel-binding options."
        ),
        references=(
            "https://github.com/dirkjanm/BloodHound.py",
            "https://raw.githubusercontent.com/dirkjanm/BloodHound.py/master/bloodhound/__init__.py",
            "https://raw.githubusercontent.com/dirkjanm/BloodHound.py/master/README.md",
        ),
        verified_parameters=(
            "username",
            "password",
            "kerberos",
            "hashes",
            "no_pass",
            "aes_key",
            "auth_method",
            "collection_method",
            "verbose",
            "nameserver",
            "dns_tcp",
            "dns_timeout",
            "domain_controller",
            "global_catalog",
            "workers",
            "exclude_dcs",
            "disable_pooling",
            "disable_autogc",
            "zip_output",
            "computerfile",
            "cachefile",
            "ldap_channel_binding",
            "use_ldaps",
            "output_prefix",
        ),
    ),
    "netexec": SourceReview(
        note=(
            "Reviewed against upstream NetExec nxc CLI and SMB protocol "
            "argparse definitions for smb-target execution, authentication "
            "and Kerberos controls, generic threading/output/DNS options, "
            "module selection, SMB port/share controls, common enumeration "
            "actions, and command execution options."
        ),
        references=(
            "https://github.com/Pennyw0rth/NetExec",
            "https://raw.githubusercontent.com/Pennyw0rth/NetExec/main/nxc/cli.py",
            "https://raw.githubusercontent.com/Pennyw0rth/NetExec/main/nxc/protocols/smb/proto_args.py",
            "https://raw.githubusercontent.com/Pennyw0rth/NetExec/main/nxc/netexec.py",
        ),
        verified_parameters=(
            "username",
            "password",
            "hashes",
            "domain",
            "local_auth",
            "kerberos",
            "use_kcache",
            "aes_key",
            "kdc_host",
            "cred_id",
            "ignore_pw_decoding",
            "no_bruteforce",
            "continue_on_success",
            "gfail_limit",
            "ufail_limit",
            "fail_limit",
            "threads",
            "timeout",
            "jitter",
            "no_progress",
            "log_file",
            "verbose",
            "debug",
            "force_ipv6",
            "dns_server",
            "dns_tcp",
            "dns_timeout",
            "module",
            "module_options",
            "list_modules",
            "show_module_options",
            "port",
            "share",
            "smb_server_port",
            "no_smbv1",
            "no_admin_check",
            "gen_relay_list",
            "smb_timeout",
            "shares",
            "users",
            "groups",
            "pass_pol",
            "rid_brute",
            "exec_method",
            "execute_cmd",
            "execute_ps",
        ),
    ),
    "responder": SourceReview(
        note=(
            "Reviewed against upstream Responder optparse definitions and "
            "README usage for interface-target execution, passive analyze "
            "mode, external poison addresses, RDNSS/DNSSL/TTL/answer-name "
            "poisoning controls, DHCP/DHCPv6/WPAD/proxy-auth modes, "
            "authentication downgrades, output verbosity, and OSX local IP."
        ),
        references=(
            "https://github.com/lgandx/Responder",
            "https://raw.githubusercontent.com/lgandx/Responder/master/Responder.py",
            "https://raw.githubusercontent.com/lgandx/Responder/master/README.md",
        ),
        verified_parameters=(
            "analyze",
            "external_ip",
            "external_ipv6",
            "rdnss",
            "dnssl_domain",
            "ttl",
            "answer_name",
            "dhcp",
            "dhcp_dns",
            "dhcpv6",
            "wpad",
            "force_wpad_auth",
            "proxy_auth",
            "upstream_proxy",
            "basic",
            "lm",
            "disable_ess",
            "error_code",
            "verbose",
            "quiet",
            "local_ip",
        ),
    ),
    "kerbrute": SourceReview(
        note=(
            "Reviewed against upstream Kerbrute Cobra root/userenum command "
            "definitions and README usage for domain-as-target userenum "
            "execution, KDC selection, output logs, verbosity, safe mode, "
            "thread/delay controls, downgrade mode, AS-REP hash capture, "
            "and username wordlist positional input."
        ),
        references=(
            "https://github.com/ropnop/kerbrute",
            "https://raw.githubusercontent.com/ropnop/kerbrute/master/README.md",
            "https://raw.githubusercontent.com/ropnop/kerbrute/master/cmd/kerbrute.go",
            "https://raw.githubusercontent.com/ropnop/kerbrute/master/cmd/userenum.go",
        ),
        verified_parameters=(
            "dc",
            "output_file",
            "verbose",
            "safe",
            "threads",
            "delay",
            "downgrade",
            "hash_file",
            "users_file",
        ),
    ),
    "impacket": SourceReview(
        note=(
            "Reviewed against upstream Impacket smbclient.py argparse source "
            "for positional target identity syntax, mini-shell input/output "
            "files, debug/timestamp logging, NTLM hash/no-password/Kerberos/"
            "AES-key authentication, and DC/target IP plus SMB port controls."
        ),
        references=(
            "https://github.com/fortra/impacket",
            "https://raw.githubusercontent.com/fortra/impacket/master/examples/smbclient.py",
            "https://raw.githubusercontent.com/fortra/impacket/master/README.md",
        ),
        verified_parameters=(
            "input_file",
            "output_file",
            "debug",
            "timestamp",
            "hashes",
            "no_pass",
            "kerberos",
            "aes_key",
            "dc_ip",
            "target_ip",
            "port",
        ),
    ),
    "certipy": SourceReview(
        note=(
            "Reviewed against upstream Certipy find parser and shared target "
            "parser for registry target-as-username execution, output format "
            "flags, template/CA filtering controls, identity selectors, "
            "domain-controller/target/DNS connection controls, authentication "
            "modes, and LDAP connection options."
        ),
        references=(
            "https://github.com/ly4k/Certipy",
            "https://raw.githubusercontent.com/ly4k/Certipy/main/certipy/commands/parsers/find.py",
            "https://raw.githubusercontent.com/ly4k/Certipy/main/certipy/commands/parsers/target.py",
            "https://raw.githubusercontent.com/ly4k/Certipy/main/certipy/commands/find.py",
        ),
        verified_parameters=(
            "password",
            "hashes",
            "kerberos",
            "aes_key",
            "no_pass",
            "dc_ip",
            "dc_host",
            "target_ip",
            "target_host",
            "nameserver",
            "dns_tcp",
            "timeout",
            "ldap_scheme",
            "ldap_port",
            "no_ldap_channel_binding",
            "no_ldap_signing",
            "ldap_simple_auth",
            "ldap_user_dn",
            "text",
            "stdout",
            "json_output",
            "csv",
            "output_prefix",
            "enabled",
            "dc_only",
            "vulnerable",
            "oids",
            "hide_admins",
            "sid",
            "dn",
        ),
    ),
    "autopsy": SourceReview(
        note=(
            "Reviewed against the Autopsy Forensic Browser man page. The "
            "registry command starts the server as sudo autopsy; the adapter "
            "replaces generated forensics parameters with the documented "
            "cookie toggles, evidence locker, live-analysis triplet, port, "
            "and optional investigator address."
        ),
        references=(
            "https://www.sleuthkit.org/autopsy/man/autopsy.html",
            "https://manpages.debian.org/bookworm/autopsy/autopsy.1.en.html",
        ),
        verified_parameters=(
            "use_cookies",
            "no_cookies",
            "evidence_locker",
            "live_device",
            "live_filesystem",
            "live_mount",
            "port",
            "remote_addr",
        ),
    ),
    "binwalk": SourceReview(
        note=(
            "Reviewed against upstream Binwalk v3 clap parser definitions for "
            "input mode, listing, quiet/verbose output, extraction, carving, "
            "recursive scans, search-all, entropy graph/logging outputs, "
            "thread count, signature include/exclude filters, and extraction "
            "directory."
        ),
        references=(
            "https://github.com/ReFirmLabs/binwalk",
            "https://raw.githubusercontent.com/ReFirmLabs/binwalk/master/src/cliparser.rs",
        ),
        verified_parameters=(
            "list_signatures",
            "stdin",
            "quiet",
            "verbose",
            "extract",
            "carve",
            "matryoshka",
            "search_all",
            "entropy",
            "png_output",
            "log_file",
            "threads",
            "exclude",
            "include",
            "output_dir",
        ),
    ),
    "wireshark": SourceReview(
        note=(
            "Reviewed against the official Wireshark man page. Wireshark is "
            "a GUI network protocol analyzer and the current registry command "
            "starts sudo wireshark without -r, -i, capture, or output flags. "
            "The adapter is therefore intentionally interactive-only for this "
            "registered command shape and suppresses generated forensics and "
            "network scan parameters."
        ),
        references=(
            "https://www.wireshark.org/docs/man-pages/wireshark.html",
            "https://www.wireshark.org/docs/man-pages/",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "bulk-extractor": SourceReview(
        note=(
            "Reviewed against the upstream bulk_extractor man page and "
            "current cxxopts CLI source. The registry target is the positional "
            "image/directory input; generated options are placed before that "
            "target so required output directory and scanner controls match "
            "the documented bulk_extractor -o outdir [options] image shape."
        ),
        references=(
            "https://github.com/simsong/bulk_extractor",
            "https://raw.githubusercontent.com/simsong/bulk_extractor/main/man/bulk_extractor.1",
            "https://raw.githubusercontent.com/simsong/bulk_extractor/main/src/bulk_extractor.cpp",
        ),
        verified_parameters=(
            "output_dir",
            "banner_file",
            "alert_list",
            "stop_list",
            "sampling",
            "print_path",
            "find_patterns",
            "find_files",
            "context_window",
            "page_size",
            "margin_size",
            "threads",
            "no_threads",
            "max_depth",
            "scanner_dirs",
            "recursive",
            "settings",
            "scan_range",
            "page_start",
            "exclusive_scanner",
            "enabled_scanners",
            "disabled_scanners",
            "quiet",
            "info_scanners",
            "version",
            "no_notify",
            "legacy_notification",
        ),
    ),
    "guymager": SourceReview(
        note=(
            "Reviewed against the Debian Guymager man page and project "
            "documentation. The current registry command starts the Qt "
            "forensic imager as sudo guymager; the adapter removes generated "
            "forensics extraction/plugin/profile parameters and exposes only "
            "the documented log= and cfg= command-line settings."
        ),
        references=(
            "https://manpages.debian.org/bookworm/guymager/guymager.1.en.html",
            "https://guymager.sourceforge.io/",
        ),
        verified_parameters=(
            "log_file",
            "config_file",
        ),
    ),
    "toolsley": SourceReview(
        note=(
            "Reviewed against the Toolsley project page and the Python "
            "standard library hashlib API used by the registry wrapper. "
            "There is no Toolsley CLI parser in this project; the registered "
            "command computes a SHA-256 digest for one positional text input, "
            "so the adapter exposes only a text target alias and no generated "
            "CLI options."
        ),
        references=(
            "https://www.toolsley.com/",
            "https://docs.python.org/3/library/hashlib.html#hashlib.sha256",
        ),
        verified_parameters=(
            "text",
        ),
    ),
    "volatility3": SourceReview(
        note=(
            "Reviewed against upstream Volatility 3 CLI source and generated "
            "manual page for config, parallelism, extension, plugin/symbol "
            "paths, verbosity, logging, output directory, quiet mode, renderer, "
            "configuration/cache controls, online/offline ISF controls, output "
            "filters, column hiding, memory location inputs, stackers, swap "
            "locations, and plugin selection."
        ),
        references=(
            "https://github.com/volatilityfoundation/volatility3",
            "https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/cli/__init__.py",
            "https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/doc/source/vol-cli.rst",
        ),
        verified_parameters=(
            "config_file",
            "parallelism",
            "extend",
            "plugin_dirs",
            "symbol_dirs",
            "symbol_dir",
            "verbosity",
            "log_file",
            "output_dir",
            "quiet",
            "renderer",
            "write_config",
            "save_config",
            "clear_cache",
            "cache_path",
            "offline",
            "remote_isf_url",
            "filters",
            "hide_columns",
            "single_location",
            "stackers",
            "single_swap_locations",
            "plugin",
        ),
    ),
    "pspy": SourceReview(
        note=(
            "Reviewed against upstream pspy README usage summary and Cobra "
            "flag definitions for process/file-system event output, recursive "
            "and non-recursive watch directories, procfs scan interval, color, "
            "debug, parent PID recording, and command truncation controls."
        ),
        references=(
            "https://github.com/DominicBreuker/pspy",
            "https://raw.githubusercontent.com/DominicBreuker/pspy/master/README.md",
            "https://raw.githubusercontent.com/DominicBreuker/pspy/master/cmd/root.go",
        ),
        verified_parameters=(
            "procevents",
            "fsevents",
            "recursive_dirs",
            "dirs",
            "interval",
            "color",
            "debug",
            "ppid",
            "truncate",
        ),
    ),
    "haiti": SourceReview(
        note=(
            "Reviewed against upstream haiti docopt CLI definition for hash "
            "identification display controls, including color disabling, "
            "extended salted variants, short output, hashcat-only, John-only, "
            "ASCII art, and debug argument output."
        ),
        references=(
            "https://github.com/noraj/haiti",
            "https://raw.githubusercontent.com/noraj/haiti/master/bin/haiti",
        ),
        verified_parameters=(
            "no_color",
            "extended",
            "short",
            "hashcat_only",
            "john_only",
            "ascii_art",
            "debug",
        ),
    ),
    "hashcat": SourceReview(
        note=(
            "Reviewed against upstream hashcat generated help, usage source, "
            "and user option parser definitions for hash/attack modes, "
            "candidate inputs, rules, session/restore controls, output and "
            "potfile handling, mask increment/charset controls, backend and "
            "workload selectors, status/runtime controls, benchmark/info "
            "modes, and common display/safety toggles."
        ),
        references=(
            "https://github.com/hashcat/hashcat",
            "https://raw.githubusercontent.com/hashcat/hashcat/master/docs/hashcat-help.md",
            "https://raw.githubusercontent.com/hashcat/hashcat/master/src/usage.c",
            "https://raw.githubusercontent.com/hashcat/hashcat/master/src/user_options.c",
        ),
        verified_parameters=(
            "hash_type",
            "attack_mode",
            "wordlist",
            "wordlist2",
            "mask",
            "rules",
            "rule_left",
            "rule_right",
            "generate_rules",
            "session",
            "restore",
            "restore_disable",
            "restore_file_path",
            "output_file",
            "outfile_format",
            "outfile_json",
            "outfile_autohex_disable",
            "separator",
            "show",
            "left",
            "username",
            "remove",
            "remove_timer",
            "potfile_disable",
            "potfile_path",
            "increment",
            "increment_inverse",
            "increment_min",
            "increment_max",
            "custom_charset1",
            "custom_charset2",
            "custom_charset3",
            "custom_charset4",
            "hex_charset",
            "hex_salt",
            "hex_wordlist",
            "workload_profile",
            "optimized_kernel",
            "backend_devices",
            "opencl_device_types",
            "backend_info",
            "status",
            "status_json",
            "status_timer",
            "runtime",
            "skip",
            "limit",
            "benchmark",
            "benchmark_all",
            "benchmark_min",
            "benchmark_max",
            "hash_info",
            "example_hashes",
            "identify",
            "stdout_candidates",
            "quiet",
            "force",
            "version",
            "help",
        ),
    ),
    "john": SourceReview(
        note=(
            "Reviewed against upstream John the Ripper Jumbo command-line "
            "documentation and option parser definitions for cracking modes, "
            "wordlist/rules handling, mask/custom charset controls, session "
            "restore/status, show/test/list modes, hash filtering, format/pot "
            "selection, candidate limits, logging, parallelism, and device "
            "selectors."
        ),
        references=(
            "https://github.com/openwall/john",
            "https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/doc/OPTIONS",
            "https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/src/options.c",
        ),
        verified_parameters=(
            "single",
            "single_rules",
            "single_seed",
            "single_wordlist",
            "wordlist",
            "wordlist_default",
            "stdin",
            "pipe",
            "rules",
            "rules_default",
            "rules_stack",
            "rules_skip_nop",
            "incremental",
            "incremental_default",
            "mask",
            "custom_charset1",
            "custom_charset2",
            "custom_charset3",
            "custom_charset4",
            "markov",
            "external",
            "stdout_candidates",
            "stdout_length",
            "restore",
            "restore_session",
            "session",
            "status",
            "status_session",
            "show",
            "show_mode",
            "make_charset",
            "test",
            "test_time",
            "stress_test",
            "no_mask",
            "skip_self_tests",
            "users",
            "groups",
            "shells",
            "salts",
            "costs",
            "format",
            "subformat",
            "pot",
            "list_option",
            "config",
            "field_separator_char",
            "min_length",
            "max_length",
            "length",
            "max_run_time",
            "max_candidates",
            "progress_every",
            "fork",
            "node",
            "devices",
            "lws",
            "gws",
            "verbosity",
            "no_log",
            "log_stderr",
            "crack_status",
            "keep_guessing",
            "reject_printable",
            "force_tty",
            "help",
        ),
    ),
    "jadx": SourceReview(
        note=(
            "Reviewed against upstream JADX README usage and JCommander CLI "
            "argument definitions for input files, output directories, source "
            "and resource toggles, threading, single-class output, Gradle "
            "export, decompilation modes, code-generation toggles, "
            "deobfuscation/mapping controls, rename/display settings, CFG "
            "output, dx conversion, logging, plugin/config controls, and help "
            "or version modes."
        ),
        references=(
            "https://github.com/skylot/jadx",
            "https://raw.githubusercontent.com/skylot/jadx/master/README.md",
            "https://raw.githubusercontent.com/skylot/jadx/master/jadx-cli/src/main/java/jadx/cli/JadxCLIArgs.java",
        ),
        verified_parameters=(
            "output_dir",
            "output_dir_src",
            "output_dir_res",
            "no_resources",
            "no_sources",
            "threads_count",
            "single_class",
            "single_class_output",
            "output_format",
            "export_gradle",
            "export_gradle_type",
            "decompilation_mode",
            "show_bad_code",
            "no_xml_pretty_print",
            "no_imports",
            "no_debug_info",
            "add_debug_lines",
            "no_inline_anonymous",
            "no_inline_methods",
            "no_move_inner_classes",
            "no_inline_kotlin_lambda",
            "no_finally",
            "no_restore_switch_over_string",
            "no_replace_consts",
            "escape_unicode",
            "respect_bytecode_access_modifiers",
            "mappings_path",
            "mappings_mode",
            "deobf",
            "deobf_min",
            "deobf_max",
            "deobf_whitelist",
            "deobf_cfg_file",
            "deobf_cfg_file_mode",
            "deobf_res_name_source",
            "use_source_name_as_class_name_alias",
            "source_name_repeat_limit",
            "use_kotlin_methods_for_var_names",
            "use_headers_for_detect_resource_extensions",
            "rename_flags",
            "integer_format",
            "type_update_limit",
            "fs_case_sensitive",
            "cfg",
            "raw_cfg",
            "fallback",
            "use_dx",
            "comments_level",
            "log_level",
            "verbose",
            "quiet",
            "disable_plugins",
            "config",
            "save_config",
            "print_files",
            "plugin_options",
            "version",
            "help",
        ),
    ),
    "apk2gold": SourceReview(
        note=(
            "Reviewed against upstream Apk2Gold README usage and shell wrapper. "
            "The wrapper accepts a single APK package argument, prints "
            "'Usage: apk2gold apk_file' when it is missing, and derives the "
            "output directory from the APK filename."
        ),
        references=(
            "https://github.com/lxdvs/apk2gold",
            "https://raw.githubusercontent.com/lxdvs/apk2gold/master/README.md",
            "https://raw.githubusercontent.com/lxdvs/apk2gold/master/apk2gold",
        ),
        verified_parameters=(
            "apk_file",
        ),
    ),
    "androguard": SourceReview(
        note=(
            "Reviewed against upstream Androguard Poetry script entry point "
            "and Click CLI definitions for the top-level verbose flag and "
            "axml, arsc, decompile, sign, apkid, analyze, disassemble, trace, "
            "dtrace, dump, and cg subcommands, including positional input "
            "files, APK lists, output controls, resource selectors, "
            "decompiler/callgraph settings, certificate hash modes, sessions, "
            "offset/size controls, tracing modules, and package names."
        ),
        references=(
            "https://github.com/androguard/androguard",
            "https://raw.githubusercontent.com/androguard/androguard/master/pyproject.toml",
            "https://raw.githubusercontent.com/androguard/androguard/master/androguard/cli/cli.py",
        ),
        verified_parameters=(
            "command",
            "input_file",
            "apk_files",
            "output_file",
            "output_dir",
            "resource",
            "package",
            "locale",
            "resource_type",
            "resource_id",
            "list_packages",
            "list_locales",
            "list_types",
            "graph_format",
            "jar",
            "limit",
            "decompiler",
            "hash_algo",
            "all_hashes",
            "show",
            "session",
            "offset",
            "size",
            "modules",
            "enable_ui",
            "package_name",
            "output_type",
            "classname",
            "methodname",
            "descriptor",
            "accessflag",
            "no_isolated",
            "verbose",
        ),
    ),
    "radare2": SourceReview(
        note=(
            "Reviewed against upstream radare2 r2 command-line usage and "
            "option parser source for architecture/bits/base/load/seek "
            "controls, command/eval/script execution, project and patch "
            "inputs, rarun profiles, debug and write modes, quiet/JSON/version/"
            "help output, sandbox and startup loading controls, binary loading "
            "modes, plugin listing, name/demangle/string behavior, connection "
            "mode, and stderr/NUL output toggles."
        ),
        references=(
            "https://github.com/radareorg/radare2",
            "https://raw.githubusercontent.com/radareorg/radare2/master/libr/main/radare2.c",
        ),
        verified_parameters=(
            "arch",
            "bits",
            "base_addr",
            "map_addr",
            "seek_addr",
            "command",
            "eval_config",
            "script",
            "pre_script",
            "project",
            "patch_file",
            "rarun_profile",
            "rarun_directive",
            "debug",
            "debug_backend",
            "analyze",
            "write",
            "quiet",
            "quit_after_commands",
            "quick_quiet",
            "json",
            "version",
            "lib_version",
            "help",
            "long_help",
            "sandbox",
            "no_user_config",
            "no_scripts_plugins",
            "no_bin_info",
            "bin_structures_only",
            "full_file",
            "force_bin_plugin",
            "asm_os",
            "raw_names",
            "no_demangle",
            "list_io_plugins",
            "list_core_plugins",
            "no_exec",
            "no_extr",
            "no_strings",
            "load_strings",
            "connect_mode",
            "zero_sep",
            "stderr_to_stdout",
            "no_stderr",
        ),
    ),
    "ghidra": SourceReview(
        note=(
            "Reviewed against upstream Ghidra AnalyzeHeadless argument enum "
            "and usage builder for project location/name input, import or "
            "process modes, pre/post scripts with arguments, script and "
            "properties paths, log destinations, overwrite/mirror/recursive/"
            "read-only/delete/no-analysis controls, processor/compiler "
            "selection, analysis timeout, server authentication/commit modes, "
            "CPU limits, library search paths, loader selection, and loader "
            "argument forwarding."
        ),
        references=(
            "https://github.com/NationalSecurityAgency/ghidra",
            "https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/AnalyzeHeadless.java",
        ),
        verified_parameters=(
            "project_name",
            "folder_path",
            "import_path",
            "process_path",
            "pre_script",
            "pre_script_args",
            "post_script",
            "post_script_args",
            "script_path",
            "properties_path",
            "script_log",
            "log_file",
            "overwrite",
            "mirror",
            "recursive",
            "recursive_depth",
            "read_only",
            "delete_project",
            "no_analysis",
            "processor",
            "cspec",
            "analysis_timeout_per_file",
            "keystore",
            "connect",
            "connect_user",
            "password",
            "commit",
            "commit_comment",
            "ok_to_delete",
            "max_cpu",
            "library_search_paths",
            "loader",
            "loader_args",
        ),
    ),
    "mobsf": SourceReview(
        note=(
            "Reviewed against upstream MobSF run.sh server entrypoint. The "
            "script accepts one optional positional bind argument in IP:PORT "
            "form, validates IPv4 address and port, and otherwise defaults to "
            "the built-in [::]:8000 binding before launching gunicorn."
        ),
        references=(
            "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
            "https://raw.githubusercontent.com/MobSF/Mobile-Security-Framework-MobSF/master/run.sh",
        ),
        verified_parameters=(
            "bind_host",
            "bind_port",
        ),
    ),
    "frida": SourceReview(
        note=(
            "Reviewed against upstream frida-tools REPL and application "
            "argparse definitions for device/remote connection selectors, "
            "target attachment/spawn modes, stdio/aux/realm/runtime/debug "
            "controls, options files and version output, script loading, "
            "parameters, CModule/codeshare/eval inputs, quiet/timeout/pause "
            "behavior, logging, lifecycle, Java.perform, and auto-reload flags."
        ),
        references=(
            "https://github.com/frida/frida-tools",
            "https://raw.githubusercontent.com/frida/frida-tools/main/frida_tools/application.py",
            "https://raw.githubusercontent.com/frida/frida-tools/main/frida_tools/repl.py",
        ),
        verified_parameters=(
            "device_id",
            "usb",
            "remote",
            "host",
            "certificate",
            "origin",
            "token",
            "keepalive_interval",
            "device_option",
            "p2p",
            "stun_server",
            "relay",
            "spawn_file",
            "attach_frontmost",
            "attach_name",
            "attach_identifier",
            "attach_pid",
            "await_spawn",
            "stdio",
            "aux",
            "realm",
            "runtime",
            "debug",
            "squelch_crash",
            "options_file",
            "load_script",
            "parameters_json",
            "cmodule",
            "toolchain",
            "codeshare",
            "eval_code",
            "quiet",
            "timeout",
            "pause",
            "output_file",
            "eternalize",
            "exit_on_error",
            "kill_on_exit",
            "auto_perform",
            "auto_reload",
            "no_auto_reload",
            "version",
        ),
    ),
    "objection": SourceReview(
        note=(
            "Reviewed against upstream Objection Click CLI definitions for "
            "global connection/API/target controls and the api, start, run, "
            "version, patchipa, patchapk, and signapk subcommands, including "
            "plugin/startup inputs, hook debugging, Frida Gadget patching, "
            "APK signing controls, manifest/resource handling, and positional "
            "signing sources."
        ),
        references=(
            "https://github.com/sensepost/objection",
            "https://raw.githubusercontent.com/sensepost/objection/master/objection/console/cli.py",
        ),
        verified_parameters=(
            "command",
            "network",
            "local",
            "host",
            "port",
            "api_host",
            "api_port",
            "name",
            "serial",
            "debug",
            "spawn",
            "no_pause",
            "foremost",
            "debugger",
            "uid",
            "plugin_folder",
            "quiet",
            "startup_command",
            "file_commands",
            "startup_script",
            "enable_api",
            "hook_debug",
            "runtime_command",
            "source",
            "architecture",
            "gadget_version",
            "codesign_signature",
            "provision_file",
            "binary_name",
            "skip_cleanup",
            "pause",
            "unzip_unicode",
            "enable_debug",
            "network_security_config",
            "skip_resources",
            "skip_signing",
            "target_class",
            "use_aapt2",
            "gadget_config",
            "script_source",
            "ignore_nativelibs",
            "manifest",
            "only_main_classes",
            "fix_concurrency_to",
            "bundle_id",
            "sources",
        ),
    ),
    "steghide": SourceReview(
        note=(
            "Reviewed against steghide documentation and packaged man page for "
            "commands, embed/extract/info file arguments, encryption and "
            "compression controls, checksum/name embedding toggles, passphrase, "
            "verbosity, quiet mode, and overwrite behavior."
        ),
        references=(
            "https://steghide.sourceforge.net/documentation.php",
            "https://manpages.debian.org/bookworm/steghide/steghide.1.en.html",
        ),
        verified_parameters=(
            "command",
            "extract",
            "embed_file",
            "cover_file",
            "stego_file",
            "extract_file",
            "output_file",
            "encryption",
            "compression_level",
            "no_compress",
            "no_checksum",
            "no_embed_name",
            "passphrase",
            "verbose",
            "quiet",
            "force",
        ),
    ),
    "stegcracker": SourceReview(
        note=(
            "Reviewed against upstream StegCracker README usage and argparse "
            "definitions for stego input file, optional wordlist, output file, "
            "thread count, chunk size, quiet mode, version, and verbose mode."
        ),
        references=(
            "https://github.com/Paradoxis/StegCracker",
            "https://raw.githubusercontent.com/Paradoxis/StegCracker/master/README.md",
            "https://raw.githubusercontent.com/Paradoxis/StegCracker/master/stegcracker/__main__.py",
        ),
        verified_parameters=(
            "wordlist",
            "output_file",
            "threads",
            "chunk_size",
            "quiet",
            "version",
            "verbose",
        ),
    ),
    "stegocracker": SourceReview(
        note=(
            "Reviewed against upstream StegoCracker installer and CLI argparse "
            "entrypoint for the installed stego command, image input/output, "
            "message encoding, image read/decode mode, audio file input/output, "
            "MP3-to-WAV conversion, version display, and self-update."
        ),
        references=(
            "https://github.com/W1LDN16H7/StegoCracker",
            "https://raw.githubusercontent.com/W1LDN16H7/StegoCracker/master/README.md",
            "https://raw.githubusercontent.com/W1LDN16H7/StegoCracker/master/install.sh",
            "https://raw.githubusercontent.com/W1LDN16H7/StegoCracker/master/stego/StegoCracker",
        ),
        verified_parameters=(
            "input_image",
            "output_image",
            "message",
            "read_from",
            "encode",
            "decode",
            "music_file",
            "output_music",
            "convert",
            "version",
            "update",
        ),
    ),
    "nmap": SourceReview(
        note=(
            "Reviewed against the official Nmap reference guide for target "
            "syntax and adapter flags: -p, -sS, -sT, -sU, -sn, -sV, -O, -sC, "
            "-T, --top-ports, --min-rate, --script, --script-args, --exclude."
        ),
        references=(
            "https://nmap.org/book/man.html",
            "https://nmap.org/book/man-briefoptions.html",
        ),
        verified_parameters=(
            "ports",
            "scan_type",
            "service_version",
            "os_detection",
            "default_scripts",
            "timing",
            "top_ports",
            "rate",
            "scripts",
            "script_args",
            "exclude_hosts",
        ),
    ),
    "portscan": SourceReview(
        note=(
            "Reviewed against the official Nmap reference guide. The built-in "
            "portscan registry command is a fixed nmap wrapper using -O for OS "
            "detection and -Pn to skip host discovery, so the adapter exposes "
            "only a host target alias and no generated CLI options."
        ),
        references=(
            "https://nmap.org/book/man.html",
            "https://nmap.org/book/man-host-discovery.html",
            "https://nmap.org/book/man-os-detection.html",
        ),
        verified_parameters=(
            "host",
        ),
    ),
    "host2ip": SourceReview(
        note=(
            "Reviewed against the Python standard library socket resolver API. "
            "The registry command resolves a single hostname with "
            "socket.gethostbyname, so the adapter exposes only a hostname "
            "target alias and no generated CLI options."
        ),
        references=(
            "https://docs.python.org/3/library/socket.html#socket.gethostbyname",
        ),
        verified_parameters=(
            "hostname",
        ),
    ),
    "isitdown": SourceReview(
        note=(
            "Reviewed against the Python standard library urllib.request API. "
            "The registry command normalizes a hostname to HTTPS when needed "
            "and calls urllib.request.urlopen with a fixed timeout, so the "
            "adapter exposes only a URL target alias and no generated CLI "
            "options."
        ),
        references=(
            "https://docs.python.org/3/library/urllib.request.html#urllib.request.urlopen",
        ),
        verified_parameters=(
            "url",
        ),
    ),
    "redhawk": SourceReview(
        note=(
            "Reviewed against upstream RED_HAWK rhawk.php. The script has no "
            "CLI parser or positional arguments; target website, HTTP/HTTPS "
            "selection, scan type, fix/update actions, and follow-up prompts "
            "are all read from stdin. The adapter is therefore intentionally "
            "interactive-only and removes generated scanner/depth/output "
            "parameters."
        ),
        references=(
            "https://github.com/Tuhinshubhra/RED_HAWK",
            "https://raw.githubusercontent.com/Tuhinshubhra/RED_HAWK/master/rhawk.php",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "dracnmap": SourceReview(
        note=(
            "Reviewed against upstream Dracnmap README and dracnmap-v2.2.sh. "
            "The shell script has no CLI parser or positional arguments; "
            "scan profile, output mode, NSE script, ping mode, and targets "
            "are all selected through stdin menus and xterm-launched nmap "
            "commands. The adapter is therefore intentionally interactive-only "
            "and removes generated nmap-style parameters."
        ),
        references=(
            "https://github.com/Screetsec/Dracnmap",
            "https://raw.githubusercontent.com/Screetsec/Dracnmap/master/README.md",
            "https://raw.githubusercontent.com/Screetsec/Dracnmap/master/dracnmap-v2.2.sh",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "reconspider": SourceReview(
        note=(
            "Reviewed against upstream ReconSpider README and reconspider.py. "
            "The entrypoint has no CLI parser or positional arguments; OSINT "
            "modules and targets are selected through a stdin menu/REPL. The "
            "adapter is therefore intentionally interactive-only and removes "
            "generated API key, resolver, passive, timeout, depth, output, and "
            "JSON parameters."
        ),
        references=(
            "https://github.com/bhavsec/reconspider",
            "https://raw.githubusercontent.com/bhavsec/reconspider/master/README.md",
            "https://raw.githubusercontent.com/bhavsec/reconspider/master/reconspider.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "xerosploit": SourceReview(
        note=(
            "Reviewed against upstream Xerosploit xerosploit.py. The tool has "
            "no CLI parser or positional arguments; network scan/start, "
            "gateway/interface configuration, target selection, and module "
            "execution are all read from stdin. The adapter is therefore "
            "intentionally interactive-only and removes generated network scan "
            "parameters."
        ),
        references=(
            "https://github.com/LionSec/xerosploit",
            "https://raw.githubusercontent.com/LionSec/xerosploit/master/xerosploit.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "nuclei": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery Nuclei docs for "
            "template path/workflow, tags, severity, rate-limit, proxy, "
            "headless, and exclude-template flags."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/nuclei/running",
        ),
        verified_parameters=(
            "severity",
            "tags",
            "template_path",
            "rate_limit",
            "proxy",
            "workflows",
            "exclude_templates",
            "headless",
            "interactsh",
        ),
    ),
    "ffuf": SourceReview(
        note=(
            "Reviewed against the upstream ffuf README usage/help for target "
            "URL, wordlist, thread, extension, redirect, proxy, match/filter, "
            "and recursion flags."
        ),
        references=(
            "https://github.com/ffuf/ffuf",
        ),
        verified_parameters=(
            "wordlist",
            "threads",
            "extensions",
            "match_codes",
            "recursive",
            "follow_redirects",
            "proxy",
            "fuzz_keyword",
            "host_header",
            "recursion_depth",
            "filter_codes",
            "filter_size",
            "filter_words",
            "add_slash",
        ),
    ),
    "httpx": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery httpx usage docs for "
            "single URL/list input, probes, match/filter codes, rate/thread "
            "controls, proxy/header/method, timeout, output, and JSON flags."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/httpx/usage",
        ),
        verified_parameters=(
            "input_file",
            "status_code",
            "title",
            "tech_detect",
            "content_length",
            "match_codes",
            "filter_codes",
            "threads",
            "rate_limit",
            "ports",
            "path",
            "follow_redirects",
            "proxy",
            "headers",
            "method",
            "timeout",
            "output_file",
            "json_output",
            "silent",
        ),
    ),
    "subfinder": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery Subfinder usage docs "
            "for domain list input, source selection/filtering, recursive and "
            "active modes, resolver/rate controls, output formats, config, "
            "proxy, and debug/output controls."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/subfinder/usage",
        ),
        verified_parameters=(
            "input_file",
            "sources",
            "exclude_sources",
            "all_sources",
            "recursive",
            "active",
            "match",
            "filter",
            "resolvers",
            "resolver_file",
            "rate_limit",
            "rate_limits",
            "threads",
            "timeout",
            "max_time",
            "output_file",
            "json_output",
            "output_dir",
            "collect_sources",
            "include_ip",
            "exclude_ip",
            "config_file",
            "provider_config",
            "proxy",
            "silent",
            "verbose",
        ),
    ),
    "gitleaks": SourceReview(
        note=(
            "Reviewed against the upstream Gitleaks README usage/options for "
            "redaction, git log options, config/baseline/ignore files, rule "
            "selection, limits, report output, logging, banner/color, and "
            "verbose flags."
        ),
        references=(
            "https://github.com/gitleaks/gitleaks",
        ),
        verified_parameters=(
            "redact",
            "log_opts",
            "config_path",
            "baseline_path",
            "ignore_path",
            "enable_rule",
            "exit_code",
            "follow_symlinks",
            "ignore_allow",
            "max_decode_depth",
            "max_archive_depth",
            "max_target_mb",
            "report_format",
            "report_path",
            "report_template",
            "log_level",
            "no_banner",
            "no_color",
            "verbose",
        ),
    ),
    "trufflehog": SourceReview(
        note=(
            "Reviewed against the upstream TruffleHog README for filesystem "
            "scans and global flags covering JSON/GitHub output, concurrency, "
            "verification controls, result filtering, entropy/config/logging, "
            "and fail-on-result behavior."
        ),
        references=(
            "https://github.com/trufflesecurity/trufflehog",
        ),
        verified_parameters=(
            "json_output",
            "github_actions",
            "concurrency",
            "no_verification",
            "results",
            "no_color",
            "allow_verification_overlap",
            "filter_unverified",
            "filter_entropy",
            "config_path",
            "print_avg_detector_time",
            "fail",
            "log_level",
        ),
    ),
    "whatweb": SourceReview(
        note=(
            "Reviewed against the upstream WhatWeb README usage help for target "
            "input and URL modifiers, aggression, HTTP/auth/proxy controls, "
            "plugin listing/selection/search, output/log formats, thread/"
            "timeout/wait performance controls, output buffering, and help/"
            "debug/version flags."
        ),
        references=(
            "https://github.com/urbanadventurer/WhatWeb",
            "https://raw.githubusercontent.com/urbanadventurer/WhatWeb/master/README.md",
        ),
        verified_parameters=(
            "input_file",
            "url_prefix",
            "url_suffix",
            "url_pattern",
            "aggression",
            "user_agent",
            "header",
            "follow_redirect",
            "max_redirects",
            "basic_auth",
            "cookie",
            "cookiejar",
            "no_cookies",
            "proxy",
            "proxy_user",
            "list_plugins",
            "info_plugins",
            "info_plugin_search",
            "search_plugins",
            "plugins",
            "grep",
            "custom_plugin",
            "dorks",
            "verbose",
            "color",
            "quiet",
            "no_errors",
            "log_brief",
            "log_verbose",
            "log_errors",
            "log_xml",
            "log_json",
            "log_sql",
            "log_sql_create",
            "log_json_verbose",
            "log_magictree",
            "log_object",
            "log_mongo_database",
            "log_mongo_collection",
            "log_mongo_host",
            "log_mongo_username",
            "log_mongo_password",
            "log_elastic_index",
            "log_elastic_host",
            "max_threads",
            "open_timeout",
            "read_timeout",
            "wait",
            "output_sync",
            "output_buffer_size",
            "short_help",
            "debug",
            "version",
        ),
    ),
    "hatcloud": SourceReview(
        note=(
            "Reviewed against upstream HatCloud Ruby OptionParser definitions. "
            "The registry command uses the -b/--byp CloudFlare bypass lookup "
            "with the supplied target domain; the upstream -o/--out option is "
            "only a placeholder in the script, so the adapter exposes only a "
            "domain target alias and no generated CLI options."
        ),
        references=(
            "https://github.com/HatBashBR/HatCloud",
            "https://raw.githubusercontent.com/HatBashBR/HatCloud/master/hatcloud.rb",
        ),
        verified_parameters=(
            "domain",
        ),
    ),
    "gospider": SourceReview(
        note=(
            "Reviewed against upstream GoSpider README usage output for single "
            "site crawling, output/proxy/user-agent/cookie/header controls, "
            "URL/domain filters, concurrency/depth/delay/timeouts, content "
            "source toggles, third-party source options, and output/debug "
            "modes."
        ),
        references=(
            "https://github.com/jaeles-project/gospider",
            "https://raw.githubusercontent.com/jaeles-project/gospider/master/README.md",
        ),
        verified_parameters=(
            "site",
            "output_dir",
            "proxy",
            "user_agent",
            "cookie",
            "header",
            "burp_request",
            "blacklist",
            "whitelist",
            "whitelist_domain",
            "threads",
            "concurrent",
            "depth",
            "delay",
            "random_delay",
            "timeout",
            "base",
            "js",
            "subs",
            "sitemap",
            "robots",
            "other_source",
            "include_subs",
            "include_other_source",
            "debug",
            "json_output",
            "verbose",
            "length",
            "filter_length",
            "raw",
            "quiet",
            "no_redirect",
            "version",
        ),
    ),
    "terminal-multiplexer": SourceReview(
        note=(
            "Reviewed against upstream Tilix manpage and application option "
            "registration for the current registry command shape. The MCP "
            "adapter is intentionally version-only and runs tilix --version; "
            "it does not expose generic command, session, or layout parameters "
            "outside this registered command."
        ),
        references=(
            "https://github.com/gnunn1/tilix",
            "https://raw.githubusercontent.com/gnunn1/tilix/master/data/man/tilix.1",
            "https://raw.githubusercontent.com/gnunn1/tilix/master/source/gx/tilix/application.d",
        ),
        verified_parameters=(
            "version",
        ),
    ),
    "instabrute": SourceReview(
        note=(
            "Reviewed against the archived instaBrute README and optparse "
            "definitions. The registry intentionally has no run_command and "
            "the MCP endpoint remains policy/info-only; adapter parameters "
            "mirror the documented legacy username-file, dictionary, single "
            "username, delay, and proxy options for inventory parity only."
        ),
        references=(
            "https://github.com/chinoogawa/instaBrute",
            "https://raw.githubusercontent.com/chinoogawa/instaBrute/master/README.md",
            "https://raw.githubusercontent.com/chinoogawa/instaBrute/master/instaBrute.py",
        ),
        verified_parameters=(
            "user_file",
            "dictionary",
            "username",
            "delay",
            "proxy",
        ),
    ),
    "hashbuster": SourceReview(
        note=(
            "Reviewed against upstream Hash-Buster README and argparse "
            "definitions. The registry command now uses buster {target}; "
            "the adapter generates the source-backed input selector before "
            "the target (-s single hash, -f file, or -d directory) and the "
            "documented -t thread count option."
        ),
        references=(
            "https://github.com/s0md3v/Hash-Buster",
            "https://raw.githubusercontent.com/s0md3v/Hash-Buster/master/README.md",
            "https://raw.githubusercontent.com/s0md3v/Hash-Buster/master/hash.py",
        ),
        verified_parameters=(
            "input_type",
            "threads",
        ),
    ),
    "evilurl": SourceReview(
        note=(
            "Reviewed against upstream EvilURL argparse definitions. The "
            "registry command now supplies the target domain through the "
            "documented -d option, and the adapter exposes only the "
            "source-backed generation, connection check, output file, and "
            "availability-check flags."
        ),
        references=(
            "https://github.com/UndeadSec/EvilURL",
            "https://raw.githubusercontent.com/UndeadSec/EvilURL/master/evilurl.py",
        ),
        verified_parameters=(
            "generate",
            "check_connection",
            "output_file",
            "check_availability",
        ),
    ),
    "knockmail": SourceReview(
        note=(
            "Reviewed against upstream KnockMail argparse definitions. The "
            "registry command stays non-targeted, while the adapter generates "
            "the documented --email option from target/email input or the "
            "-f file option for batch verification; generic OSINT resolver, "
            "API key, timeout, and JSON/output parameters were removed."
        ),
        references=(
            "https://github.com/heywoodlh/KnockMail",
            "https://raw.githubusercontent.com/heywoodlh/KnockMail/master/knockmail.py",
        ),
        verified_parameters=(
            "email",
            "input_file",
        ),
    ),
    "socialscan": SourceReview(
        note=(
            "Reviewed against upstream socialscan README and CLI argparse "
            "definitions. The registry target is the positional username or "
            "email query; the adapter exposes source-backed platform "
            "selection, result grouping, availability filtering, token "
            "caching, proxy-list, verbosity, profile URL, JSON output, and "
            "debug flags."
        ),
        references=(
            "https://github.com/iojw/socialscan",
            "https://raw.githubusercontent.com/iojw/socialscan/master/README.md",
            "https://raw.githubusercontent.com/iojw/socialscan/master/socialscan/cli.py",
        ),
        verified_parameters=(
            "platforms",
            "view_by",
            "available_only",
            "cache_tokens",
            "proxy_list",
            "verbose",
            "show_urls",
            "json_file",
            "debug",
        ),
    ),
    "appcheck": SourceReview(
        note=(
            "Reviewed against upstream underhanded.sh. The script has no "
            "CLI parser or positional arguments; app selection, custom URL, "
            "and redirect URL are read interactively from stdin before the "
            "script starts its local PHP/ngrok workflow. The adapter is "
            "therefore intentionally interactive-only and removes generated "
            "scanner/depth/output parameters."
        ),
        references=(
            "https://github.com/jakuta-tech/underhanded",
            "https://raw.githubusercontent.com/jakuta-tech/underhanded/master/underhanded.sh",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "showme": SourceReview(
        note=(
            "Reviewed against upstream SMWYG.py and README. The tool has no "
            "CLI parser or positional arguments; domain and email searches "
            "are selected through stdin menu choices. The adapter is "
            "therefore intentionally interactive-only and removes generated "
            "hash, wordlist, git-secret, and OSINT parameters."
        ),
        references=(
            "https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got",
            "https://raw.githubusercontent.com/Viralmaniar/SMWYG-Show-Me-What-You-Got/master/README.md",
            "https://raw.githubusercontent.com/Viralmaniar/SMWYG-Show-Me-What-You-Got/master/SMWYG.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "goblin-wordgenerator": SourceReview(
        note=(
            "Reviewed against upstream Goblin WordGenerator source. The tool "
            "has no CLI parser or positional arguments; size range, personal "
            "data, output filename, uppercase, special-character, and numeric "
            "choices are all read via stdin prompts. The adapter is therefore "
            "intentionally interactive-only and removes generated hashcat-style "
            "wordlist/hash parameters."
        ),
        references=(
            "https://github.com/UndeadSec/GoblinWordGenerator",
            "https://raw.githubusercontent.com/UndeadSec/GoblinWordGenerator/master/goblin.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "allinone-socialmedia": SourceReview(
        note=(
            "Reviewed against upstream Brute_Force README and OptionParser "
            "definitions for the current registry command shape. The MCP "
            "adapter is intentionally help-only and runs Brute_Force.py -h; "
            "it does not expose the brute-force service, password, list, or "
            "proxy parameters outside this registered help command."
        ),
        references=(
            "https://github.com/Matrix07ksa/Brute_Force",
            "https://raw.githubusercontent.com/Matrix07ksa/Brute_Force/master/README.md",
            "https://raw.githubusercontent.com/Matrix07ksa/Brute_Force/master/Brute_Force.py",
        ),
        verified_parameters=(
            "help",
        ),
    ),
    "faceshell": SourceReview(
        note=(
            "Reviewed against upstream Brute_Force README and OptionParser "
            "definitions for Facebook mode. The registry command now keeps "
            "the source-backed -f/--facebook target in run_command and lets "
            "the adapter generate the documented password-list, single "
            "password, and proxy-list options while preserving the previous "
            "default wordlist.txt behavior."
        ),
        references=(
            "https://github.com/Matrix07ksa/Brute_Force",
            "https://raw.githubusercontent.com/Matrix07ksa/Brute_Force/master/README.md",
            "https://raw.githubusercontent.com/Matrix07ksa/Brute_Force/master/Brute_Force.py",
        ),
        verified_parameters=(
            "wordlist",
            "password",
            "proxy_file",
        ),
    ),
    "holehe": SourceReview(
        note=(
            "Reviewed against upstream Holehe argparse definitions for email "
            "target execution, used-site filtering, terminal color/clear "
            "toggles, password-recovery suppression, CSV output, and timeout."
        ),
        references=(
            "https://github.com/megadose/holehe",
            "https://raw.githubusercontent.com/megadose/holehe/master/holehe/core.py",
            "https://raw.githubusercontent.com/megadose/holehe/master/README.md",
        ),
        verified_parameters=(
            "only_used",
            "no_color",
            "no_clear",
            "no_password_recovery",
            "csv",
            "timeout",
        ),
    ),
    "breacher": SourceReview(
        note=(
            "Reviewed against upstream Breacher argparse definitions for URL "
            "target execution plus path prefix, panel type, and fast-mode "
            "controls."
        ),
        references=(
            "https://github.com/s0md3v/Breacher",
            "https://raw.githubusercontent.com/s0md3v/Breacher/master/breacher.py",
            "https://raw.githubusercontent.com/s0md3v/Breacher/master/README.md",
        ),
        verified_parameters=(
            "path",
            "panel_type",
            "fast",
        ),
    ),
    "secretfinder": SourceReview(
        note=(
            "Reviewed against upstream SecretFinder argparse definitions for "
            "URL/file/folder input, JavaScript extraction, output destination, "
            "regex filtering, Burp export mode, cookies, ignore/only filters, "
            "custom headers, and proxy settings. The registry command now uses "
            "-i {target} instead of the help-only command."
        ),
        references=(
            "https://github.com/m4ll0k/SecretFinder",
            "https://raw.githubusercontent.com/m4ll0k/SecretFinder/master/SecretFinder.py",
            "https://raw.githubusercontent.com/m4ll0k/SecretFinder/master/README.md",
        ),
        verified_parameters=(
            "extract",
            "output_file",
            "regex",
            "burp",
            "cookie",
            "ignore",
            "only",
            "headers",
            "proxy",
        ),
    ),
    "maigret": SourceReview(
        note=(
            "Reviewed against upstream Maigret ArgumentParser definitions for "
            "username targets, request timeout/retry/concurrency controls, "
            "recursion/extraction and identifier settings, database/update and "
            "cookie controls, repeated ignore/site filters, proxy settings, "
            "site filtering, parse/self-check/stats modes, console verbosity, "
            "report formats, JSON output type, and report sorting."
        ),
        references=(
            "https://github.com/soxoj/maigret",
            "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/maigret.py",
            "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/__main__.py",
            "https://raw.githubusercontent.com/soxoj/maigret/main/README.md",
        ),
        verified_parameters=(
            "extra_usernames",
            "timeout",
            "retries",
            "max_connections",
            "no_recursion",
            "no_extracting",
            "id_type",
            "permute",
            "db_file",
            "no_autoupdate",
            "force_update",
            "cookies_jar_file",
            "ignore_ids",
            "folder_output",
            "proxy",
            "tor_proxy",
            "i2p_proxy",
            "with_domains",
            "all_sites",
            "top_sites",
            "tags",
            "exclude_tags",
            "sites",
            "use_disabled_sites",
            "parse_url",
            "self_check",
            "stats",
            "print_not_found",
            "print_errors",
            "verbose",
            "info",
            "debug",
            "no_color",
            "no_progressbar",
            "txt",
            "csv",
            "html",
            "pdf",
            "md",
            "graph",
            "json_report",
            "reports_sorting",
        ),
    ),
    "spiderfoot": SourceReview(
        note=(
            "Reviewed against upstream SpiderFoot sf.py argparse definitions "
            "for debug/listen/module/correlation/target scan controls, event "
            "type and use-case selection, output formatting, field/header "
            "controls, strict/quiet/version modes, and module concurrency."
        ),
        references=(
            "https://github.com/smicallef/spiderfoot",
            "https://raw.githubusercontent.com/smicallef/spiderfoot/master/sf.py",
            "https://raw.githubusercontent.com/smicallef/spiderfoot/master/README.md",
        ),
        verified_parameters=(
            "debug",
            "listen",
            "modules",
            "list_modules",
            "correlate",
            "event_types",
            "use_case",
            "list_types",
            "output_format",
            "no_headers",
            "strip_newlines",
            "include_source",
            "max_data_length",
            "delimiter",
            "filter",
            "show_event_types",
            "strict_mode",
            "quiet",
            "version",
            "max_threads",
        ),
    ),
    "theHarvester": SourceReview(
        note=(
            "Reviewed against the upstream theHarvester argparse definitions "
            "and README for domain/source selection, result limit/start offset, "
            "proxy/Shodan/screenshot controls, DNS lookup/resolve/brute-force "
            "options, report filename, API endpoint wordlist/scan, and quiet "
            "mode."
        ),
        references=(
            "https://github.com/laramies/theHarvester",
            "https://raw.githubusercontent.com/laramies/theHarvester/master/theHarvester/__main__.py",
        ),
        verified_parameters=(
            "sources",
            "limit",
            "start",
            "proxies",
            "shodan",
            "screenshot",
            "dns_server",
            "takeover",
            "dns_resolve",
            "dns_lookup",
            "dns_brute",
            "filename",
            "wordlist",
            "api_scan",
            "quiet",
        ),
    ),
    "sherlock": SourceReview(
        note=(
            "Reviewed against the upstream Sherlock argparse definitions for "
            "username target input, verbosity, file/folder output controls, "
            "CSV/XLSX/TXT/JSON outputs, repeated --site selection, proxy, "
            "response dumping, timeout, print controls, color, browse, local "
            "site data, NSFW inclusion, and exclusion override flags."
        ),
        references=(
            "https://github.com/sherlock-project/sherlock",
            "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/sherlock.py",
        ),
        verified_parameters=(
            "verbose",
            "folder_output",
            "output_file",
            "csv_output",
            "xlsx_output",
            "sites",
            "site_list",
            "proxy",
            "dump_response",
            "json_file",
            "timeout",
            "print_all",
            "print_found",
            "no_color",
            "browse",
            "local",
            "nsfw",
            "txt_output",
            "ignore_exclusions",
        ),
    ),
    "amass": SourceReview(
        note=(
            "Reviewed against the OWASP Amass user guide for the enum command, "
            "including config/output controls, active/passive modes, alteration "
            "and brute-force inputs, source include/exclude lists, resolver/QPS "
            "controls, ports, scripts, timeout, and verbose output."
        ),
        references=(
            "https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md",
        ),
        verified_parameters=(
            "config_file",
            "output_dir",
            "no_color",
            "silent",
            "active",
            "passive",
            "alts",
            "alteration_wordlist",
            "alteration_masks",
            "blacklist",
            "blacklist_file",
            "brute",
            "domain_file",
            "exclude_sources",
            "exclude_file",
            "include_sources",
            "include_file",
            "interface",
            "include_ip",
            "ipv4",
            "ipv6",
            "list_sources",
            "log_file",
            "max_depth",
            "min_for_recursive",
            "known_names_file",
            "no_recursive",
            "output_file",
            "output_prefix",
            "ports",
            "resolvers",
            "resolver_file",
            "dns_qps",
            "resolver_qps",
            "scripts_dir",
            "timeout",
            "trusted_resolvers",
            "trusted_resolver_file",
            "trusted_qps",
            "verbose",
            "wordlist",
            "wordlist_masks",
        ),
    ),
    "masscan": SourceReview(
        note=(
            "Reviewed against the upstream masscan README for port selection, "
            "rate/config echo, banner-grabbing source settings, include/exclude "
            "files, output formats/files, and readscan replay."
        ),
        references=(
            "https://github.com/robertdavidgraham/masscan",
        ),
        verified_parameters=(
            "ports",
            "rate",
            "config_file",
            "echo",
            "banners",
            "source_ip",
            "source_port",
            "exclude_file",
            "include_file",
            "output_xml",
            "output_json",
            "output_list",
            "output_grepable",
            "output_format",
            "output_filename",
            "readscan",
        ),
    ),
    "rustscan": SourceReview(
        note=(
            "Reviewed against RustScan's upstream clap input definitions for "
            "ports/ranges, config/banner/output modes, resolver, batch/timeout "
            "limits, scan order, scripts, exclusions, UDP mode, and trailing "
            "nmap arguments."
        ),
        references=(
            "https://github.com/RustScan/RustScan",
            "https://github.com/RustScan/RustScan/blob/master/src/input.rs",
        ),
        verified_parameters=(
            "ports",
            "port_range",
            "no_config",
            "no_banner",
            "config_path",
            "greppable",
            "accessible",
            "resolver",
            "batch_size",
            "timeout",
            "tries",
            "ulimit",
            "scan_order",
            "scripts",
            "top",
            "exclude_ports",
            "exclude_addresses",
            "udp",
            "nmap_args",
        ),
    ),
    "rang3r": SourceReview(
        note=(
            "Reviewed against upstream rang3r optparse definitions. The script "
            "accepts only --ip for the IP address or range to scan, matching "
            "the registry command, so the adapter exposes only an ip target "
            "alias and no generated CLI options."
        ),
        references=(
            "https://github.com/floriankunushevci/rang3r",
            "https://raw.githubusercontent.com/floriankunushevci/rang3r/master/rang3r.py",
        ),
        verified_parameters=(
            "ip",
        ),
    ),
    "striker": SourceReview(
        note=(
            "Reviewed against upstream Striker source. The CLI reads a single "
            "positional target from sys.argv[1] and does not define named CLI "
            "flags for output format, timeout, scan depth, or user agent, so "
            "the adapter exposes only a domain target alias."
        ),
        references=(
            "https://github.com/s0md3v/Striker",
            "https://raw.githubusercontent.com/s0md3v/Striker/master/striker.py",
        ),
        verified_parameters=(
            "domain",
        ),
    ),
    "recondog": SourceReview(
        note=(
            "Reviewed against upstream ReconDog argparse definitions. The "
            "registry command now supplies -t with the MCP target; the adapter "
            "exposes the real -c module choice parameter and does not expose "
            "generic OSINT/API/output flags that the tool does not accept."
        ),
        references=(
            "https://github.com/s0md3v/ReconDog",
            "https://raw.githubusercontent.com/s0md3v/ReconDog/master/dog",
        ),
        verified_parameters=(
            "choice",
        ),
    ),
    "katana": SourceReview(
        note=(
            "Reviewed against official ProjectDiscovery Katana usage docs for "
            "target list input, crawl depth/strategy, JavaScript and known-file "
            "crawling, form/headless options, proxy/header settings, timeout/"
            "retry/rate/concurrency controls, crawl duration, output, JSONL, "
            "field selection, and quiet/color controls."
        ),
        references=(
            "https://docs.projectdiscovery.io/opensource/katana/usage",
        ),
        verified_parameters=(
            "input_file",
            "depth",
            "strategy",
            "js_crawl",
            "known_files",
            "automatic_form_fill",
            "form_extraction",
            "headless",
            "headless_options",
            "no_sandbox",
            "system_chrome",
            "proxy",
            "headers",
            "timeout",
            "retry",
            "rate_limit",
            "concurrency",
            "parallelism",
            "delay",
            "crawl_duration",
            "output_file",
            "json_output",
            "field",
            "silent",
            "no_color",
        ),
    ),
    "arjun": SourceReview(
        note=(
            "Reviewed against the upstream Arjun usage guide for target files, "
            "JSON/Burp/text outputs, HTTP method and included data, thread/"
            "delay/timeout/rate controls, wordlist/chunk settings, redirects, "
            "passive discovery, casing, and custom headers."
        ),
        references=(
            "https://github.com/s0md3v/Arjun",
            "https://github.com/s0md3v/Arjun/wiki/Usage",
        ),
        verified_parameters=(
            "input_file",
            "output_json",
            "output_burp",
            "output_text",
            "method",
            "include_data",
            "threads",
            "delay",
            "timeout",
            "stable",
            "rate_limit",
            "wordlist",
            "chunk_size",
            "disable_redirects",
            "passive",
            "casing",
            "headers",
        ),
    ),
    "gobuster": SourceReview(
        note=(
            "Reviewed against the upstream Gobuster README for dir mode "
            "wordlist/extensions, custom headers/cookies, length/status output, "
            "threads/delay/user-agent/timeout, file output, quiet/progress, "
            "expanded URLs, and slash-appending flags."
        ),
        references=(
            "https://github.com/OJ/gobuster",
        ),
        verified_parameters=(
            "wordlist",
            "extensions",
            "headers",
            "cookies",
            "show_length",
            "status_codes",
            "threads",
            "delay",
            "user_agent",
            "timeout",
            "output_file",
            "quiet",
            "no_progress",
            "expanded",
            "add_slash",
        ),
    ),
    "feroxbuster": SourceReview(
        note=(
            "Reviewed against official feroxbuster command-line docs for "
            "wordlists/extensions/methods/request data, headers/cookies/query, "
            "filters/status allow-lists, timeout/redirects/TLS, recursion and "
            "rate controls, collection, verbosity/output, debug/state, and "
            "progress limiting flags."
        ),
        references=(
            "https://github.com/epi052/feroxbuster",
            "https://epi052.github.io/feroxbuster-docs/docs/configuration/command-line/",
        ),
        verified_parameters=(
            "wordlist",
            "extensions",
            "methods",
            "data",
            "headers",
            "cookies",
            "query",
            "add_slash",
            "protocol",
            "dont_scan",
            "scope",
            "filter_size",
            "filter_regex",
            "filter_words",
            "filter_lines",
            "filter_codes",
            "status_codes",
            "unique",
            "timeout",
            "follow_redirects",
            "insecure",
            "threads",
            "no_recursion",
            "depth",
            "force_recursion",
            "dont_extract_links",
            "scan_limit",
            "parallelism",
            "rate_limit",
            "response_size_limit",
            "time_limit",
            "auto_tune",
            "auto_bail",
            "dont_filter",
            "collect_extensions",
            "collect_backups",
            "collect_words",
            "dont_collect",
            "verbosity",
            "silent",
            "quiet",
            "json_output",
            "output_file",
            "debug_log",
            "no_state",
            "limit_bars",
        ),
    ),
    "sublist3r": SourceReview(
        note=(
            "Reviewed against upstream Sublist3r argparse definitions for "
            "domain target execution, subbrute brute-force enablement, port "
            "scan list, verbosity, thread count, engine selection, output file, "
            "and no-color output."
        ),
        references=(
            "https://github.com/aboul3la/Sublist3r",
            "https://raw.githubusercontent.com/aboul3la/Sublist3r/master/sublist3r.py",
            "https://raw.githubusercontent.com/aboul3la/Sublist3r/master/README.md",
        ),
        verified_parameters=(
            "bruteforce",
            "ports",
            "verbose",
            "threads",
            "engines",
            "output_file",
            "no_color",
        ),
    ),
    "dirsearch": SourceReview(
        note=(
            "Reviewed against the upstream dirsearch README Options section for "
            "wordlists/extensions, status/size/text/regex filters, prefixes/"
            "suffixes, recursion controls, HTTP method/data/headers, redirect/"
            "agent/cookie/proxy/rate settings, report formats, output, quiet, "
            "full-url, and color controls."
        ),
        references=(
            "https://github.com/maurosoria/dirsearch",
        ),
        verified_parameters=(
            "wordlist",
            "extensions",
            "include_status",
            "exclude_status",
            "exclude_sizes",
            "exclude_text",
            "exclude_regex",
            "prefixes",
            "suffixes",
            "threads",
            "recursive",
            "deep_recursive",
            "force_recursive",
            "recursion_depth",
            "recursion_status",
            "subdirs",
            "exclude_subdirs",
            "method",
            "data",
            "headers",
            "header_list",
            "follow_redirects",
            "random_agent",
            "user_agent",
            "cookies",
            "proxy",
            "proxy_list",
            "timeout",
            "delay",
            "max_rate",
            "retries",
            "format",
            "output_file",
            "json_report",
            "plain_text_report",
            "csv_report",
            "markdown_report",
            "xml_report",
            "sqlite_report",
            "quiet",
            "full_url",
            "no_color",
        ),
    ),
    "dirb": SourceReview(
        note=(
            "Reviewed against the Debian-packaged DIRB man page for URL "
            "target plus optional wordlist, user-agent/cookie/header/client "
            "certificate, 404 tuning, case/location/output/proxy/auth "
            "controls, recursion toggles, warning/not-found behavior, "
            "extension amplification, and request delay."
        ),
        references=(
            "https://manpages.debian.org/bookworm/dirb/dirb.1.en.html",
            "https://manpages.debian.org/bookworm/dirb/dirb.1",
        ),
        verified_parameters=(
            "wordlist",
            "user_agent",
            "preserve_url_path",
            "cookie",
            "client_cert",
            "fine_tune_404",
            "header",
            "case_insensitive",
            "show_location",
            "ignore_code",
            "output_file",
            "proxy",
            "proxy_auth",
            "no_recursive",
            "interactive_recursion",
            "silent",
            "no_force_slash",
            "auth",
            "show_not_found",
            "ignore_warnings",
            "extensions_file",
            "extensions",
            "delay_ms",
        ),
    ),
    "web2attack": SourceReview(
        note=(
            "Reviewed against upstream web2attack console entrypoint and "
            "Interface command-loop implementation. The executable starts "
            "an interactive Cmd shell with use/set/show/run commands rather "
            "than accepting module, target, credential, or web-discovery CLI "
            "flags. The adapter is therefore intentionally interactive-only "
            "and suppresses generated target/options."
        ),
        references=(
            "https://github.com/santatic/web2attack",
            "https://raw.githubusercontent.com/santatic/web2attack/master/w2aconsole",
            "https://raw.githubusercontent.com/santatic/web2attack/master/w2a/core/interface.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "checkurl": SourceReview(
        note=(
            "Reviewed against upstream checkURL argparse definitions. The "
            "registry command uses the documented --url target mode, so the "
            "adapter exposes only the compatible --check-url connectivity "
            "toggle and removes generated discovery/phishing parameters. The "
            "upstream --url-list mode is intentionally not exposed because it "
            "is mutually exclusive with the registered --url target command."
        ),
        references=(
            "https://github.com/UndeadSec/checkURL",
            "https://raw.githubusercontent.com/UndeadSec/checkURL/master/checkURL.py",
        ),
        verified_parameters=(
            "check_url",
        ),
    ),
    "blazy": SourceReview(
        note=(
            "Reviewed against upstream Blazy README and argparse definitions. "
            "The registry command now reflects the documented main.py -i "
            "target input form, while the adapter exposes only the source-"
            "backed JSON output path and HTTP timeout options. The tool "
            "remains archived and policy/info-only, so the endpoint does not "
            "execute from MCP."
        ),
        references=(
            "https://github.com/s0md3v/Blazy",
            "https://raw.githubusercontent.com/s0md3v/Blazy/master/README.md",
            "https://raw.githubusercontent.com/s0md3v/Blazy/master/main.py",
        ),
        verified_parameters=(
            "json_output",
            "timeout",
        ),
    ),
    "takeover": SourceReview(
        note=(
            "Reviewed against upstream takeover help text and getopt parser "
            "for domain target, domain list input, proxy, output, threads, "
            "timeout, User-Agent, HTTP 200 processing, and verbose mode. The "
            "registry command no longer forces -v; verbose is exposed as an "
            "explicit adapter flag."
        ),
        references=(
            "https://github.com/edoardottt/takeover",
            "https://raw.githubusercontent.com/edoardottt/takeover/master/README.md",
            "https://raw.githubusercontent.com/edoardottt/takeover/master/takeover.py",
        ),
        verified_parameters=(
            "list_file",
            "proxy",
            "output_file",
            "threads",
            "timeout",
            "user_agent",
            "process_200",
            "verbose",
        ),
    ),
    "skipfish": SourceReview(
        note=(
            "Reviewed against the Skipfish packaged usage documentation for "
            "options-before-target execution: mandatory output directory, "
            "wordlist, authentication, host/IP, cookie/header/browser controls, "
            "crawl limits and URL/domain filters, reporting toggles, learning/"
            "extension settings, form autofill, dictionaries/signatures, and "
            "connection, timeout, size, rate, stop, and config controls."
        ),
        references=(
            "https://www.kali.org/tools/skipfish/",
            "https://manpages.ubuntu.com/manpages/jammy/man1/skipfish.1.html",
        ),
        verified_parameters=(
            "output_dir",
            "write_wordlist",
            "read_wordlist",
            "auth",
            "host_ip",
            "cookie",
            "header",
            "browser",
            "no_new_cookies",
            "max_depth",
            "max_children",
            "max_descendants",
            "request_limit",
            "crawl_probability",
            "seed",
            "include_url",
            "exclude_url",
            "skip_param",
            "crawl_domain",
            "trust_domain",
            "skip_5xx",
            "no_forms",
            "no_html_parse",
            "log_mixed_content",
            "log_cache_mismatches",
            "log_external_urls",
            "suppress_duplicates",
            "quiet",
            "verbose",
            "no_autolearn",
            "no_extension_fuzzing",
            "purge_age",
            "form_autofill",
            "max_guesses",
            "signatures",
            "max_connections",
            "host_connections",
            "max_failures",
            "request_timeout",
            "io_timeout",
            "idle_timeout",
            "response_size_limit",
            "drop_binary_responses",
            "max_requests_per_second",
            "stop_after",
            "config_file",
        ),
    ),
    "caido": SourceReview(
        note=(
            "Reviewed against Caido project/docs for the current registry "
            "command shape. The MCP adapter is intentionally help-only and "
            "runs caido --help; it does not expose generated scanning, "
            "wordlist, recursion, or proxy parameters that are not part of "
            "this registered command."
        ),
        references=(
            "https://github.com/caido/caido",
            "https://docs.caido.io/",
        ),
        verified_parameters=(
            "help",
        ),
    ),
    "mitmproxy": SourceReview(
        note=(
            "Reviewed against the mitmproxy project/docs for the current "
            "registry command shape. The MCP adapter is intentionally "
            "version-only and runs mitmproxy --version; it does not expose "
            "generated crawling, wordlist, recursion, or proxy parameters "
            "that are not part of this registered command."
        ),
        references=(
            "https://github.com/mitmproxy/mitmproxy",
            "https://docs.mitmproxy.org/stable/",
        ),
        verified_parameters=(
            "version",
        ),
    ),
    "nikto": SourceReview(
        note=(
            "Reviewed against the upstream Nikto README help/options for CGI "
            "dirs, config/display/dbcheck/evasion, output formats, auth, plugin "
            "selection, max time, mutation, DNS/SSL/404 behavior, output/save, "
            "ports/root/tuning/timeout/user-agent/proxy/vhost, and update flags."
        ),
        references=(
            "https://github.com/sullo/nikto",
        ),
        verified_parameters=(
            "ask",
            "cgi_dirs",
            "config_file",
            "display",
            "dbcheck",
            "evasion",
            "output_format",
            "auth",
            "list_plugins",
            "max_time",
            "mutate",
            "mutate_options",
            "no_interactive",
            "no_lookup",
            "no_ssl",
            "no_404",
            "output_file",
            "pause",
            "plugins",
            "port",
            "rsa_cert",
            "root",
            "save_dir",
            "ssl",
            "tuning",
            "timeout",
            "user_agent",
            "until",
            "update",
            "use_proxy",
            "vhost",
            "notfound_code",
            "notfound_string",
        ),
    ),
    "owasp-zap": SourceReview(
        note=(
            "Reviewed against the official ZAP desktop command line docs and "
            "Quick Start add-on command line docs for quick scan URL/report/"
            "progress, ZAPit URL, core config/session/logging options, add-on "
            "management, script loading, support info, and SBOM output flags."
        ),
        references=(
            "https://www.zaproxy.org/docs/desktop/cmdline/",
            "https://www.zaproxy.org/docs/desktop/addons/quick-start/cmdline/",
        ),
        verified_parameters=(
            "quick_out",
            "quick_progress",
            "zapit_url",
            "config",
            "config_file",
            "home_dir",
            "install_dir",
            "new_session",
            "session",
            "low_mem",
            "experimental_db",
            "no_stdout",
            "log_level",
            "silent",
            "addon_install",
            "addon_install_all",
            "addon_uninstall",
            "addon_update",
            "addon_list",
            "script",
            "support_info",
            "sbom_zip",
        ),
    ),
    "testssl": SourceReview(
        note=(
            "Reviewed against the upstream testssl.sh manual for input/mass "
            "testing, warnings/timeouts/auth/header/mTLS options, STARTTLS and "
            "proxy/IP/IPv6 handling, tuning flags, single check selectors, "
            "vulnerability/header/client checks, output formatting, and file "
            "output controls."
        ),
        references=(
            "https://github.com/drwetter/testssl.sh",
            "https://raw.githubusercontent.com/drwetter/testssl.sh/3.2/doc/testssl.1.md",
        ),
        verified_parameters=(
            "input_file",
            "mode",
            "warnings",
            "connect_timeout",
            "openssl_timeout",
            "basic_auth",
            "req_header",
            "mtls_file",
            "starttls",
            "xmpp_host",
            "mx",
            "ip",
            "proxy",
            "ipv6",
            "ssl_native",
            "openssl_path",
            "bugs",
            "assume_http",
            "no_dns",
            "sneaky",
            "user_agent",
            "ids_friendly",
            "phone_out",
            "add_ca",
            "each_cipher",
            "cipher_per_proto",
            "categories",
            "forward_secrecy",
            "protocols",
            "server_preference",
            "server_defaults",
            "single_cipher",
            "check_headers",
            "client_simulation",
            "grease",
            "vulnerabilities",
            "quiet",
            "wide",
            "mapping",
            "show_each",
            "color",
            "colorblind",
            "debug",
            "disable_rating",
            "log",
            "logfile",
            "json_output",
            "jsonfile",
            "json_pretty",
            "jsonfile_pretty",
            "csv_output",
            "csvfile",
            "html_output",
            "htmlfile",
            "out_file",
            "outfile",
            "severity",
            "append",
            "overwrite",
            "outprefix",
        ),
    ),
    "dalfox": SourceReview(
        note=(
            "Reviewed against the official DalFox command-line flags reference "
            "for request configuration, scanning behavior, performance, parameter "
            "mining, control flow, and output/reporting flags."
        ),
        references=(
            "https://github.com/hahwul/dalfox",
            "https://dalfox.hahwul.com/advanced/features/command-flags/",
        ),
        verified_parameters=(
            "blind_callback",
            "config_file",
            "cookies",
            "custom_alert_type",
            "custom_alert_value",
            "custom_payload",
            "data",
            "deep_domxss",
            "delay",
            "follow_redirects",
            "force_headless_verification",
            "headers",
            "ignore_param",
            "ignore_return",
            "method",
            "parameter",
            "proxy",
            "remote_payloads",
            "timeout",
            "user_agent",
            "waf_evasion",
            "max_cpu",
            "workers",
            "mining_dict",
            "mining_dict_word",
            "mining_dom",
            "remote_wordlists",
            "skip_mining_all",
            "skip_mining_dict",
            "skip_mining_dom",
            "only_custom_payload",
            "only_discovery",
            "skip_bav",
            "skip_discovery",
            "skip_grepping",
            "skip_headless",
            "skip_xss_scanning",
            "use_bav",
            "debug",
            "format",
            "found_action",
            "found_action_shell",
            "grep_file",
            "har_file_path",
            "no_color",
            "no_spinner",
            "only_poc",
            "output_file",
            "output_all",
            "output_request",
            "output_response",
            "poc_type",
            "report",
            "report_format",
            "silence",
        ),
    ),
    "xssfinder": SourceReview(
        note=(
            "Reviewed against upstream extended-xss-search README, main script, "
            "and Config loader. The documented invocation is python3 "
            "extended-xss-search.py; runtime inputs come from app-settings.conf "
            "and config files such as urls-to-test.txt, parameters.txt, "
            "http-headers.txt, and cookie-jar.txt. The adapter therefore "
            "corrects the registry script name, suppresses target argv and "
            "generic XSS flags, and exposes only a config-driven marker."
        ),
        references=(
            "https://github.com/Damian89/extended-xss-search",
            "https://raw.githubusercontent.com/Damian89/extended-xss-search/master/README.md",
            "https://raw.githubusercontent.com/Damian89/extended-xss-search/master/extended-xss-search.py",
            "https://raw.githubusercontent.com/Damian89/extended-xss-search/master/inc/Config.py",
            "https://raw.githubusercontent.com/Damian89/extended-xss-search/master/example.app-settings.conf",
        ),
        verified_parameters=(
            "config_driven",
        ),
    ),
    "xss-payload-generator": SourceReview(
        note=(
            "Reviewed against upstream XSS-LOADER README, payloader.py, and "
            "xssScan.py. The documented invocation is python3 payloader.py; "
            "the source uses input() prompts for payload selection, scanner "
            "target URL, payload-list choice, and dork-finder workflow rather "
            "than argparse/click options. The adapter therefore suppresses "
            "generated payload/XSS flags and target argv, exposing only an "
            "interactive marker while preserving CAUTION confirmation."
        ),
        references=(
            "https://github.com/capture0x/XSS-LOADER",
            "https://raw.githubusercontent.com/capture0x/XSS-LOADER/master/README.md",
            "https://raw.githubusercontent.com/capture0x/XSS-LOADER/master/payloader.py",
            "https://raw.githubusercontent.com/capture0x/XSS-LOADER/master/xssScan.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "rvuln": SourceReview(
        note=(
            "Reviewed against upstream RVuln HOW-TO and Rust main.rs. The "
            "documented startup is ./RVuln and the source reads Target URL, "
            "query parameters, wordlist path, and verbose mode from stdin "
            "with read_line rather than parsing CLI arguments. The adapter "
            "therefore points at the built release binary, suppresses target "
            "argv and generated web-scanner flags, and exposes only an "
            "interactive marker."
        ),
        references=(
            "https://github.com/yangr0/RVuln",
            "https://raw.githubusercontent.com/yangr0/RVuln/master/HOW-TO.md",
            "https://raw.githubusercontent.com/yangr0/RVuln/master/src/main.rs",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "xsstrike": SourceReview(
        note=(
            "Reviewed against upstream XSStrike argparse definitions for POST "
            "data, encoding, fuzzer/update modes, timeout/proxy/crawl/JSON/path "
            "controls, seed and payload files, crawl level, headers, threads, "
            "delay, skip/DOM/blind toggles, and logging controls."
        ),
        references=(
            "https://github.com/UltimateHackers/XSStrike",
            "https://raw.githubusercontent.com/UltimateHackers/XSStrike/master/xsstrike.py",
        ),
        verified_parameters=(
            "data",
            "encode",
            "fuzzer",
            "update",
            "timeout",
            "use_proxy",
            "crawl",
            "json_data",
            "path_injection",
            "seeds_file",
            "payload_file",
            "level",
            "headers",
            "threads",
            "delay",
            "skip",
            "skip_dom",
            "blind",
            "console_log_level",
            "file_log_level",
            "log_file",
        ),
    ),
    "xspear": SourceReview(
        note=(
            "Reviewed against upstream XSpear README usage for POST data, all-"
            "parameter mode, no-XSS analysis mode, headers/cookies, custom "
            "payloads, raw request input, parameter selection, blind callback, "
            "threading, output format, config file, and verbosity."
        ),
        references=(
            "https://github.com/hahwul/XSpear",
            "https://raw.githubusercontent.com/hahwul/XSpear/master/README.md",
        ),
        verified_parameters=(
            "data",
            "test_all_params",
            "no_xss",
            "headers",
            "cookie",
            "custom_payload",
            "raw_file",
            "parameter",
            "blind_callback",
            "threads",
            "output_format",
            "config_file",
            "verbose",
        ),
    ),
    "xsscon": SourceReview(
        note=(
            "Reviewed against upstream XSSCon argparse definitions for crawl "
            "depth, payload level/value, method mode, user-agent, single URL, "
            "proxy, about, and cookie flags."
        ),
        references=(
            "https://github.com/menkrep1337/XSSCon",
            "https://raw.githubusercontent.com/menkrep1337/XSSCon/master/xsscon.py",
        ),
        verified_parameters=(
            "depth",
            "payload_level",
            "payload",
            "method",
            "user_agent",
            "single_url",
            "proxy",
            "about",
            "cookie",
        ),
    ),
    "xanxss": SourceReview(
        note=(
            "Reviewed against upstream XanXSS argparse definitions for "
            "verification amount, number of findings, test time, inline/file "
            "payloads, verbosity, proxy, headers, throttle, polyglot, prefix, "
            "and suffix flags."
        ),
        references=(
            "https://github.com/Ekultek/XanXSS",
            "https://raw.githubusercontent.com/Ekultek/XanXSS/master/lib/cmd.py",
        ),
        verified_parameters=(
            "verification_amount",
            "amount_to_find",
            "test_time",
            "payloads",
            "payload_file",
            "verbose",
            "proxy",
            "headers",
            "throttle",
            "polyglot",
            "prefix",
            "suffix",
        ),
    ),
    "commix": SourceReview(
        note=(
            "Reviewed against upstream Commix OptionParser definitions for "
            "batch/answers/general checks, target crawl and method controls, "
            "request headers/auth/proxy/Tor settings, timeout/retry controls, "
            "injection parameter selection, prefix/suffix/technique/delay/"
            "time-sec settings, OS command execution, tamper/OS hints, "
            "detection level and skip controls, and miscellaneous safety/output "
            "modes. Upstream exposes --os-cmd, not a --os-shell flag."
        ),
        references=(
            "https://github.com/commixproject/commix",
            "https://raw.githubusercontent.com/commixproject/commix/master/src/utils/menu.py",
            "https://raw.githubusercontent.com/commixproject/commix/master/README.md",
        ),
        verified_parameters=(
            "batch",
            "answers",
            "check_internet",
            "crawl",
            "crawl_exclude",
            "method",
            "data",
            "host",
            "referer",
            "user_agent",
            "random_agent",
            "cookie",
            "headers",
            "proxy",
            "tor",
            "tor_port",
            "auth_url",
            "auth_data",
            "auth_type",
            "auth_cred",
            "timeout",
            "retries",
            "parameter",
            "skip",
            "prefix",
            "suffix",
            "technique",
            "skip_technique",
            "delay",
            "time_sec",
            "tmp_path",
            "web_root",
            "alter_shell",
            "os_cmd",
            "os",
            "tamper",
            "level",
            "skip_calc",
            "skip_empty",
            "failed_tries",
            "smart",
            "ignore_dependencies",
            "list_tampers",
            "no_logging",
            "purge",
            "skip_waf",
            "mobile",
            "offline",
            "wizard",
            "disable_coloring",
        ),
    ),
    "sqlmap": SourceReview(
        note=(
            "Reviewed against upstream sqlmap cmdline parser for URL target "
            "execution via registry command, request configuration, injection "
            "parameter selection, DBMS/detection settings, tamper/technique "
            "controls, enumeration actions, OS takeover options, threading, "
            "form/crawl/session controls, and output directory."
        ),
        references=(
            "https://github.com/sqlmapproject/sqlmap",
            "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/lib/parse/cmdline.py",
            "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/README.md",
        ),
        verified_parameters=(
            "data",
            "method",
            "cookie",
            "headers",
            "user_agent",
            "referer",
            "auth_type",
            "auth_cred",
            "proxy",
            "delay",
            "timeout",
            "retries",
            "csrf_token",
            "random_agent",
            "parameter",
            "skip",
            "dbms",
            "dbms_cred",
            "risk",
            "level",
            "tamper",
            "technique",
            "enumerate_databases",
            "tables",
            "columns",
            "dump",
            "os_cmd",
            "os_shell",
            "threads",
            "forms",
            "crawl",
            "flush_session",
            "output_dir",
        ),
    ),
    "nosqlmap": SourceReview(
        note=(
            "Reviewed against upstream NoSQLMap argparse build_parser() and "
            "module args() hooks. Verified database/web attack mode selection, "
            "platform/victim/listener/web request settings, ON/OFF HTTPS and "
            "verbose toggles, POST/header lists, and nsmweb injection payload, "
            "timing, and save-path options. The adapter maps the base target to "
            "--victim because the registry command has no positional target."
        ),
        references=(
            "https://github.com/codingo/NoSQLMap",
            "https://raw.githubusercontent.com/codingo/NoSQLMap/master/nosqlmap.py",
            "https://raw.githubusercontent.com/codingo/NoSQLMap/master/nsmweb.py",
            "https://raw.githubusercontent.com/codingo/NoSQLMap/master/nsmmongo.py",
            "https://raw.githubusercontent.com/codingo/NoSQLMap/master/nsmcouch.py",
            "https://raw.githubusercontent.com/codingo/NoSQLMap/master/nsmscan.py",
            "https://raw.githubusercontent.com/codingo/NoSQLMap/master/README.md",
        ),
        verified_parameters=(
            "attack",
            "platform",
            "victim",
            "db_port",
            "my_ip",
            "my_port",
            "web_port",
            "uri",
            "http_method",
            "https",
            "verbose",
            "post_data",
            "request_headers",
            "injected_parameter",
            "inject_size",
            "inject_format",
            "params",
            "do_time_attack",
            "save_path",
        ),
    ),
    "blisqy": SourceReview(
        note=(
            "Reviewed against upstream Blisqy README and top-level example "
            "scripts. The repository exposes importable blindfuzzer and "
            "blindexploit modules plus hard-coded FindBlindSpot.py and "
            "ExploitBlindSpot.py examples; it does not provide the registry's "
            "previous blisqy.py CLI or a target-safe command-line parser. The "
            "registry command is therefore intentionally empty and the adapter "
            "is policy/info-only with a library-usage marker parameter."
        ),
        references=(
            "https://github.com/JohnTroony/Blisqy",
            "https://raw.githubusercontent.com/JohnTroony/Blisqy/master/README.md",
            "https://raw.githubusercontent.com/JohnTroony/Blisqy/master/FindBlindSpot.py",
            "https://raw.githubusercontent.com/JohnTroony/Blisqy/master/ExploitBlindSpot.py",
        ),
        verified_parameters=(
            "library_usage",
        ),
    ),
    "leviathan": SourceReview(
        note=(
            "Reviewed against upstream Leviathan README and leviathan.py. The "
            "documented invocation is python leviathan.py and the source is a "
            "Python 2 menu-driven console using raw_input prompts rather than "
            "argparse/click options or a positional target. The adapter "
            "therefore suppresses generated web/SQLi flags and target argv, "
            "exposing only an interactive marker while preserving CAUTION "
            "confirmation."
        ),
        references=(
            "https://github.com/utkusen/leviathan",
            "https://raw.githubusercontent.com/utkusen/leviathan/master/README.md",
            "https://raw.githubusercontent.com/utkusen/leviathan/master/leviathan.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "routersploit": SourceReview(
        note=(
            "Reviewed against upstream RouterSploit README, rsf.py, and "
            "interpreter nonInteractive implementation. With no args rsf.py "
            "starts the interactive console; with args it accepts -m/--module "
            "and repeated -s/--set assignments before executing the selected "
            "module. The adapter suppresses generated exploit placeholders, "
            "maps the base target to a target set-option, and exposes only "
            "module, set_options, and interactive controls."
        ),
        references=(
            "https://github.com/threat9/routersploit",
            "https://raw.githubusercontent.com/threat9/routersploit/master/README.md",
            "https://raw.githubusercontent.com/threat9/routersploit/master/rsf.py",
            "https://raw.githubusercontent.com/threat9/routersploit/master/routersploit/interpreter.py",
        ),
        verified_parameters=(
            "module",
            "set_options",
            "interactive",
        ),
    ),
    "websploit": SourceReview(
        note=(
            "Reviewed against upstream WebSploit README, install script, "
            "console entrypoint, and an interactive module. The installed "
            "command launches websploit.py, which reads commands from "
            "raw_input at the wsf prompt and dispatches use/show/help/os "
            "commands; modules such as directory_scanner also read set/run "
            "commands from raw_input. No argparse, getopt, or sys.argv CLI "
            "surface was found, so the adapter suppresses target argv and "
            "generated web/exploit placeholders and exposes only an "
            "interactive marker."
        ),
        references=(
            "https://github.com/The404Hacking/websploit",
            "https://raw.githubusercontent.com/The404Hacking/websploit/master/README.md",
            "https://raw.githubusercontent.com/The404Hacking/websploit/master/Setup/install.sh",
            "https://raw.githubusercontent.com/The404Hacking/websploit/master/websploit.py",
            "https://raw.githubusercontent.com/The404Hacking/websploit/master/modules/directory_scanner.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "vegil": SourceReview(
        note=(
            "Reviewed against upstream Vegile README and bash entrypoint. "
            "The documented usage exposes inject, unlimited, and help modes; "
            "the script dispatches --i/--inject and --u/--unlimited with the "
            "second argument as a backdoor/rootkit file path, plus "
            "--h/--help. The adapter removes unsupported listener/session "
            "placeholders and keeps Vegile DANGEROUS policy/info-only."
        ),
        references=(
            "https://github.com/Screetsec/Vegile",
            "https://raw.githubusercontent.com/Screetsec/Vegile/master/README.md",
            "https://raw.githubusercontent.com/Screetsec/Vegile/master/Vegile",
        ),
        verified_parameters=(
            "action",
            "backdoor_path",
            "help",
        ),
    ),
    "chrome-keylogger": SourceReview(
        note=(
            "Reviewed against upstream Hera README, hera.py, and core builder "
            "helpers. The documented command is python3 hera.py; hera.py uses "
            "interactive input prompts for server domain, manifest edits, and "
            "whether to start the local PHP server. No argparse, getopt, or "
            "sys.argv CLI options were found, so the adapter removes generated "
            "post-exploitation and mobile placeholders and exposes only an "
            "interactive marker. The tool remains DANGEROUS and policy-only."
        ),
        references=(
            "https://github.com/UndeadSec/HeraKeylogger",
            "https://raw.githubusercontent.com/UndeadSec/HeraKeylogger/master/README.md",
            "https://raw.githubusercontent.com/UndeadSec/HeraKeylogger/master/hera.py",
            "https://raw.githubusercontent.com/UndeadSec/HeraKeylogger/master/core/builder.py",
            "https://raw.githubusercontent.com/UndeadSec/HeraKeylogger/master/core/pre.py",
        ),
        verified_parameters=(
            "interactive",
        ),
    ),
    "pwncat-cs": SourceReview(
        note=(
            "Reviewed against upstream pwncat README usage examples and "
            "pwncat/__main__.py argparse entrypoint. The pwncat-cs command "
            "accepts optional connection-string target syntax plus listen, "
            "port, platform, SSL certificate/key, SSH identity, implant "
            "listing, version, plugin pre-download, config, and verbose "
            "flags. The registry command now invokes the real pwncat-cs "
            "entrypoint instead of forcing --help, and the adapter removes "
            "unsupported post-exploit placeholder parameters."
        ),
        references=(
            "https://github.com/calebstewart/pwncat",
            "https://raw.githubusercontent.com/calebstewart/pwncat/master/README.md",
            "https://raw.githubusercontent.com/calebstewart/pwncat/master/pwncat/__main__.py",
        ),
        verified_parameters=(
            "listen",
            "port",
            "platform",
            "ssl",
            "ssl_cert",
            "ssl_key",
            "identity_file",
            "list_implants",
            "version",
            "download_plugins",
            "config_file",
            "verbose",
        ),
    ),
    "sliver": SourceReview(
        note=(
            "Reviewed against the official installer, GitHub release assets, "
            "Kali command help, and upstream client/server Cobra definitions. "
            "The installer downloads separate sliver-server and sliver-client "
            "binaries, creates /usr/local/bin/sliver as a symlink to the client, "
            "and runs the server daemon separately. The registry now invokes "
            "the client symlink instead of forcing --help. The adapter exposes "
            "client-side root/console/import/mcp/version parameters, rc script, "
            "WireGuard connect mode, import config file positionals, MCP config, "
            "and help. Server-side operator/daemon/builder flags are not exposed "
            "because they belong to sliver-server, not the sliver client symlink."
        ),
        references=(
            "https://sliver.sh/install",
            "https://www.kali.org/tools/sliver/",
            "https://github.com/BishopFox/sliver/releases",
            "https://raw.githubusercontent.com/BishopFox/sliver/master/client/cli/cli.go",
            "https://raw.githubusercontent.com/BishopFox/sliver/master/client/cli/console.go",
            "https://raw.githubusercontent.com/BishopFox/sliver/master/client/cli/import.go",
            "https://raw.githubusercontent.com/BishopFox/sliver/master/client/cli/mcp.go",
            "https://raw.githubusercontent.com/BishopFox/sliver/master/server/cli/cli.go",
        ),
        verified_parameters=(
            "command",
            "rc_script",
            "enable_wg",
            "config_files",
            "mcp_config",
            "version",
            "help",
        ),
    ),
    "havoc": SourceReview(
        note=(
            "Reviewed against upstream README, makefile, and Cobra command "
            "definitions for the teamserver entrypoint. The built binary is "
            "./havoc, with server and client subcommands; server exposes "
            "profile, debug, debug-dev, send-logs, default profile, and "
            "verbose flags, while client forwards args to client/Havoc. The "
            "registry no longer forces --help so structured server/client "
            "arguments can be appended, and the adapter removes unsupported "
            "listener/session/tunnel placeholder parameters."
        ),
        references=(
            "https://github.com/HavocFramework/Havoc",
            "https://raw.githubusercontent.com/HavocFramework/Havoc/main/README.md",
            "https://raw.githubusercontent.com/HavocFramework/Havoc/main/makefile",
            "https://raw.githubusercontent.com/HavocFramework/Havoc/main/teamserver/cmd/cmd.go",
            "https://raw.githubusercontent.com/HavocFramework/Havoc/main/teamserver/cmd/server.go",
            "https://raw.githubusercontent.com/HavocFramework/Havoc/main/teamserver/cmd/client.go",
        ),
        verified_parameters=(
            "command",
            "profile",
            "default_profile",
            "debug",
            "debug_dev",
            "send_logs",
            "verbose",
            "help",
        ),
    ),
    "mythic": SourceReview(
        note=(
            "Reviewed against upstream Mythic README, root Makefile, "
            "Mythic_CLI README, and Cobra command definitions. The repo "
            "builds a mythic-cli binary in the Mythic directory; README "
            "documents sudo ./mythic-cli start for default containers. The "
            "adapter now models the lifecycle CLI surface for start, stop, "
            "restart, and status, with service/container positionals, "
            "start/stop --keep-volume, status --verbose, and command help. "
            "Mythic remains DANGEROUS and policy/info-only, so this endpoint "
            "does not execute or bypass policy."
        ),
        references=(
            "https://github.com/its-a-feature/Mythic",
            "https://raw.githubusercontent.com/its-a-feature/Mythic/master/README.md",
            "https://raw.githubusercontent.com/its-a-feature/Mythic/master/Makefile",
            "https://raw.githubusercontent.com/its-a-feature/Mythic/master/Mythic_CLI/README.md",
            "https://raw.githubusercontent.com/its-a-feature/Mythic/master/Mythic_CLI/src/cmd/rootCmd.go",
            "https://raw.githubusercontent.com/its-a-feature/Mythic/master/Mythic_CLI/src/cmd/start.go",
            "https://raw.githubusercontent.com/its-a-feature/Mythic/master/Mythic_CLI/src/cmd/stop.go",
            "https://raw.githubusercontent.com/its-a-feature/Mythic/master/Mythic_CLI/src/cmd/restart.go",
            "https://raw.githubusercontent.com/its-a-feature/Mythic/master/Mythic_CLI/src/cmd/status.go",
        ),
        verified_parameters=(
            "command",
            "service_names",
            "keep_volume",
            "verbose",
            "help",
        ),
    ),
    "evil-winrm": SourceReview(
        note=(
            "Reviewed against upstream Evil-WinRM README help text and "
            "evil-winrm.rb OptionParser definitions. The registry target maps "
            "to -i/--ip, and the adapter now exposes the documented "
            "authentication, SSL/certificate, Kerberos, script/executable path, "
            "URL, user-agent, version, color/path-completion, and logging "
            "flags instead of generic post-exploitation placeholders. Upload "
            "and download are interactive shell commands, not startup CLI "
            "options."
        ),
        references=(
            "https://github.com/Hackplayers/evil-winrm",
            "https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md",
            "https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/evil-winrm.rb",
        ),
        verified_parameters=(
            "username",
            "password",
            "nt_hash",
            "port",
            "ssl",
            "public_key",
            "private_key",
            "realm",
            "ccache",
            "scripts_path",
            "spn",
            "executables_path",
            "url",
            "user_agent",
            "version",
            "no_colors",
            "no_rpath_completion",
            "log_session",
        ),
    ),
    "chisel": SourceReview(
        note=(
            "Reviewed against upstream Chisel README and main.go flag parsing "
            "for top-level server/client subcommands, version output, server "
            "host/port/key/auth/keepalive/backend/SOCKS/reverse/TLS flags, "
            "client server/remotes/fingerprint/auth/retry/proxy/header/Host/"
            "SNI/TLS flags, and common pid/verbose flags. The registry command "
            "now invokes chisel directly instead of forcing --help; the adapter "
            "suppresses base target argv and maps target/server into the client "
            "<server> positional argument before remotes."
        ),
        references=(
            "https://github.com/jpillora/chisel",
            "https://raw.githubusercontent.com/jpillora/chisel/master/README.md",
            "https://raw.githubusercontent.com/jpillora/chisel/master/main.go",
        ),
        verified_parameters=(
            "command",
            "server",
            "remotes",
            "host",
            "port",
            "key_seed",
            "keygen",
            "keyfile",
            "authfile",
            "auth",
            "keepalive",
            "backend",
            "socks5",
            "reverse",
            "tls_key",
            "tls_cert",
            "tls_domain",
            "tls_ca",
            "fingerprint",
            "max_retry_count",
            "max_retry_interval",
            "proxy",
            "header",
            "hostname",
            "sni",
            "tls_skip_verify",
            "pid",
            "verbose",
            "version",
        ),
    ),
    "ligolo-ng": SourceReview(
        note=(
            "Reviewed against official Ligolo-ng install/quickstart docs and "
            "the upstream cmd/proxy Go flag definitions. Ligolo-ng builds two "
            "separate binaries, proxy and agent; the registry now builds both "
            "from source but executes the local proxy binary. The adapter "
            "therefore suppresses target argv and exposes only proxy startup "
            "flags for listen address, certificate modes/files/domains, config, "
            "daemon/API mode, profiling, banner, verbosity, version, and help. "
            "Agent-side flags such as connect, bind, retry, socks/proxy, and "
            "certificate fingerprint are not exposed because they belong to the "
            "separate agent binary."
        ),
        references=(
            "https://docs.ligolo.ng/InstallBuild/",
            "https://docs.ligolo.ng/Quickstart/",
            "https://raw.githubusercontent.com/nicocha30/ligolo-ng/master/cmd/proxy/main.go",
            "https://raw.githubusercontent.com/nicocha30/ligolo-ng/master/cmd/agent/main.go",
        ),
        verified_parameters=(
            "listen_addr",
            "autocert",
            "selfcert",
            "cert_file",
            "key_file",
            "allow_domains",
            "selfcert_domain",
            "config_file",
            "daemon",
            "api_listen_addr",
            "cpu_profile",
            "mem_profile",
            "verbose",
            "no_banner",
            "version",
            "help",
        ),
    ),
    "peass-ng": SourceReview(
        note=(
            "Reviewed against upstream PEASS-ng linPEAS README usage and "
            "documented help block. The registry installs and runs the release "
            "linpeas.sh script, so the adapter suppresses target argv and "
            "exposes LinPEAS flags for all/extra/regex/stealth checks, sudo "
            "password, debug, network discovery/scan, port forwarding, firmware "
            "folder analysis, selected check groups, wait/force mode, quiet, "
            "no-color, and help. Output redirection and remote transfer examples "
            "are shell usage patterns, not linpeas CLI parameters."
        ),
        references=(
            "https://github.com/peass-ng/PEASS-ng",
            "https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/linPEAS/README.md",
        ),
        verified_parameters=(
            "all_checks",
            "extra_enum",
            "regex_checks",
            "stealth",
            "password",
            "debug",
            "auto_network_scan",
            "discover_net",
            "ports",
            "scan_ip",
            "port_forward",
            "firmware_path",
            "selected_checks",
            "wait",
            "force_linpeas",
            "force_macpeas",
            "quiet",
            "no_color",
            "help",
        ),
    ),
    "explo": SourceReview(
        note=(
            "Reviewed against upstream explo argparse parser and README usage. "
            "The CLI accepts one or more testcase YAML filenames and the "
            "-v/--verbose flag; proxy and timeout controls are environment "
            "variables, not CLI parameters. The registry command now leaves "
            "verbose opt-in to the adapter instead of forcing it."
        ),
        references=(
            "https://github.com/telekom-security/explo",
            "https://raw.githubusercontent.com/telekom-security/explo/master/README.md",
            "https://raw.githubusercontent.com/telekom-security/explo/master/explo/core.py",
            "https://raw.githubusercontent.com/telekom-security/explo/master/setup.py",
        ),
        verified_parameters=(
            "extra_files",
            "verbose",
        ),
    ),
    "dsss": SourceReview(
        note=(
            "Reviewed against upstream DSSS option parsing for POST data, cookie, "
            "user-agent, referer, and proxy flags."
        ),
        references=(
            "https://github.com/stamparm/DSSS",
            "https://raw.githubusercontent.com/stamparm/DSSS/master/dsss.py",
        ),
        verified_parameters=(
            "data",
            "cookie",
            "user_agent",
            "referer",
            "proxy",
        ),
    ),
    "sqlscan": SourceReview(
        note=(
            "Reviewed against upstream sqlscan README usage showing URL or input "
            "file targets scanned with the --scan mode flag."
        ),
        references=(
            "https://github.com/Cvar1984/sqlscan",
            "https://raw.githubusercontent.com/Cvar1984/sqlscan/dev/README.md",
        ),
        verified_parameters=(
            "scan",
        ),
    ),
    "wafw00f": SourceReview(
        note=(
            "Reviewed against upstream wafw00f OptionParser definitions for "
            "verbosity, find-all matching, redirect suppression, one-WAF tests, "
            "output file/format, input files, WAF listing, proxy, version, custom "
            "headers file, timeout, and color suppression."
        ),
        references=(
            "https://github.com/EnableSecurity/wafw00f",
            "https://raw.githubusercontent.com/EnableSecurity/wafw00f/master/wafw00f/main.py",
        ),
        verified_parameters=(
            "verbosity",
            "find_all",
            "no_redirect",
            "test_waf",
            "output_file",
            "output_format",
            "input_file",
            "list_wafs",
            "proxy",
            "version",
            "headers_file",
            "timeout",
            "no_color",
        ),
    ),
    "anonsurf": SourceReview(
        note=(
            "Reviewed against upstream kali-anonsurf README usage. The CLI "
            "accepts one positional action from start, stop, restart, change, "
            "status, starti2p, and stopi2p; unsupported generic Tor port and "
            "country parameters were removed from the adapter."
        ),
        references=(
            "https://github.com/Und3rf10w/kali-anonsurf",
            "https://raw.githubusercontent.com/Und3rf10w/kali-anonsurf/master/README.md",
        ),
        verified_parameters=(
            "action",
        ),
    ),
    "multitor": SourceReview(
        note=(
            "Reviewed against upstream multitor README parameter table for help, "
            "debug, verbose, init count, kill/show/new identity operations, "
            "user, socks/control ports, proxy type, and HAProxy frontend flags."
        ),
        references=(
            "https://github.com/trimstray/multitor",
            "https://raw.githubusercontent.com/trimstray/multitor/master/README.md",
        ),
        verified_parameters=(
            "init_instances",
            "user",
            "socks_port",
            "control_port",
            "proxy",
            "haproxy",
            "kill",
            "show_id",
            "new_id",
            "debug",
            "verbose",
            "help",
        ),
    ),
    "cupp": SourceReview(
        note=(
            "Reviewed against upstream CUPP README and argparse source for "
            "interactive profiling, dictionary improvement, wordlist download, "
            "Alecto DB parsing, version display, and quiet mode."
        ),
        references=(
            "https://github.com/Mebus/cupp",
            "https://raw.githubusercontent.com/Mebus/cupp/master/README.md",
            "https://raw.githubusercontent.com/Mebus/cupp/master/cupp.py",
        ),
        verified_parameters=(
            "interactive",
            "improve_file",
            "download_wordlist",
            "alecto",
            "version",
            "quiet",
        ),
    ),
    "wlcreator": SourceReview(
        note=(
            "Reviewed against upstream wlcreator README usage and C source. "
            "The executable accepts one positional password length argument; "
            "character-set and pattern choices are interactive stdin prompts "
            "and are intentionally left to raw/manual use."
        ),
        references=(
            "https://github.com/Z4nzu/wlcreator",
            "https://raw.githubusercontent.com/Z4nzu/wlcreator/master/README.md",
            "https://raw.githubusercontent.com/Z4nzu/wlcreator/master/wlcreator.c",
        ),
        verified_parameters=(
            "length",
        ),
    ),
}

BASE_ADAPTER_PARAMETERS = {"target", "options", "confirm_authorized"}


@dataclass(frozen=True)
class AdapterResearchRecord:
    """Evidence summary for one generated adapter."""

    tool_name: str
    title: str
    category: str
    safety_tier: str
    endpoint: str
    execution_state: str
    source_status: str
    named_override: bool
    source_reviewed: bool
    parameter_count: int
    project_url: str
    verified_parameters: tuple[str, ...]
    unverified_parameters: tuple[str, ...]
    evidence: tuple[str, ...]
    gap: str


def build_adapter_research_records(
    registry: ToolRegistry,
    safety: SafetyPolicy,
) -> list[AdapterResearchRecord]:
    """Build per-tool adapter research records from concrete registry data."""
    specs = {spec.tool_name: spec for spec in build_adapter_specs(registry, safety)}
    records: list[AdapterResearchRecord] = []

    for tool in registry.list_all_tools():
        spec = specs[tool.name]
        params = adapter_parameter_names(tool, spec)
        reviewable_params = sorted(set(params) - BASE_ADAPTER_PARAMETERS)
        source_review = SOURCE_REVIEWED_TOOLS.get(tool.name)
        source_reviewed = source_review is not None
        named_override = tool.name in NAMED_OVERRIDE_TOOL_NAMES
        split_adapter = has_split_adapter(tool.name)
        verified_params = sorted(source_review.verified_parameters) if source_review else []
        unverified_params = (
            sorted(set(reviewable_params) - set(verified_params))
            if source_review
            else reviewable_params
        )

        if source_reviewed:
            source_status = SOURCE_STATUS_SOURCE_REVIEWED
        elif named_override:
            source_status = SOURCE_STATUS_NAMED_OVERRIDE
        else:
            source_status = SOURCE_STATUS_REGISTRY_DERIVED

        evidence = [
            "registry metadata: category, tags, run_command, install_commands, project_url",
            f"generated adapter parameter schema with {len(params)} parameters",
        ]
        if split_adapter:
            evidence.append("dedicated split adapter module is registered")
        elif named_override:
            evidence.append("tool-specific named override exists in tool_adapters.py")
        else:
            evidence.append("parameters are derived from category/tag adapter rules")
        if tool.project_url:
            evidence.append(f"registry project_url: {tool.project_url}")
        if source_review:
            evidence.append(f"source review note: {source_review.note}")
            evidence.append(
                "source-verified parameters: " + ", ".join(verified_params)
            )
            evidence.extend(
                f"source reference: {reference}"
                for reference in source_review.references
            )

        gap = ""
        if source_reviewed and unverified_params:
            gap = (
                "source review does not yet verify exposed parameters: "
                + ", ".join(unverified_params)
            )
        elif not source_reviewed:
            gap = (
                "upstream source/docs have not been manually reviewed for exact "
                "CLI parity"
            )

        records.append(
            AdapterResearchRecord(
                tool_name=tool.name,
                title=tool.title,
                category=tool.category,
                safety_tier=tool.safety_tier.value,
                endpoint=spec.mcp_name,
                execution_state="executable" if spec.exposed else "policy/info-only",
                source_status=source_status,
                named_override=named_override,
                source_reviewed=source_reviewed,
                parameter_count=len(params),
                project_url=tool.project_url,
                verified_parameters=tuple(verified_params),
                unverified_parameters=tuple(unverified_params),
                evidence=tuple(evidence),
                gap=gap,
            )
        )

    return records


def summarize_adapter_research(records: list[AdapterResearchRecord]) -> dict[str, int]:
    """Return aggregate research-status counts."""
    by_status = Counter(record.source_status for record in records)
    return {
        "total": len(records),
        "registry_derived": by_status[SOURCE_STATUS_REGISTRY_DERIVED],
        "named_override": by_status[SOURCE_STATUS_NAMED_OVERRIDE],
        "source_reviewed": by_status[SOURCE_STATUS_SOURCE_REVIEWED],
        "fully_source_verified": sum(
            1 for record in records
            if record.source_reviewed and not record.unverified_parameters
        ),
        "source_review_gaps": sum(1 for record in records if record.gap),
    }


def find_adapter_research_record(
    registry: ToolRegistry,
    safety: SafetyPolicy,
    tool_name: str,
) -> AdapterResearchRecord | None:
    """Find one adapter research record by tool name."""
    normalized = tool_name.strip()
    if not normalized:
        return None
    for record in build_adapter_research_records(registry, safety):
        if record.tool_name == normalized:
            return record
    return None
