"""Dedicated adapter metadata for WhatWeb."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_file", str, "", "File containing targets, or /dev/stdin."),
        AdapterParameterSpec("url_prefix", str, "", "Prefix added to target URLs."),
        AdapterParameterSpec("url_suffix", str, "", "Suffix added to target URLs."),
        AdapterParameterSpec("url_pattern", str, "", "Pattern that inserts targets with %insert%."),
        AdapterParameterSpec("aggression", int, 0, "Aggression level 1, 3, or 4; 0 leaves default."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
        AdapterParameterSpec("header", str, "", "HTTP header, for example Foo:Bar."),
        AdapterParameterSpec("follow_redirect", str, "", "Redirect policy: never, http-only, meta-only, same-site, or always."),
        AdapterParameterSpec("max_redirects", int, 0, "Maximum contiguous redirects; 0 leaves default."),
        AdapterParameterSpec("basic_auth", str, "", "HTTP basic auth in user:password format."),
        AdapterParameterSpec("cookie", str, "", "Initial cookies, for example name=value; name2=value2."),
        AdapterParameterSpec("cookiejar", str, "", "Cookie jar file path."),
        AdapterParameterSpec("no_cookies", bool, False, "Disable automatic cookie handling."),
        AdapterParameterSpec("proxy", str, "", "Proxy host[:port]."),
        AdapterParameterSpec("proxy_user", str, "", "Proxy auth in username:password format."),
        AdapterParameterSpec("list_plugins", bool, False, "List all plugins."),
        AdapterParameterSpec("info_plugins", bool, False, "List detailed plugin information."),
        AdapterParameterSpec("info_plugin_search", str, "", "Detailed plugin search terms."),
        AdapterParameterSpec("search_plugins", str, "", "Search plugins for a keyword."),
        AdapterParameterSpec("plugins", str, "", "Comma-delimited plugin selection list."),
        AdapterParameterSpec("grep", str, "", "String or regular expression to search in responses."),
        AdapterParameterSpec("custom_plugin", str, "", "Inline custom plugin definition."),
        AdapterParameterSpec("dorks", str, "", "Plugin name for Google dorks."),
        AdapterParameterSpec("verbose", int, 0, "Verbosity level 1-2; 0 leaves default."),
        AdapterParameterSpec("color", str, "", "Color mode: never, always, or auto."),
        AdapterParameterSpec("quiet", bool, False, "Suppress brief stdout logging."),
        AdapterParameterSpec("no_errors", bool, False, "Suppress error messages."),
        AdapterParameterSpec("log_brief", str, "", "Brief log output file."),
        AdapterParameterSpec("log_verbose", str, "", "Verbose log output file."),
        AdapterParameterSpec("log_errors", str, "", "Error log output file."),
        AdapterParameterSpec("log_xml", str, "", "XML log output file."),
        AdapterParameterSpec("log_json", str, "", "JSON log output file."),
        AdapterParameterSpec("log_sql", str, "", "SQL INSERT log output file."),
        AdapterParameterSpec("log_sql_create", str, "", "SQL table creation output file."),
        AdapterParameterSpec("log_json_verbose", str, "", "Verbose JSON log output file."),
        AdapterParameterSpec("log_magictree", str, "", "MagicTree XML log output file."),
        AdapterParameterSpec("log_object", str, "", "Ruby object log output file."),
        AdapterParameterSpec("log_mongo_database", str, "", "MongoDB database name."),
        AdapterParameterSpec("log_mongo_collection", str, "", "MongoDB collection name."),
        AdapterParameterSpec("log_mongo_host", str, "", "MongoDB host."),
        AdapterParameterSpec("log_mongo_username", str, "", "MongoDB username."),
        AdapterParameterSpec("log_mongo_password", str, "", "MongoDB password."),
        AdapterParameterSpec("log_elastic_index", str, "", "Elasticsearch index name."),
        AdapterParameterSpec("log_elastic_host", str, "", "Elasticsearch host:port."),
        AdapterParameterSpec("max_threads", int, 0, "Maximum simultaneous threads; 0 leaves default."),
        AdapterParameterSpec("open_timeout", int, 0, "TCP open timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("read_timeout", int, 0, "HTTP read timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("wait", int, 0, "Seconds to wait between connections; 0 leaves default."),
        AdapterParameterSpec("output_sync", bool, False, "Force immediate output flushing."),
        AdapterParameterSpec("output_buffer_size", int, -1, "Output buffer size; -1 leaves default, 0 disables buffering."),
        AdapterParameterSpec("short_help", bool, False, "Show short usage help."),
        AdapterParameterSpec("debug", bool, False, "Raise plugin errors."),
        AdapterParameterSpec("version", bool, False, "Show version information."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "input_file", "--input-file")
    add_value(tokens, kwargs, "url_prefix", "--url-prefix")
    add_value(tokens, kwargs, "url_suffix", "--url-suffix")
    add_value(tokens, kwargs, "url_pattern", "--url-pattern")
    add_value(tokens, kwargs, "aggression", "--aggression")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_value(tokens, kwargs, "header", "--header")
    add_value(tokens, kwargs, "follow_redirect", "--follow-redirect")
    add_value(tokens, kwargs, "max_redirects", "--max-redirects")
    add_value(tokens, kwargs, "basic_auth", "--user")
    add_value(tokens, kwargs, "cookie", "--cookie")
    add_value(tokens, kwargs, "cookiejar", "--cookiejar")
    add_bool(tokens, kwargs, "no_cookies", "--no-cookies")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_value(tokens, kwargs, "proxy_user", "--proxy-user")
    add_bool(tokens, kwargs, "list_plugins", "--list-plugins")
    if kwargs.get("info_plugin_search"):
        add_value(tokens, kwargs, "info_plugin_search", "--info-plugins")
    else:
        add_bool(tokens, kwargs, "info_plugins", "--info-plugins")
    add_value(tokens, kwargs, "search_plugins", "--search-plugins")
    add_value(tokens, kwargs, "plugins", "--plugins")
    add_value(tokens, kwargs, "grep", "--grep")
    add_value(tokens, kwargs, "custom_plugin", "--custom-plugin")
    add_value(tokens, kwargs, "dorks", "--dorks")
    verbosity = int_value(kwargs, "verbose")
    if verbosity:
        tokens.extend(["-v"] * min(verbosity, 2))
    add_value(tokens, kwargs, "color", "--color")
    add_bool(tokens, kwargs, "quiet", "--quiet")
    add_bool(tokens, kwargs, "no_errors", "--no-errors")
    add_value(tokens, kwargs, "log_brief", "--log-brief")
    add_value(tokens, kwargs, "log_verbose", "--log-verbose")
    add_value(tokens, kwargs, "log_errors", "--log-errors")
    add_value(tokens, kwargs, "log_xml", "--log-xml")
    add_value(tokens, kwargs, "log_json", "--log-json")
    add_value(tokens, kwargs, "log_sql", "--log-sql")
    add_value(tokens, kwargs, "log_sql_create", "--log-sql-create")
    add_value(tokens, kwargs, "log_json_verbose", "--log-json-verbose")
    add_value(tokens, kwargs, "log_magictree", "--log-magictree")
    add_value(tokens, kwargs, "log_object", "--log-object")
    add_value(tokens, kwargs, "log_mongo_database", "--log-mongo-database")
    add_value(tokens, kwargs, "log_mongo_collection", "--log-mongo-collection")
    add_value(tokens, kwargs, "log_mongo_host", "--log-mongo-host")
    add_value(tokens, kwargs, "log_mongo_username", "--log-mongo-username")
    add_value(tokens, kwargs, "log_mongo_password", "--log-mongo-password")
    add_value(tokens, kwargs, "log_elastic_index", "--log-elastic-index")
    add_value(tokens, kwargs, "log_elastic_host", "--log-elastic-host")
    add_value(tokens, kwargs, "max_threads", "--max-threads")
    add_value(tokens, kwargs, "open_timeout", "--open-timeout")
    add_value(tokens, kwargs, "read_timeout", "--read-timeout")
    add_value(tokens, kwargs, "wait", "--wait")
    add_bool(tokens, kwargs, "output_sync", "--output-sync")
    output_buffer_size = kwargs.get("output_buffer_size")
    if output_buffer_size not in (None, "", -1):
        tokens.extend(["--output-buffer-size", str(output_buffer_size)])
    add_bool(tokens, kwargs, "short_help", "--short-help")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "version", "--version")
    return tokens
