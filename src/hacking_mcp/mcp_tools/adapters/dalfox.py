"""Dedicated adapter metadata for DalFox."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("blind_callback", str, "", "Blind XSS callback URL."),
        AdapterParameterSpec("config_file", str, "", "DalFox configuration file path."),
        AdapterParameterSpec("cookies", str, "", "Cookie header value."),
        AdapterParameterSpec("custom_alert_type", str, "", "Custom alert type, for example str or none."),
        AdapterParameterSpec("custom_alert_value", str, "", "Custom alert value."),
        AdapterParameterSpec("custom_payload", str, "", "Custom payload file path."),
        AdapterParameterSpec("data", str, "", "HTTP request body data."),
        AdapterParameterSpec("deep_domxss", bool, False, "Enable deep DOM XSS testing."),
        AdapterParameterSpec("delay", int, 0, "Delay between requests in milliseconds; 0 leaves default."),
        AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects."),
        AdapterParameterSpec("force_headless_verification", bool, False, "Force headless payload verification."),
        AdapterParameterSpec("headers", str, "", "Additional HTTP header."),
        AdapterParameterSpec("ignore_param", str, "", "Parameter name to ignore."),
        AdapterParameterSpec("ignore_return", str, "", "HTTP status codes to ignore."),
        AdapterParameterSpec("method", str, "", "HTTP method to use."),
        AdapterParameterSpec("parameter", str, "", "Only test the named parameter."),
        AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
        AdapterParameterSpec("remote_payloads", str, "", "Remote payload list selectors."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
        AdapterParameterSpec("waf_evasion", bool, False, "Enable WAF evasion mode."),
        AdapterParameterSpec("max_cpu", int, 0, "Maximum CPU percentage; 0 leaves default."),
        AdapterParameterSpec("workers", int, 0, "Number of workers; 0 leaves default."),
        AdapterParameterSpec("mining_dict", bool, False, "Enable dictionary-based parameter mining."),
        AdapterParameterSpec("mining_dict_word", str, "", "Extra dictionary word for parameter mining."),
        AdapterParameterSpec("mining_dom", bool, False, "Enable DOM-based parameter mining."),
        AdapterParameterSpec("remote_wordlists", str, "", "Remote wordlist selectors."),
        AdapterParameterSpec("skip_mining_all", bool, False, "Skip all parameter mining."),
        AdapterParameterSpec("skip_mining_dict", bool, False, "Skip dictionary parameter mining."),
        AdapterParameterSpec("skip_mining_dom", bool, False, "Skip DOM parameter mining."),
        AdapterParameterSpec("only_custom_payload", bool, False, "Use only custom payloads."),
        AdapterParameterSpec("only_discovery", bool, False, "Only perform parameter analysis/discovery."),
        AdapterParameterSpec("skip_bav", bool, False, "Skip basic another verification checks."),
        AdapterParameterSpec("skip_discovery", bool, False, "Skip discovery phase."),
        AdapterParameterSpec("skip_grepping", bool, False, "Skip grepping phase."),
        AdapterParameterSpec("skip_headless", bool, False, "Skip headless browser verification."),
        AdapterParameterSpec("skip_xss_scanning", bool, False, "Skip XSS scanning phase."),
        AdapterParameterSpec("use_bav", bool, False, "Enable basic another verification."),
        AdapterParameterSpec("debug", bool, False, "Enable debug output."),
        AdapterParameterSpec("format", str, "", "Output format."),
        AdapterParameterSpec("found_action", str, "", "Command to run when a vulnerability is found."),
        AdapterParameterSpec("found_action_shell", str, "", "Shell to use for found_action."),
        AdapterParameterSpec("grep_file", str, "", "Custom grepping file."),
        AdapterParameterSpec("har_file_path", str, "", "HAR file output path."),
        AdapterParameterSpec("no_color", bool, False, "Disable colored output."),
        AdapterParameterSpec("no_spinner", bool, False, "Disable spinner output."),
        AdapterParameterSpec("only_poc", str, "", "Only print selected PoC type."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("output_all", bool, False, "Write all logs to output."),
        AdapterParameterSpec("output_request", bool, False, "Include raw HTTP request in output."),
        AdapterParameterSpec("output_response", bool, False, "Include raw HTTP response in output."),
        AdapterParameterSpec("poc_type", str, "", "PoC type, for example plain or curl."),
        AdapterParameterSpec("report", bool, False, "Show detailed report output."),
        AdapterParameterSpec("report_format", str, "", "Report format."),
        AdapterParameterSpec("silence", bool, False, "Enable silent output."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "blind_callback", "-b")
    add_value(tokens, kwargs, "config_file", "--config")
    add_value(tokens, kwargs, "cookies", "-C")
    add_value(tokens, kwargs, "custom_alert_type", "--custom-alert-type")
    add_value(tokens, kwargs, "custom_alert_value", "--custom-alert-value")
    add_value(tokens, kwargs, "custom_payload", "--custom-payload")
    add_value(tokens, kwargs, "data", "-d")
    add_bool(tokens, kwargs, "deep_domxss", "--deep-domxss")
    add_value(tokens, kwargs, "delay", "--delay")
    add_bool(tokens, kwargs, "follow_redirects", "--follow-redirects")
    add_bool(tokens, kwargs, "force_headless_verification", "--force-headless-verification")
    add_value(tokens, kwargs, "headers", "-H")
    add_value(tokens, kwargs, "ignore_param", "--ignore-param")
    add_value(tokens, kwargs, "ignore_return", "--ignore-return")
    add_value(tokens, kwargs, "method", "-X")
    add_value(tokens, kwargs, "parameter", "-p")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_value(tokens, kwargs, "remote_payloads", "--remote-payloads")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_bool(tokens, kwargs, "waf_evasion", "--waf-evasion")
    add_value(tokens, kwargs, "max_cpu", "--max-cpu")
    add_value(tokens, kwargs, "workers", "-w")
    add_bool(tokens, kwargs, "mining_dict", "--mining-dict")
    add_value(tokens, kwargs, "mining_dict_word", "--mining-dict-word")
    add_bool(tokens, kwargs, "mining_dom", "--mining-dom")
    add_value(tokens, kwargs, "remote_wordlists", "--remote-wordlists")
    add_bool(tokens, kwargs, "skip_mining_all", "--skip-mining-all")
    add_bool(tokens, kwargs, "skip_mining_dict", "--skip-mining-dict")
    add_bool(tokens, kwargs, "skip_mining_dom", "--skip-mining-dom")
    add_bool(tokens, kwargs, "only_custom_payload", "--only-custom-payload")
    add_bool(tokens, kwargs, "only_discovery", "--only-discovery")
    add_bool(tokens, kwargs, "skip_bav", "--skip-bav")
    add_bool(tokens, kwargs, "skip_discovery", "--skip-discovery")
    add_bool(tokens, kwargs, "skip_grepping", "--skip-grepping")
    add_bool(tokens, kwargs, "skip_headless", "--skip-headless")
    add_bool(tokens, kwargs, "skip_xss_scanning", "--skip-xss-scanning")
    add_bool(tokens, kwargs, "use_bav", "--use-bav")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_value(tokens, kwargs, "format", "--format")
    add_value(tokens, kwargs, "found_action", "--found-action")
    add_value(tokens, kwargs, "found_action_shell", "--found-action-shell")
    add_value(tokens, kwargs, "grep_file", "--grep")
    add_value(tokens, kwargs, "har_file_path", "--har-file-path")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    add_bool(tokens, kwargs, "no_spinner", "--no-spinner")
    add_value(tokens, kwargs, "only_poc", "--only-poc")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "output_all", "--output-all")
    add_bool(tokens, kwargs, "output_request", "--output-request")
    add_bool(tokens, kwargs, "output_response", "--output-response")
    add_value(tokens, kwargs, "poc_type", "--poc-type")
    add_bool(tokens, kwargs, "report", "--report")
    add_value(tokens, kwargs, "report_format", "--report-format")
    add_bool(tokens, kwargs, "silence", "--silence")
    return tokens
