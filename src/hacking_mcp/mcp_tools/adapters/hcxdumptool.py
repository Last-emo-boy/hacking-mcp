"""Dedicated adapter metadata for hcxdumptool."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters():
    return [
        AdapterParameterSpec("interface", str, "", "Wireless interface to use."),
        AdapterParameterSpec("output_file", str, "", "pcapng output file for captured packets."),
        AdapterParameterSpec("channel", str, "", "Channel with band suffix, for example 1a or 36b."),
        AdapterParameterSpec("frequency", str, "", "Frequency to use, for example 2412 or 5180."),
        AdapterParameterSpec("use_all_frequencies", bool, False, "Use all available frequencies from the interface."),
        AdapterParameterSpec("stay_time", int, 0, "Minimum channel stay time in seconds; 0 leaves default."),
        AdapterParameterSpec("ack_frames", bool, False, "ACK incoming frames when active monitor mode is supported."),
        AdapterParameterSpec("list_interfaces", bool, False, "Show physical interface list and terminate."),
        AdapterParameterSpec("list_interfaces_short", bool, False, "Show greppable physical interface list and terminate."),
        AdapterParameterSpec("interface_info", str, "", "Show detailed information about this interface and terminate."),
        AdapterParameterSpec("bpf_file", str, "", "Input Berkeley Packet Filter code file."),
        AdapterParameterSpec("fake_time_clock", bool, False, "Enable fake time clock."),
        AdapterParameterSpec("real_time_display", int, 0, "Real-time display mode; 0 leaves upstream default."),
        AdapterParameterSpec("disable_terminal_size", bool, False, "Disable TIOCGWINSZ for real-time displays."),
        AdapterParameterSpec("rcascan", str, "", "Radio channel assessment scan mode: active or passive."),
        AdapterParameterSpec("monitor_interface", str, "", "Set monitor mode on this interface and terminate."),
        AdapterParameterSpec("m2max", int, 0, "Maximum received M1M2ROGUE count; 0 leaves default."),
        AdapterParameterSpec("associationmax", int, 0, "Maximum attempts to associate with an AP; 0 leaves default."),
        AdapterParameterSpec("disable_disassociation", bool, False, "Do not transmit DISASSOCIATION frames."),
        AdapterParameterSpec("proberesponsetx", int, 0, "Number of PROBERESPONSEs to transmit; 0 leaves default."),
        AdapterParameterSpec("essidlist", str, "", "File containing ESSIDs to initialize the ESSID list."),
        AdapterParameterSpec("error_max", int, 0, "Maximum allowed errors; 0 leaves default."),
        AdapterParameterSpec("watchdog_max", int, 0, "Watchdog timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("timeout_minutes", int, 0, "Timeout timer in minutes; 0 leaves default."),
        AdapterParameterSpec("exit_on_eapol", int, 0, "Exit on EAPOL occurrence bitmask; 0 leaves default."),
        AdapterParameterSpec("daemonize", bool, False, "Run as a daemon."),
        AdapterParameterSpec("help", bool, False, "Show overview help."),
        AdapterParameterSpec("extended_help", bool, False, "Show additional help and troubleshooting."),
        AdapterParameterSpec("version", bool, False, "Show version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "interface", "-i")
    add_value(tokens, kwargs, "output_file", "-w")
    add_value(tokens, kwargs, "channel", "-c")
    add_value(tokens, kwargs, "frequency", "-f")
    add_bool(tokens, kwargs, "use_all_frequencies", "-F")
    add_value(tokens, kwargs, "stay_time", "-t")
    add_bool(tokens, kwargs, "ack_frames", "-A")
    add_bool(tokens, kwargs, "list_interfaces", "-L")
    add_bool(tokens, kwargs, "list_interfaces_short", "-l")
    add_value(tokens, kwargs, "interface_info", "-I")
    add_value(tokens, kwargs, "bpf_file", "--bpf")
    add_bool(tokens, kwargs, "fake_time_clock", "--ftc")
    add_value(tokens, kwargs, "real_time_display", "--rds")
    add_bool(tokens, kwargs, "disable_terminal_size", "--rdt")
    add_value(tokens, kwargs, "rcascan", "--rcascan")
    add_value(tokens, kwargs, "monitor_interface", "-m")
    add_value(tokens, kwargs, "m2max", "--m2max")
    add_value(tokens, kwargs, "associationmax", "--associationmax")
    add_bool(tokens, kwargs, "disable_disassociation", "--disable_disassociation")
    add_value(tokens, kwargs, "proberesponsetx", "--proberesponsetx")
    add_value(tokens, kwargs, "essidlist", "--essidlist")
    add_value(tokens, kwargs, "error_max", "--errormax")
    add_value(tokens, kwargs, "watchdog_max", "--watchdogmax")
    add_value(tokens, kwargs, "timeout_minutes", "--tot")
    add_value(tokens, kwargs, "exit_on_eapol", "--exitoneapol")
    add_bool(tokens, kwargs, "daemonize", "--daemonize")
    add_bool(tokens, kwargs, "help", "-h")
    add_bool(tokens, kwargs, "extended_help", "--help")
    add_bool(tokens, kwargs, "version", "-v")
    return tokens
