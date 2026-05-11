"""Dedicated adapter metadata for hcxtools."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters():
    return [
        AdapterParameterSpec("input_file", str, "", "Input pcapng, pcap, cap, or gzip-compressed capture file."),
        AdapterParameterSpec("output_hash", str, "", "Output WPA-PBKDF2-PMKID+EAPOL hash file for hashcat mode 22000."),
        AdapterParameterSpec("output_hash_ftpsk", str, "", "Output WPA-PBKDF2-PMKID+EAPOL hash file for hashcat mode 37100."),
        AdapterParameterSpec("essid_wordlist", str, "", "Output ESSID wordlist from captured frames."),
        AdapterParameterSpec("proberequest_wordlist", str, "", "Output ESSID wordlist from PROBEREQUEST frames."),
        AdapterParameterSpec("identity_file", str, "", "Output unsorted identity list."),
        AdapterParameterSpec("username_file", str, "", "Output unsorted username list."),
        AdapterParameterSpec("device_info_file", str, "", "Output device information list."),
        AdapterParameterSpec("convert_all", bool, False, "Convert all possible hashes instead of only the best one."),
        AdapterParameterSpec("eapol_timeout", int, 0, "EAPOL timeout in milliseconds; 0 leaves upstream default."),
        AdapterParameterSpec("nonce_error_corrections", int, 0, "Nonce error correction value; 0 leaves upstream default."),
        AdapterParameterSpec("ignore_ie", bool, False, "Do not use cipher and AKM information."),
        AdapterParameterSpec("max_essids", int, 0, "Maximum allowed ESSIDs; 0 leaves upstream default."),
        AdapterParameterSpec("eapmd5_file", str, "", "Output EAP MD5 challenge file for hashcat mode 4800."),
        AdapterParameterSpec("eapmd5_john_file", str, "", "Output EAP MD5 challenge file for John."),
        AdapterParameterSpec("eapleap_file", str, "", "Output EAP LEAP/MSCHAPV2 challenge file."),
        AdapterParameterSpec("tacacs_plus_file", str, "", "Output TACACS+ v1 hash file."),
        AdapterParameterSpec("nmea_in", str, "", "Input NMEA 0183 file."),
        AdapterParameterSpec("nmea_out", str, "", "Output GPS data in NMEA 0183 format."),
        AdapterParameterSpec("csv_file", str, "", "Output access point information in CSV format."),
        AdapterParameterSpec("log_file", str, "", "Output log file."),
        AdapterParameterSpec("raw_out", str, "", "Output frames in HEX ASCII."),
        AdapterParameterSpec("raw_in", str, "", "Input frames in HEX ASCII."),
        AdapterParameterSpec("lts_file", str, "", "Output BSSID list to sync with external GPS data."),
        AdapterParameterSpec("pmkid_client_file", str, "", "Output WPA mesh/repeater PMKID hash file."),
        AdapterParameterSpec("deprecated_pmkid_file", str, "", "Output deprecated PMKID file."),
        AdapterParameterSpec("deprecated_hccapx_file", str, "", "Output deprecated hccapx v4 file."),
        AdapterParameterSpec("deprecated_hccap_file", str, "", "Output deprecated hccap file."),
        AdapterParameterSpec("deprecated_john_file", str, "", "Output deprecated PMKID/EAPOL John format file."),
        AdapterParameterSpec("prefix", str, "", "Convert all supported outputs to files using this prefix."),
        AdapterParameterSpec("add_timestamp", bool, False, "Add date/time and EAPOL time gap to hash lines."),
        AdapterParameterSpec("help", bool, False, "Show help."),
        AdapterParameterSpec("version", bool, False, "Show version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "output_hash", "-o")
    add_value(tokens, kwargs, "output_hash_ftpsk", "-f")
    add_value(tokens, kwargs, "essid_wordlist", "-E")
    add_value(tokens, kwargs, "proberequest_wordlist", "-R")
    add_value(tokens, kwargs, "identity_file", "-I")
    add_value(tokens, kwargs, "username_file", "-U")
    add_value(tokens, kwargs, "device_info_file", "-D")
    add_bool(tokens, kwargs, "convert_all", "--all")
    add_value(tokens, kwargs, "eapol_timeout", "--eapoltimeout")
    add_value(tokens, kwargs, "nonce_error_corrections", "--nonce-error-corrections")
    add_bool(tokens, kwargs, "ignore_ie", "--ignore-ie")
    add_value(tokens, kwargs, "max_essids", "--max-essids")
    add_value(tokens, kwargs, "eapmd5_file", "--eapmd5")
    add_value(tokens, kwargs, "eapmd5_john_file", "--eapmd5-john")
    add_value(tokens, kwargs, "eapleap_file", "--eapleap")
    add_value(tokens, kwargs, "tacacs_plus_file", "--tacacs-plus")
    add_value(tokens, kwargs, "nmea_in", "--nmea-in")
    add_value(tokens, kwargs, "nmea_out", "--nmea-out")
    add_value(tokens, kwargs, "csv_file", "--csv")
    add_value(tokens, kwargs, "log_file", "--log")
    add_value(tokens, kwargs, "raw_out", "--raw-out")
    add_value(tokens, kwargs, "raw_in", "--raw-in")
    add_value(tokens, kwargs, "lts_file", "--lts")
    add_value(tokens, kwargs, "pmkid_client_file", "--pmkid-client")
    add_value(tokens, kwargs, "deprecated_pmkid_file", "--pmkid")
    add_value(tokens, kwargs, "deprecated_hccapx_file", "--hccapx")
    add_value(tokens, kwargs, "deprecated_hccap_file", "--hccap")
    add_value(tokens, kwargs, "deprecated_john_file", "--john")
    add_value(tokens, kwargs, "prefix", "--prefix")
    add_bool(tokens, kwargs, "add_timestamp", "--add-timestamp")
    add_bool(tokens, kwargs, "help", "-h")
    add_bool(tokens, kwargs, "version", "-v")
    return tokens
