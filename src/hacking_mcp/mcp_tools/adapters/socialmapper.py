"""Dedicated adapter metadata for Social Mapper."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters():
    return [
        AdapterParameterSpec("input_format", str, "", "Input format: csv, imagefolder, company, or socialmapper."),
        AdapterParameterSpec("input_value", str, "", "CSV path, image folder, company name, or Social Mapper HTML input."),
        AdapterParameterSpec("mode", str, "", "Matching mode: accurate or fast."),
        AdapterParameterSpec("threshold", str, "", "Threshold: loose, standard, strict, or superstrict."),
        AdapterParameterSpec("email_format", str, "", "Email pattern for phishing list generation."),
        AdapterParameterSpec("company_id", str, "", "Optional LinkedIn company id for company input."),
        AdapterParameterSpec("show_browser", bool, False, "Show browser while searching."),
        AdapterParameterSpec("wait_after_login", bool, False, "Wait after login to allow 2FA completion."),
        AdapterParameterSpec("all_sites", bool, False, "Check all supported social media sites."),
        AdapterParameterSpec("facebook", bool, False, "Check Facebook."),
        AdapterParameterSpec("pinterest", bool, False, "Check Pinterest."),
        AdapterParameterSpec("twitter", bool, False, "Check Twitter."),
        AdapterParameterSpec("instagram", bool, False, "Check Instagram."),
        AdapterParameterSpec("linkedin", bool, False, "Check LinkedIn."),
        AdapterParameterSpec("vkontakte", bool, False, "Check VKontakte."),
        AdapterParameterSpec("weibo", bool, False, "Check Weibo."),
        AdapterParameterSpec("douban", bool, False, "Check Douban."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose mode."),
        AdapterParameterSpec("debug", bool, False, "Enable debug mode."),
        AdapterParameterSpec("version", bool, False, "Show version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "input_format", "-f")
    add_value(tokens, kwargs, "input_value", "-i")
    add_value(tokens, kwargs, "mode", "-m")
    add_value(tokens, kwargs, "threshold", "-t")
    add_value(tokens, kwargs, "email_format", "-e")
    add_value(tokens, kwargs, "company_id", "-cid")
    add_bool(tokens, kwargs, "show_browser", "-s")
    add_bool(tokens, kwargs, "wait_after_login", "-w")
    add_bool(tokens, kwargs, "all_sites", "-a")
    add_bool(tokens, kwargs, "facebook", "-fb")
    add_bool(tokens, kwargs, "pinterest", "-pn")
    add_bool(tokens, kwargs, "twitter", "-tw")
    add_bool(tokens, kwargs, "instagram", "-ig")
    add_bool(tokens, kwargs, "linkedin", "-li")
    add_bool(tokens, kwargs, "vkontakte", "-vk")
    add_bool(tokens, kwargs, "weibo", "-wb")
    add_bool(tokens, kwargs, "douban", "-db")
    add_bool(tokens, kwargs, "verbose", "-vv")
    add_bool(tokens, kwargs, "debug", "-d")
    add_bool(tokens, kwargs, "version", "-v")
    return tokens
