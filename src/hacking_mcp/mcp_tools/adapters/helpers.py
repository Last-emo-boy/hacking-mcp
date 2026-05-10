"""Small helpers for dedicated per-tool adapter modules."""


def add_value(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    value = kwargs.get(key)
    if value in (None, "", 0, False):
        return
    tokens.extend([flag, str(value)])


def add_bool(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    if kwargs.get(key):
        tokens.append(flag)


def add_assignment(tokens: list[str], kwargs: dict, key: str, name: str) -> None:
    value = kwargs.get(key)
    if value in (None, "", 0, False):
        return
    tokens.append(f"{name}={value}")


def int_value(kwargs: dict, key: str) -> int:
    try:
        return int(kwargs.get(key) or 0)
    except (TypeError, ValueError):
        return 0
