"""Small helpers for dedicated per-tool adapter modules."""

import shlex


def add_value(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    value = kwargs.get(key)
    if value in (None, "", 0, False):
        return
    tokens.extend([flag, str(value)])


def add_values(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    value = kwargs.get(key)
    if value in (None, "", 0, False):
        return

    if isinstance(value, (list, tuple, set)):
        values = [str(item) for item in value if item not in (None, "", 0, False)]
    else:
        raw = str(value).replace(",", " ")
        try:
            values = shlex.split(raw)
        except ValueError:
            values = raw.split()

    if not values:
        return
    tokens.append(flag)
    tokens.extend(values)


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
