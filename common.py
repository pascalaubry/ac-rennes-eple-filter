import importlib.metadata
from pathlib import Path

import sys
from colorama import Style

from django.template.defaulttags import register
from packaging.version import Version

APP_NAME: str = 'ac-rennes-eple-filter'
VERSION: Version = Version(importlib.metadata.version(APP_NAME))
COPYRIGHT: str = '2022-2025 Région académique Bretagne'
PATH: Path = Path(__file__).parents[0].resolve()


@register.filter
def get_item(dictionary, key):
    try:
        return dictionary.get(key)
    except AttributeError:
        print(f'AttributeError in get_item(dictionary=[{dictionary}], key=[{key}])')
        return None


@register.filter
def join_strings(separator, strings):
    return separator.join(strings)


def singleton(class_):
    instances = {}

    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance


def get_cache_dir() -> Path:
    cache_dir: Path = Path('.') / 'cache'
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_download_cache_dir() -> Path:
    cache_dir: Path = get_cache_dir() / 'download'
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_control_cache_dir() -> Path:
    cache_dir: Path = get_cache_dir() / 'control'
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_reports_dir() -> Path:
    reports_dir: Path = Path('.') / 'reports'
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def colorize(string: str, color: str = None, on_color: str = None, style: str = None) -> str:
    output = ''
    if color is not None:
        output = output + color
    if on_color is not None:
        output = output + on_color
    if style is not None:
        output = output + style
    output = output + string
    if color is not None or on_color is not None:
        output = output + Style.RESET_ALL
    return output


def exit_program(string: str = None):
    if string is not None:
        print(string)
    input('Press Enter to continue... ')
    sys.exit()
