from pathlib import Path

import sys
from colorama import Style


VERSION: str = '1.6'
COPYRIGHT: str = '2022-2023 Région académique Bretagne'
PATH: Path = Path(__file__).parents[0].resolve()


def singleton(class_):
    instances = {}

    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance


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
