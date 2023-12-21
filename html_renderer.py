import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

import django
from colorama import Fore
from django.conf import settings
from django.template.loader import render_to_string

from common import singleton, colorize, VERSION, COPYRIGHT, PATH


@singleton
class HTMLRenderer:
    def __init__(self):
        settings.configure(TEMPLATES=[
            {
                'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'DIRS': [PATH / 'templates', ],
                'APP_DIRS': False,
            },
        ])
        django.setup()

    @staticmethod
    def render(template: str, context: dict[str, Any], html_file: Path):
        context.update({
            'version': VERSION,
            'copyright': COPYRIGHT,
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        content = render_to_string(template, context)
        print(f'Writing HTML file [{html_file}]... ', end='')
        with open(html_file, 'w') as f:
            f.write(content)
        print(colorize(f'OK', Fore.GREEN))
        webbrowser.open(str(html_file))
