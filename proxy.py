from contextlib import suppress
from pathlib import Path

import yaml
from yaml.loader import SafeLoader
from common import colorize, exit_program
from colorama import Fore


class ProxyConfig:

    def __init__(self, proxy_id: str, proxy_dict: dict[str, str]):
        self.id = proxy_id
        try:
            self.type: str = proxy_dict['type']
        except KeyError:
            exit_program(colorize(f'Type not set for proxy [{self.id}], exiting', Fore.RED))
        self.url: str | None = None
        self.http_proxy: str | None = None
        self.https_proxy: str | None = None
        match self.type:
            case 'direct':
                pass
            case 'pac':
                try:
                    self.url = proxy_dict['url']
                except KeyError:
                    exit_program(colorize(f'URL not set for proxy [{self.id}], exiting', Fore.RED))
            case 'system':
                pass
            case 'manual':
                try:
                    self.https_proxy = proxy_dict['https']
                except KeyError:
                    exit_program(colorize(f'HTTPS proxy is not set for proxy [{self.id}], exiting', Fore.RED))
                try:
                    self.http_proxy = proxy_dict['http']
                except KeyError:
                    exit_program(colorize(f'HTTP proxy is not set for proxy [{self.id}], exiting', Fore.RED))
            case _:
                exit_program(colorize(f'Invalid type [{self.type}] for proxy [{self.id}], exiting', Fore.RED))

    def __str__(self):
        match self.type:
            case 'direct':
                return 'Connexion directe à internet'
            case 'pac':
                return f'Configuration automatique (URL: {self.url})'
            case 'system':
                return 'Configuration système de la machine'
            case 'manual':
                if self.http_proxy == self.https_proxy:
                    return f'Configuration manuelle (HTTP/HTTPS: {self.https_proxy})'
                else:
                    return f'Configuration manuelle (HTTPS: {self.https_proxy}, HTTP: {self.http_proxy})'
            case _:
                raise ValueError


proxy_configs: dict[str, ProxyConfig] | None = None
proxy_config: ProxyConfig | None = None


def read_proxy_configs():
    global proxy_configs
    if proxy_configs is None:
        proxy_configs = {}
        proxy_config_file: Path = Path('proxy.yml')
        print('Reading proxy configurations... ')
        config_dicts: dict[str, dict[str, str]]
        try:
            with open(proxy_config_file, 'rt', encoding='utf8') as file:
                config_dicts = yaml.load(file.read().encode('utf-8'), Loader=SafeLoader)
        except FileNotFoundError:
            exit_program(colorize(f'File {proxy_config_file} not found, exiting', Fore.RED))
        for proxy_id, proxy_config_dict in config_dicts.items():
            proxy_configs[proxy_id] = ProxyConfig(proxy_id, proxy_config_dict)
            print(f'- {proxy_id}: {proxy_configs[proxy_id]}')
            if not proxy_configs:
                exit_program(colorize(f'No proxy configuration found in {proxy_config_file}, exiting', Fore.RED))


def set_proxy_config(proxy_id: str | None):
    global proxy_config
    global proxy_configs
    read_proxy_configs()
    if not proxy_id:
        proxy_config = proxy_configs[list(proxy_configs.keys())[0]]
        print(f'Using default proxy [{proxy_config.id}]')
    else:
        try:
            proxy_config = proxy_configs[proxy_id]
        except KeyError:
            exit_program(colorize(f'Proxy [{proxy_id}] not found, exiting', Fore.RED))


def get_proxy_config() -> ProxyConfig:
    global proxy_config
    global proxy_configs
    read_proxy_configs()
    if proxy_config is None:
        if len(proxy_configs) == 1:
            set_proxy_config(None)  # default
        else:
            print('Available proxy configurations:')
            i: int = 0
            for proxy_id in proxy_configs:
                print(f'- [{i + 1}] {proxy_configs[proxy_id].id}: {proxy_configs[proxy_id]}')
                i += 1
            while True:
                choice = input(
                    f'Choose the proxy to use (by default [1] {list(proxy_configs.keys())[0]}): '
                ).upper().strip() or '1'
                with suppress(ValueError, IndexError):
                    proxy_config = proxy_configs[list(proxy_configs.keys())[int(choice) - 1]]
                    break
    return proxy_config
