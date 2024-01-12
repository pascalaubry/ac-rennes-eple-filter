import re
from urllib.parse import urlparse

import yaml
from dns.exception import DNSException
from requests.exceptions import SSLError, ProxyError, TooManyRedirects, ConnectionError, Timeout
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from yaml.loader import SafeLoader
from common import colorize, exit_program, singleton
from colorama import Fore
import requests
from pypac import PACSession, get_pac


disable_warnings(InsecureRequestWarning)


@singleton
class ProxyConfig:

    def __init__(self):
        print('Reading proxy config... ', end='')
        proxy_config_file = 'proxy.yml'
        proxy_config: dict[str, str | dict[str, str] | None]
        with open(proxy_config_file, 'rt', encoding='utf8') as file:
            proxy_config = yaml.load(file.read().encode('utf-8'), Loader=SafeLoader)
        try:
            self.type: str = proxy_config['type']
        except KeyError:
            exit_program(f'Proxy type not set in {proxy_config_file}')
        self.pac_url: str | None = None
        self.http_proxy: str | None = None
        self.https_proxy: str | None = None
        match self.type:
            case 'direct':
                pass
            case 'pac':
                try:
                    self.pac_url = proxy_config['pac_url']
                except KeyError:
                    exit_program(f'Proxy pac_url not set in {proxy_config_file}')
            case 'system':
                pass
            case 'manual':
                try:
                    proxy_config['proxies']
                except KeyError:
                    exit_program(colorize(f"Manual proxies are not set in {proxy_config_file}", Fore.RED))
                try:
                    self.https_proxy = proxy_config['proxies']['https']
                except KeyError:
                    exit_program(colorize(f"Manual HTTPS proxy is not set in {proxy_config_file}", Fore.RED))
                try:
                    self.http_proxy = proxy_config['proxies']['http']
                except KeyError:
                    exit_program(colorize(f"Manual HTTP proxy is not set in {proxy_config_file}", Fore.RED))
            case _:
                exit_program(colorize(f"Invalid proxy type [{self.type}] in {proxy_config_file}", Fore.RED))
        print(colorize('OK', Fore.GREEN))

    def __str__(self):
        match self.type:
            case 'direct':
                return 'Connexion directe à internet'
            case 'pac':
                return f'Configuration automatique (URL: {self.pac_url})'
            case 'system':
                return 'Utilisation de la configuration système de la machine'
            case 'manual':
                return f'Configuration manuelle (HTTPS: {self.https_proxy}, HTTP: {self.http_proxy})'
            case _:
                raise ValueError


class WebClient:

    def __init__(self):
        print('Initializing web engine... ', end='')
        self.__session: PACSession | None = None
        print(colorize('OK', Fore.GREEN))

    @property
    def _session(self) -> PACSession:
        if self.__session is None:
            proxy_config: ProxyConfig = ProxyConfig()
            pac = get_pac(
                url=proxy_config.pac_url,
                from_os_settings=proxy_config.type == 'system',
                proxies={
                    'https': proxy_config.https_proxy,
                    'http': proxy_config.http_proxy,
                } if proxy_config.type == 'manual' else None
            )
            self.__session = PACSession(pac)
        return self.__session

    def __request(
            self, url: str, method: str, follow_redirect: bool,
            code_200_needed: bool, verify: bool, verbose: bool
    ) -> tuple[requests.Response | None, str | None]:
        last_url: str = url
        headers: dict[str, str] = {
            # use a 'standard' user agent to prevent from 403 errors on some sites
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36',
        }
        try:
            response: requests.Response | None = None
            if method == 'head':
                response: requests.Response = self._session.head(
                    url, headers=headers, verify=verify, allow_redirects=False)
            elif method == 'get':
                response: requests.Response = self._session.get(
                    url, headers=headers, verify=verify, allow_redirects=False)
            else:
                exit_program(colorize(f'Unknown method [{method}]', Fore.RED))
            if follow_redirect:
                while response.status_code in range(300, 400):
                    new_url = response.headers['location']
                    if not urlparse(new_url).scheme:
                        new_url = f'{urlparse(last_url).scheme}://{urlparse(last_url).netloc.rstrip("/")}/{new_url.lstrip("/")}'
                    last_url = new_url
                    if verbose:
                        p_url = urlparse(last_url)
                        if p_url.port:
                            print(f'>> {p_url.scheme}://{p_url.netloc.rstrip("/")}:{p_url.port}/{p_url.path.lstrip("/")} ', end='')
                        else:
                            print(f'>> {p_url.scheme}://{p_url.netloc.rstrip("/")}/{p_url.path.lstrip("/")} ', end='')
                    return self.__request(last_url, method, follow_redirect, code_200_needed, verify, verbose)
            if verbose:
                if code_200_needed and response.status_code != 200:
                    print(colorize(f'Error #{response.status_code} ', Fore.RED), end=' ')
                else:
                    print(colorize(f'{response.status_code} ',
                                   Fore.GREEN if response.status_code == 200 else Fore.YELLOW), end='')
            return response, last_url
        except ConnectionError as ce:
            if matches := re.match('^.*ProxyError\(.*OSError\(\'Tunnel connection failed: (.*)\'\).*$', str(ce)):
                print(colorize(f'Blocked by ProxyError({matches.group(1)}) ', Fore.YELLOW), end='')
                raise ProxyError()
            # if matches := re.match('^.*ProxyError\(.*RemoteDisconnected\(\'(.*)\'\).*$', str(ce)):
            #    print(colorize(f'RemoteDisconnected({matches.group(1)}) ', Fore.YELLOW), end='')
            #    raise ce
            searches: dict[str, tuple[str, Exception]] = {
                'RemoteDisconnected': ('RemoteDisconnected ', SSLError(),),
                'SSLError': ('SSLError ', SSLError(),),
                'NameResolutionError': ('NameResolutionError ', DNSException(),),
                'ConnectTimeoutError': ('ConnectTimeoutError ', ce,),
                'NewConnectionError': ('NewConnectionError ', ce,),
                'ConnectionResetError': ('ConnectionResetError ', ce,),
                'TooManyRedirects': ('TooManyRedirects ', ce,),
                'ProxyError': ('ProxyError ', ce,),
            }
            # print(colorize(f'ce=[{ce}] ', Fore.YELLOW), end='')
            for string in searches:
                if str(ce).find(string) != -1:
                    # if string == 'ProxyError':
                    #     print(colorize(f'{ce} ', Fore.YELLOW), end='')
                    print(colorize(f'{searches[string][0]} ', Fore.YELLOW), end='')
                    raise searches[string][1]
            print(colorize(f'{ce} ', Fore.YELLOW), end='')
            raise ce
        except TooManyRedirects:
            print(colorize(f'TooManyRedirects ', Fore.YELLOW), end='')
            raise ConnectionError()
        except Timeout:
            print(colorize(f'Timeout ', Fore.YELLOW), end='')
            raise ConnectionError()

    def head(
            self, url: str, follow_redirect: bool = True, code_200_needed: bool = True, verify: bool = True,
            verbose: bool = True
    ) -> tuple[requests.Response | None, str | None]:
        return self.__request(url, 'head', follow_redirect, code_200_needed, verify, verbose)

    def get(
            self, url: str, follow_redirect: bool = True, code_200_needed: bool = True, verify: bool = True,
            verbose: bool = True
    ) -> tuple[requests.Response | None, str | None]:
        return self.__request(url, 'get', follow_redirect, code_200_needed, verify, verbose)
