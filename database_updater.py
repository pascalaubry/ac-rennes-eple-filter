import os.path
from abc import abstractmethod
from pathlib import Path
from typing import List, Tuple, Optional

import requests
import tarfile
import time
from dns.exception import DNSException
from requests.exceptions import SSLError, ProxyError, ConnectionError, Timeout

from database import Database
from web_client import WebClient
from colorama import Fore
from common import colorize, get_download_cache_dir


class Category:

    def __init__(
            self,
            name: str, origin_name: str,
            download_folder: Path, download_filename_extension: str, base_url: str,
            web: WebClient, database: Database):
        super().__init__()
        self._name: str = name
        self.__origin_name: str = origin_name
        self._download_folder: Path = download_folder
        download_filename: str = self._name + '.' + download_filename_extension
        self.__url: str = base_url + '/' + download_filename
        self._download_file: Path = download_folder / download_filename
        self._domains_file: Optional[Path] = None
        self.__web: WebClient = web
        self.__database: Database = database

    @abstractmethod
    def _extract(self) -> bool:
        return True

    def download(self) -> bool:
        last_modified_file: Path = self._download_folder / (self._name + '.last-modified')
        if os.path.exists(last_modified_file):
            print(f'Looking for changes in category {self._name}... ', end='')
            with open(last_modified_file, 'r') as f:
                local_last_modified: str = f.read()
                response: requests.Response
                final_url: str
                try:
                    response, final_url = self.__web.head(self.__url, verbose=False)[:2]
                except ProxyError | SSLError | DNSException | ConnectionError:
                    print(colorize(f'no response', Fore.RED))
                    return False
                if 'last-modified' not in response.headers:
                    print(colorize(f'last-modified field not in response header ({final_url})', Fore.RED))
                    print(response.content)
                    return False
                last_modified = response.headers['last-modified']
                if response.headers['last-modified'] == local_last_modified:
                    print(colorize(f'up to date ({local_last_modified})', Fore.GREEN))
                    return True
                print(colorize(f'changes detected ({last_modified})', Fore.YELLOW))
        print(f'Downloading category {self._name}... ', end='')
        response: requests.Response
        final_url: str
        try:
            response = self.__web.get(self.__url)[0]
        except ProxyError | SSLError | DNSException | ConnectionError | Timeout:
            print(colorize(f'no response', Fore.RED))
            return False
        if 'last-modified' not in response.headers:
            print(colorize(f'last-modified field not in response header', Fore.RED))
            return False
        print(colorize('OK', Fore.GREEN))
        open(self._download_file, 'wb').write(response.content)
        if not self._extract():
            return False
        if not os.path.exists(self._domains_file):
            print(colorize(f'Category {self._name}: File not found ({self._domains_file})', Fore.RED))
            return False
        open(last_modified_file, 'w').write(response.headers['last-modified'])
        return True

    def __store_domains(self, domains: List[str]):
        data: List[Tuple[str, str, str]] = []
        for domain in domains:
            data.append((self.__origin_name, self._name, domain))
        self.__database.executemany('INSERT INTO data(origin, category, domain) VALUES (?, ?, ?)', data)

    def store(self) -> int:
        print(f'Storing category {self._name}...', end='')
        start = time.time()
        entries: int = 0
        bulk_size: int = 15000
        print_size: int = 100000
        with open(self._domains_file) as f:
            domains: List[str] = []
            for line in f:
                line = line.strip()
                if line != '' and line[0] != '#' and line.find('*') == -1:
                    domains.append((line.strip()))
                    entries += 1
                if entries > 0 and entries % bulk_size == 0:
                    self.__store_domains(domains)
                    domains = []
                if entries > 0 and entries % print_size == 0:
                    print(colorize('.', Fore.GREEN), end='')
            self.__store_domains(domains)
            print(colorize(
                f' {entries} domains added in {time.time() - start:.0f} seconds', Fore.GREEN))
        return entries


class RennesCategory(Category):

    def __init__(self, name: str, origin_name: str, download_folder: Path, web: WebClient, database: Database):
        super().__init__(
            name, origin_name,
            download_folder, 'txt', 'https://www.toutatice.fr/filtrage',
            web, database)
        self._domains_file = self._download_file

    def _extract(self) -> bool:
        return True


class ToulouseCategory(Category):

    def __init__(self, name: str, origin_name: str, download_folder: Path, web: WebClient, database: Database):
        super().__init__(
            name, origin_name,
            download_folder, 'tar.gz', 'http://dsi.ut-capitole.fr/blacklists/download',
            web, database)
        sub_folder: str = name
        if sub_folder == 'malware':  # packaging bug in toulouse lists!!!
            sub_folder = 'phishing'
        self._domains_file = self._download_folder / sub_folder / 'domains'

    def _extract(self) -> bool:
        print(f'Extracting {os.path.basename(self._download_file)}... ', end='')
        archive = tarfile.open(self._download_file)
        archive.extractall(self._download_folder)
        archive.close()
        print(colorize(f'OK', Fore.GREEN))
        return True


class CategoryOrigin:

    def __init__(self, name: str, download_folder: Path):
        super().__init__()
        self._name = name
        self._download_folder: Path = download_folder / self._name
        self._categories: List[Category] = []

    def download(self) -> bool:
        print(f'Downloading origin {self._name}...')
        if not os.path.exists(self._download_folder):
            os.makedirs(self._download_folder)
        download_ok: bool = True
        for category in self._categories:
            if not category.download():
                download_ok = False
        if download_ok:
            print(colorize(f'Downloaded origin {self._name}.', Fore.GREEN))
        else:
            print(colorize(f'Downloading origin {self._name} failed.', Fore.RED))
        return download_ok

    def store(self) -> int:
        total_entries: int = 0
        for category in self._categories:
            total_entries += category.store()
        return total_entries


class RennesOrigin(CategoryOrigin):

    category_names: List[str] = [
        'whitelist-BYPASS-AUTH',
        'blacklist-CLG-LYC-PERS',
        'blacklist-CLG-LYC',
        'blacklist-CLG',
        'whitelist-PERS-LYC-CLG',
        'whitelist-PERS-LYC',
        'whitelist-PERS',
    ]

    def __init__(self, download_folder: Path, web: WebClient, database: Database):
        name = 'rennes'
        super().__init__(name, download_folder)
        for category_name in self.category_names:
            self._categories.append(
                RennesCategory(category_name, self._name, self._download_folder, web, database))


class ToulouseOrigin(CategoryOrigin):

    category_names: List[str] = [
        'adult',
        'agressif',
        'arjel',
        'associations_religieuses',
        'astrology',
        'audio-video',
        'bank',
        'bitcoin',
        'blog',
        'celebrity',
        'chat',
        'child',
        'cleaning',
        'cooking',
        'cryptojacking',
        'dangerous_material',
        'dating',
        'ddos',
        'dialer',
        'doh',
        'download',
        'drogue',
        'educational_games',
        'examen_pix',
        'filehosting',
        'financial',
        'forums',
        'gambling',
        'games',
        'hacking',
        'jobsearch',
        'lingerie',
        'liste_blanche',
        'liste_bu',
        'malware',
        'manga',
        'marketingware',
        'mixed_adult',
        'mobile-phone',
        'phishing',
        'press',
        'publicite',
        'radio',
        'reaffected',
        'redirector',
        'remote-control',
        'sect',
        'sexual_education',
        'shopping',
        'shortener',
        'social_networks',
        'sports',
        'stalkerware',
        'strict_redirector',
        'strong_redirector',
        'translation',
        'tricheur',
        'update',
        'vpn',
        'warez',
        'webmail',
    ]

    def __init__(self, download_folder: Path, web: WebClient, database: Database):
        name = 'toulouse'
        super().__init__(name, download_folder)
        for category_name in self.category_names:
            self._categories.append(
                ToulouseCategory(category_name, self._name, self._download_folder, web, database))


class DatabaseUpdater:

    def __init__(self, database: Database, web: WebClient):
        super().__init__()
        self.__database = database
        download_folder: Path = get_download_cache_dir()
        self.__origins: List[CategoryOrigin] = [
            RennesOrigin(download_folder, web, database),
            ToulouseOrigin(download_folder, web, database),
            ]

    def update(self) -> int:
        print('Downloading...')
        download_ok = True
        for origin in self.__origins:
            if not origin.download():
                download_ok = False
        if not download_ok:
            print(colorize('Downloading failed, database will not be updated.', Fore.RED))
            return 0
        print(colorize('All downloads succeeded.', Fore.GREEN))
        print('Resetting the database... ', end='')
        self.__database.execute('DELETE FROM data')
        print(colorize('OK', Fore.GREEN))
        print('Filling the database...')
        entries: int = 0
        for origin in self.__origins:
            entries += origin.store()
        print(colorize(f'{entries} total entries stored.', Fore.GREEN if entries > 0 else Fore.RED))
        self.__database.commit()
        return entries
