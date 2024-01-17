import json
import math
import random
import re
from enum import IntEnum

import chardet
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, ParseResult
import socket

import whois
from colorama import Fore
from django.template.defaulttags import register
from dns.exception import DNSException
from requests import Response
from requests.exceptions import SSLError, ProxyError, ConnectionError
from whois.parser import PywhoisError

from domain_checker import DomainChecker, PolicyResult
from common import colorize, VERSION, get_reports_dir
from database import Database
from html_renderer import HTMLRenderer
from policy import Policy
from web_client import WebClient, ProxyConfig


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


class ResultStatus(IntEnum):
    DnsError = 0
    SslError = 1
    ConnectError = 2
    NotAuthenticated = 3
    Allowed = 4
    Denied = 5

    @property
    def report_str(self) -> str:
        match self:
            case ResultStatus.SslError:
                return 'Erreur SSL'
            case ResultStatus.DnsError:
                return 'Erreur DNS'
            case ResultStatus.ConnectError:
                return 'Erreur de connexion'
            case ResultStatus.NotAuthenticated:
                return 'Erreur d\'authentification'
            case ResultStatus.Allowed:
                return 'Autorisée'
            case ResultStatus.Denied:
                return 'Interdite'
            case _:
                raise ValueError

    def __str__(self) -> str:
        match self:
            case ResultStatus.SslError:
                return 'SSL error'
            case ResultStatus.DnsError:
                return 'DNS error'
            case ResultStatus.ConnectError:
                return 'Connection error'
            case ResultStatus.NotAuthenticated:
                return 'Auth error'
            case ResultStatus.Allowed:
                return 'Allowed'
            case ResultStatus.Denied:
                return 'Denied'
            case _:
                raise ValueError


class WebResult:
    def __init__(self, domain: str, url: str, web: WebClient):
        self.status: ResultStatus | None = None
        self.domain = domain
        parsed_url: ParseResult = urlparse(url)
        self.url_protocol = parsed_url.scheme
        self.url_domain = parsed_url.netloc
        self.cached = False
        cache_dir: Path = Path('.') / 'cache' / 'control'
        cache_dir.mkdir(parents=True, exist_ok=True)
        info_cache_file = cache_dir / f'{self.url_protocol}_{self.url_domain}.info'
        content_cache_file = cache_dir / f'{self.url_protocol}_{self.url_domain}.html'
        self.response_code: int | None = None
        self.response_content: str | None = None
        self.response_headers: dict[str] | None = None
        self.final_url: str | None = None
        self.matching_category: str | None = None
        self.matching_domain: str | None = None
        if info_cache_file.exists():
            if time.time() - info_cache_file.lstat().st_mtime < 4 * 3600:
                print('cached ', end='')
                with open(info_cache_file, 'r') as f:
                    data = json.load(f)
                    self.status = ResultStatus(data['status'])
                    self.final_url = data['final_url']
                    self.matching_domain = data['matching_domain']
                    self.matching_category = data['matching_category']
                    self.response_code = data['response_code']
                    self.response_headers = data['response_headers']
                if content_cache_file.exists():
                    with open(content_cache_file, 'rb') as f:
                        self.response_content = f.read().decode('utf-8')
                if self.final_url is not None and self.final_url != url:
                    print(f'>>...>> {self.final_url} ', end='')
                if self.response_code:
                    print(colorize(
                        f'{self.response_code} ', Fore.GREEN if self.response_code == 200 else Fore.YELLOW), end='')
                print(f'{self.status} ', end='')
                self.cached = True
            else:
                print('expired ', end='')
        if not self.cached:
            try:
                response: Response
                response, self.final_url = web.get(url, follow_redirect=True, code_200_needed=False, verify=False)
                self.__decode_response(response)
            except ProxyError:
                self.status = ResultStatus.Denied
            except SSLError:
                self.status = ResultStatus.SslError
            except DNSException:
                self.status = ResultStatus.DnsError
            except ConnectionError:
                self.status = ResultStatus.ConnectError
            if self.status is None:
                self.__analyse_response()
            with open(info_cache_file, 'w') as f:
                json.dump({
                    'status': self.status,
                    'final_url': self.final_url,
                    'response_code': self.response_code,
                    'matching_category': self.matching_category,
                    'matching_domain': self.matching_domain,
                    'response_headers': self.response_headers,
                }, f)
            if self.response_content:
                with open(content_cache_file, 'wb') as f:
                    f.write(self.response_content.encode('utf-8'))
        self.compliant: bool | None = None

    def __decode_response(self, response: Response):
        self.response_code = response.status_code
        self.response_headers = {}
        for k in response.headers:
            self.response_headers[k] = response.headers[k]
        encoding: str = ''
        try:
            encoding = chardet.detect(response.content)['encoding']
            if encoding is None:
                encoding = 'utf-8'
            self.response_content = response.content.decode(encoding)
        except UnicodeDecodeError as ude:
            if encoding == 'utf-8':
                print(colorize(f'UnicodeDecodeError (encoding detected: {encoding}) {ude} ', Fore.YELLOW),
                      end='')
                self.status = ResultStatus.Allowed
                return
            try:
                encoding = 'utf-8'
                self.response_content = response.content.decode(encoding)
            except UnicodeDecodeError as ude:
                print(colorize(f'UnicodeDecodeError (encoding supposed: {encoding}) {ude} ', Fore.YELLOW),
                      end='')
                self.status = ResultStatus.Allowed

    def __analyse_response(self):
        # print(f"code={response.status_code} ", end='')
        if (self.final_url.startswith('http://articatech.net/block.html')
                or self.final_url.startswith('https://articatech.net/block.html')):
            print(colorize(f'Blocked by Artica ', Fore.YELLOW), end=' ')
            self.status = ResultStatus.Denied
            return
        if 'X-Squid-Error' in self.response_headers:
            if self.response_headers['X-Squid-Error'].startswith('ERR_ACCESS_DENIED'):
                print(colorize(f'Denied by Squid ', Fore.YELLOW), end=' ')
                self.status = ResultStatus.Denied
                return
            if self.response_headers['X-Squid-Error'].startswith('ERR_DNS_FAIL'):
                print(colorize(f'DNS failed ', Fore.YELLOW), end=' ')
                self.status = ResultStatus.DnsError
                return
            if self.response_headers['X-Squid-Error'].startswith('ERR_CONNECT_FAIL'):
                print(colorize(f'Connect failed ', Fore.YELLOW), end=' ')
                self.status = ResultStatus.ConnectError
                return
            else:
                print(colorize(
                    f"Unknown X-Squid-Error=[{self.response_headers['X-Squid-Error']}] ", Fore.YELLOW), end='')
        if self.response_code == 499:
            print(colorize(f'Blocked by antivirus ', Fore.YELLOW), end='')
            self.status = ResultStatus.Denied
            return
        response_lines: list[str] = self.response_content.splitlines()
        one_line_content: str = ' '.join(response_lines)
        if self.response_code == 503:
            if re.match(r'.*<!-- ERR_DNS_FAIL -->.*', one_line_content):
                print(colorize(f'ERR_DNS_FAIL ', Fore.YELLOW), end='')
                self.status = ResultStatus.DnsError
                return
            if re.match(r'.*<!-- ERR_CONNECT_FAIL -->.*', one_line_content):
                print(colorize(f'ERR_CONNECT_FAIL ', Fore.YELLOW), end='')
                self.status = ResultStatus.ConnectError
                return
            if re.match(r'.*<h1>page web bloquée</h1>.*', one_line_content.lower()):
                # if matches := re.match(
                #        r'.*<p><b>url:</b>(.+)</p>\s*<p><b>category:</b>(.+)</p>.*', one_line_content.lower()):
                #    blocked_url = matches.group(1).strip()
                #    blocked_category = matches.group(2).strip()
                if matches := re.match(
                        r'.*<p><b>url:</b>([^<]+)<.*', one_line_content.lower()):
                    self.matching_domain = matches.group(1).strip()
                if matches := re.match(
                        r'.*.*<p><b>category:</b>([^<]+)<.*.*', one_line_content.lower()):
                    self.matching_category = matches.group(1).strip()
                print(colorize(
                    f'URL {self.matching_domain} blocked for category {self.matching_category} ', Fore.YELLOW), end='')
                self.status = ResultStatus.Denied
                return
            else:
                print(colorize(f'[<h1>page web bloquée</h1> not found] one_line_content={one_line_content}', Fore.BLUE))
            for line in response_lines:
                match: bool = False
                if re.match(r'.*<h1>page web bloquée</h1>.*', line.lower()):
                    match = True
                if re.match(r'.*<b>category:</b>.*', line.lower()):
                    match = True
                if re.match(r'.*<b>url:</b>.*', line.lower()):
                    match = True
                print(colorize(line[:256], Fore.BLUE if match else Fore.YELLOW))
            self.status = ResultStatus.Denied
            return
        if self.response_code == 202:  # Stormshield
            title_https_web_site_blocked: int = False
            for line in response_lines:
                if re.match(r'.*<title>\s*(HTTPS web site blocked)\s*</title>.*', line):
                    title_https_web_site_blocked = True
                if line.strip() == 'Blocage':
                    print(colorize(f'Blocked by Stormshield ({line}) ', Fore.YELLOW), end='')
                    self.status = ResultStatus.Denied
                    return
                if matches := re.match(r'.*<title id="header_title">([^<]+)</title>.*', line):
                    print(colorize(f'Blocked by Stormshield (policy: {matches.group(1)}) ', Fore.YELLOW), end='')
                    self.status = ResultStatus.Denied
                    return
                if matches := re.match(
                        r'.*<blockquote><h\d>\s*Reason\s*:\s*([^<]*)<br>.*</h\d></blockquote>.*', line):
                    reason: str = matches.group(1).strip()
                    for string in [
                        'expired',  # The SSL server certificate is expired or not yet valid
                        'not trusted',  # The SSL server certificate authority is not trusted
                        'self-signed',  # The SSL server uses a self-signed certificate
                        'requested name',  # The SSL server does not match the requested name
                    ]:
                        if reason.find(string) != -1:
                            print(colorize(f'Blocked by Stormshield (SSL error: {reason}) ', Fore.YELLOW), end='')
                            self.status = ResultStatus.SslError
                            return
                    for string in [
                        'rejects the connection',  # Your administrator rejects the connection to this SSL server
                    ]:
                        if reason.find(string) != -1:
                            print(colorize(f'Blocked by Stormshield (policy error: {reason}) ', Fore.YELLOW), end='')
                            self.status = ResultStatus.Denied
                            return
                    print(colorize(f'Blocked by Stormshield (unknown error: {reason}) ', Fore.YELLOW), end='')
                    self.status = ResultStatus.Denied
                    return
            if title_https_web_site_blocked:
                print(colorize('HTTPS web site blocked (no reason found in content) ', Fore.YELLOW), end='')
                for line in response_lines:
                    print(colorize(line[:256], Fore.YELLOW))
                self.status = ResultStatus.Denied
                return
            print(colorize('No blocking pattern found ', Fore.YELLOW), end='')
            for line in response_lines:
                print(colorize(line[:256], Fore.YELLOW))
            self.status = ResultStatus.Allowed
            return
        if self.response_code == 200:
            for line in response_lines:
                # <meta
                #   http-equiv="refresh"
                #   content="0; url=https://85-NAC01.colleges35.sib.fr/captive-portal?destination_url=<url>">
                if re.match(r'.*<meta\s+http-equiv="refresh"\s+content=".*colleges35\.sib\.fr.*".*>', line):
                    print(colorize('Not authenticated by Artica ', Fore.YELLOW), end='')
                    self.status = ResultStatus.NotAuthenticated
                    return
                if re.match(r'.*<title>AUTHENTIFICATION</title>.*', line):
                    print(colorize('Not authenticated by Stormshield ', Fore.YELLOW), end='')
                    self.status = ResultStatus.NotAuthenticated
                    return
        self.status = ResultStatus.Allowed
        return

    @property
    def not_authenticated(self) -> bool:
        return self.status == ResultStatus.NotAuthenticated

    @property
    def error(self) -> bool:
        return self.status in [ResultStatus.DnsError, ResultStatus.SslError, ResultStatus.ConnectError]

    @property
    def allowed(self) -> bool:
        return self.status == ResultStatus.Allowed

    @property
    def denied(self) -> bool:
        return self.status == ResultStatus.Denied

    @property
    def simplified_final_url(self) -> str | None:
        if not self.final_url:
            return None
        url: ParseResult = urlparse(self.final_url)
        return f'{url.scheme}://{url.netloc}{f":{url.port}" if url.port else ""}{url.path if url.path else "/"}{"?..." if url.query else ""}'

    def set_compliant(self, compliant: bool):
        self.compliant = compliant

    def __str__(self) -> str:
        return (f'{self.__class__.__name__}('
                f'url_protocol={self.url_protocol}, '
                f'url_domain={self.url_domain}, '
                f'domain={self.domain}, '
                f'status={self.status}, '
                f'final_url={self.final_url}, '
                f'response_code={self.response_code}, '
                f'response_length={len(self.response_content) if self.response_content else None}, '
                f'response_headers={self.response_headers}'
                f')')


class PolicyController:

    def __init__(
            self, policy: Policy, database: Database, web: WebClient,
            profile: str, verbose: bool = True):
        self.policy: Policy = policy
        self.database: Database = database
        self.profile: str = profile
        self.hostname: str = socket.gethostname()
        if verbose:
            print(f'Hostname:   {self.hostname}')
        self.private_ip: str = socket.gethostbyname(self.hostname)
        if verbose:
            print(f'Private IP: {self.private_ip}')
        if verbose:
            print('Retrieving public IP... ', end='')
        self.public_ip: str | None = None
        self.public_hostname: str | None = None
        ip_url: str = 'https://api.ipify.org'
        try:
            self.public_ip = web.get(
                ip_url, follow_redirect=True, code_200_needed=True, verbose=verbose, verify=False
            )[0].content.decode('utf8')
            self.public_hostname = socket.gethostbyaddr(self.public_ip)[0]
        except ConnectionError:
            print(colorize(f'could not reach {ip_url} ', Fore.YELLOW), end='')
            pass
        except socket.herror:
            pass
        except AttributeError:
            pass
        if verbose:
            if self.public_hostname is None or self.public_ip == self.public_hostname:
                print(f'\nPublic IP:  {self.public_ip}')
            else:
                print(f'\nPublic IP:  {self.public_ip} ({self.public_hostname})')
        self.policy_expected_results_file: Path = Path('ac_rennes_eple_filter_expected_results.json')
        self.policy_expected_results: dict[str, PolicyResult] = {}
        self.web_results: dict[str, WebResult] = {}
        self.error_urls: list[str] = []
        self.compliant_urls: list[str] = []
        self.too_strict_urls: list[str] = []
        self.too_permissive_urls: list[str] = []
        if self.__read_policy_expected_results(verbose):
            self.__test_urls(web, verbose)

    def __read_policy_expected_results(self, verbose: bool) -> bool:
        if verbose:
            print(f'Looking for {self.policy_expected_results_file}... ', end='')
        if not self.policy_expected_results_file.is_file():
            if verbose:
                print(colorize(f'file not found.', Fore.YELLOW))
            self.__build_policy_expected_results_file(verbose)
        elif self.policy_expected_results_file.lstat().st_mtime > time.time() - 60 * 60 * 24:
            if verbose:
                print(colorize(f'up to date.', Fore.GREEN))
        else:
            if verbose:
                print(colorize(f'obsolete.', Fore.GREEN))
            self.__build_policy_expected_results_file(verbose)
        if not self.policy_expected_results_file.exists():
            print(colorize(f'File {self.policy_expected_results_file} not found, aborting.', Fore.RED))
            return False
        if verbose:
            print(f'Reading {self.policy_expected_results_file}... ', end='')
        with open(self.policy_expected_results_file, 'r') as f:
            profile_results: dict[str, dict[str, bool | str]] = json.loads(f.read())[self.profile]
            for url in profile_results:
                self.policy_expected_results[url] = PolicyResult(
                    profile_results[url]['allowed'], profile_results[url]['matching_domain'],
                    profile_results[url]['matching_category'])
        if verbose:
            print(colorize(f'{len(self.policy_expected_results)} domains read.', Fore.GREEN))
        return True

    @staticmethod
    def __test_whois_dns(domain: str) -> bool:
        # print(f'{str}')
        domain_parts = domain.split('.')
        domain = '.'.join(domain_parts[-2:])
        # print(f'  domain = {domain}')
        try:
            whois_response = whois.whois(domain)
        except PywhoisError as pwe:
            print(colorize(f'PywhoisError={str(pwe).splitlines(keepends=False)[0]} ', Fore.BLUE), end='')
            return False
        try:
            whois_domain = whois_response["domain_name"]
        except KeyError:
            print(colorize(f'domain_name not set ', Fore.BLUE), end='')
            try:
                whois_domain = whois_response["name"]
            except KeyError:
                print(colorize(f'name not set ', Fore.BLUE), end='')
                return False
        if whois_domain is None:
            print(colorize(f'empty domain ', Fore.BLUE), end='')
            return False
        try:
            socket.getaddrinfo(domain, 0)
        except socket.gaierror as ge:
            print(colorize(f'{ge} ', Fore.BLUE), end='')
            return False
        return True

    def __get_test_domains(self, verbose: bool = True) -> list[str]:
        """return [
            'toutatice.fr',
            'u-bordeaux.fr',
            'www.ac-rennes.fr',
            'ip-stresser-xbox.hdxba.com',
            'ddlddl.free.fr',
            'selectivesearch-inc.com',
            'yalho.com',
            'app-analytics.snapchat.com',
            'xnore.com',
            'blade24.lisbon-rack405.nodes.gen4.ninja',
            'blade2.vienna-rack452.nodes.gen4.ninja',
            'world.wemineltc.com',
            'dvdplayer.de',
        ][:3]"""
        categories: dict[str, dict[str, str | int]] = {}
        self.database.execute('SELECT origin, category, COUNT(id) FROM data GROUP BY origin, category')
        for result in self.database.fetchall():
            categories[result[1]] = {
                'origin': result[0],
                'domains_number': result[2],
            }
        domains: list[str] = []
        random.seed()
        for rule in self.policy.active_rules:  # + self.policy.inactive_rules:
            if rule.category in categories:
                category_domains: int = 0
                if categories[rule.category]['origin'] == 'rennes':
                    domain_per_category: int = 20
                    if verbose:
                        print(f'Adding last {domain_per_category} domains of category {rule.category}... ', end='')
                    self.database.execute(
                        'SELECT domain FROM data WHERE category = ? ORDER BY id DESC LIMIT ?',
                        (rule.category, domain_per_category * 3))
                    for result in self.database.fetchall():
                        domain: str = result[0]
                        if self.__test_whois_dns(domain):
                            domains.append(domain := result[0])
                            category_domains += 1
                            if verbose:
                                print(f'{domain} ({category_domains}) ', end='')
                            if category_domains == domain_per_category:
                                break
                        else:
                            if verbose:
                                print(colorize(f'{domain} ', Fore.YELLOW), end='')
                else:
                    domain_per_category: int = 5
                    if verbose:
                        print(f'Picking last {domain_per_category} domains of category {rule.category}... ', end='')
                    self.database.execute(
                        'SELECT domain FROM data WHERE category = ? ORDER BY id DESC LIMIT 1',
                        (rule.category, ))
                    domain: str = self.database.fetchone()[0]
                    if self.__test_whois_dns(domain):
                        domains.append(domain)
                        category_domains += 1
                        if verbose:
                            print(f'{domain} ({category_domains}) ', end='')
                    else:
                        if verbose:
                            print(colorize(f'{domain} ', Fore.YELLOW), end='')
                    for i in range(3 * domain_per_category - 1):
                        self.database.execute(
                            'SELECT domain FROM data WHERE category = ? ORDER BY id DESC LIMIT ?, ?',
                            (rule.category, random.randrange(0, categories[rule.category]['domains_number']), 1))
                        domain: str = self.database.fetchone()[0]
                        if self.__test_whois_dns(domain):
                            domains.append(domain)
                            category_domains += 1
                            if verbose:
                                print(f'{domain} ({category_domains}) ', end='')
                            if category_domains == domain_per_category:
                                break
                        else:
                            if verbose:
                                print(colorize(f'{domain} ', Fore.YELLOW), end='')
                if verbose:
                    print(f'')
            else:
                if verbose:
                    print(f'Category {rule.category} not found in database.')
        return domains

    def __build_policy_expected_results_file(self, verbose: bool = True):
        if verbose:
            print(f'Building policy expected results...')
        domains: list[str] = self.__get_test_domains(verbose)
        expected_results_dict: dict[str, dict[str, dict[str, bool | str]]] = {}
        for profile in Policy.profiles:
            expected_results_dict[profile] = {}
        for domain in domains:
            if verbose:
                print(f'Getting policy on domain {domain}... ', end='')
            domain_checker: DomainChecker = DomainChecker(self.policy, self.database, domain, verbose=False)
            for profile in Policy.profiles:
                result = domain_checker.result(profile)
                expected_results_dict[profile][domain] = {
                    'allowed': result.allowed,
                    'matching_domain': result.matching_domain,
                    'matching_category': result.matching_category,
                }
            if verbose:
                print('/'.join([
                    ('allowed' if expected_results_dict[profile][domain]['allowed'] else 'denied')
                    for profile in Policy.profiles
                ]))
        if verbose:
            print(f'Writing {self.policy_expected_results_file}... ', end='')
        with open(self.policy_expected_results_file, 'w') as f:
            f.write(json.dumps(expected_results_dict))
        if verbose:
            print(colorize('OK', Fore.GREEN))

    def __test_urls(self, web: WebClient, verbose: bool):
        first_domain = ''
        items = len(self.policy_expected_results) * 2
        item = 0
        start = time.time()
        eta = '--:--'
        for domain in self.policy_expected_results:
            if first_domain:
                if domain != first_domain:
                    continue
                else:
                    first_domain = ''
            for scheme in ['http', 'https', ]:
                item_start = time.time()
                item_percent = 100 * item // items
                if item > 10:
                    average_time = (time.time() - start) / item
                    estimated_time = math.ceil((items - item) * average_time)
                    eta = f'{estimated_time // 60:02}:{estimated_time % 60:02}'
                url = f'{scheme}://{domain}/'
                if verbose:
                    print(f'[{item_percent:02}%] [ETA: {eta}] Testing {url} ', end='')
                self.web_results[url] = WebResult(domain, url, web)
                if self.web_results[url].error:
                    parse_result = urlparse(url)
                    if (not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parse_result.netloc)
                            and not parse_result.netloc.startswith('www.')):
                        # TEST WWW.DOMAIN
                        www_url = url.replace('://', '://www.')
                        if verbose:
                            print(f'Trying {www_url} ', end='')
                        self.web_results[url] = WebResult(domain, www_url, web)
                if self.web_results[url].cached:
                    items -= 1
                else:
                    item += 1
                match self.web_results[url].status:
                    case ResultStatus.SslError | ResultStatus.DnsError | ResultStatus.ConnectError:
                        print(colorize(f'{self.web_results[url].status}', Fore.YELLOW), end='')
                        self.error_urls.append(url)
                    case ResultStatus.NotAuthenticated:
                        print(colorize(f'{self.web_results[url].status}', Fore.YELLOW), end='')
                        self.error_urls.append(url)
                    case ResultStatus.Allowed:
                        self.web_results[url].set_compliant(self.policy_expected_results[domain].allowed)
                        if self.web_results[url].compliant:
                            self.compliant_urls.append(url)
                            print(colorize('OK', Fore.GREEN), end='')
                        else:
                            self.too_permissive_urls.append(url)
                            print(colorize('too permissive', Fore.RED), end='')
                    case ResultStatus.Denied:
                        self.web_results[url].set_compliant(not self.policy_expected_results[domain].allowed)
                        if self.web_results[url].compliant:
                            self.compliant_urls.append(url)
                            print(colorize('OK', Fore.GREEN), end='')
                        else:
                            self.too_strict_urls.append(url)
                            print(colorize('too strict', Fore.RED), end='')
                print(f' ({time.time() - item_start:.2f})')
        time_spent: int = math.ceil(time.time() - start)
        print(f'Time spent: {time_spent // 60:02}:{time_spent % 60:02}')

    @property
    def test_nb(self) -> int:
        return len(self.web_results.keys())

    @property
    def error_nb(self) -> int:
        return len(self.error_urls)

    @property
    def too_strict_nb(self) -> int:
        return len(self.too_strict_urls)

    @property
    def too_permissive_nb(self) -> int:
        return len(self.too_permissive_urls)

    @property
    def compliant_nb(self) -> int:
        return len(self.compliant_urls)

    @property
    def compliance_str(self) -> str:
        total_nb: int = self.compliant_nb + self.too_strict_nb + self.too_permissive_nb
        return '-' if total_nb == 0 else f'{self.compliant_nb / total_nb * 100:.0f}%'

    def print(self):
        date: str = datetime.now().strftime("%Y%m%d")
        html_file: Path = (get_reports_dir()
                           / f'ac_rennes_eple_filter-{VERSION}-{self.profile.upper()}'
                             f'-{self.public_ip}-{date}-{ProxyConfig().type}.html')
        HTMLRenderer().render(
            'report.html',
            {
                'controller': self,
                'proxy_config': ProxyConfig(),
            },
            html_file)
