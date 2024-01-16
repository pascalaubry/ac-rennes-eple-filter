import json
import math
import random
import re
from enum import IntEnum

import chardet
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import requests
import socket

import whois
from colorama import Fore
from django.template.defaulttags import register
from dns.exception import DNSException
from requests.exceptions import SSLError, ProxyError, ConnectionError
from whois.parser import PywhoisError

from domain_checker import DomainChecker, PolicyResult
from common import colorize, VERSION
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

    def __str__(self) -> str:
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


class WebResult:
    def __init__(self, url: str, web: WebClient):
        response: requests.Response | None
        final_url: str | None
        self.status: ResultStatus | None = None
        self.compliant: bool | None = None
        self.domain = urlparse(url).netloc
        try:
            response, final_url = web.get(url, follow_redirect=True, code_200_needed=False, verify=False)
        except ProxyError:
            self.status = ResultStatus.Denied
            return
        except SSLError:
            self.status = ResultStatus.SslError
            return
        except DNSException:
            self.status = ResultStatus.DnsError
            return
        except ConnectionError:
            self.status = ResultStatus.ConnectError
            return
        # print(f"code={response.status_code} ", end='')
        if (final_url.startswith('http://articatech.net/block.html')
                or final_url.startswith('https://articatech.net/block.html')):
            print(colorize(f'Blocked by Artica ', Fore.YELLOW), end=' ')
            self.status = ResultStatus.Denied
            return
        if 'X-Squid-Error' in response.headers:
            if response.headers['X-Squid-Error'].startswith('ERR_ACCESS_DENIED'):
                print(colorize(f'Denied by Squid ', Fore.YELLOW), end=' ')
                self.status = ResultStatus.Denied
                return
            if response.headers['X-Squid-Error'].startswith('ERR_DNS_FAIL'):
                print(colorize(f'DNS failed ', Fore.YELLOW), end=' ')
                self.status = ResultStatus.DnsError
                return
            if response.headers['X-Squid-Error'].startswith('ERR_CONNECT_FAIL'):
                print(colorize(f'Connect failed ', Fore.YELLOW), end=' ')
                self.status = ResultStatus.ConnectError
                return
            else:
                print(colorize(f"Unknown X-Squid-Error=[{response.headers['X-Squid-Error']}] ", Fore.YELLOW), end='')
        if response.status_code == 499:
            print(colorize(f'Blocked by antivirus ', Fore.YELLOW), end='')
            self.status = ResultStatus.Denied
            return
        decoded_content: str
        decoded_lines: list[str]
        one_line_content: str
        encoding: str = ''
        content: bytes = response.content
        try:
            encoding = chardet.detect(content)['encoding']
            if encoding is None:
                encoding = 'utf-8'
            decoded_content = content.decode(encoding)
            decoded_lines = decoded_content.splitlines()
            one_line_content = ' '.join(decoded_lines)
        except UnicodeDecodeError as ude:
            if encoding == 'utf-8':
                print(colorize(f'UnicodeDecodeError (encoding detected: {encoding}) {ude} ', Fore.YELLOW), end='')
                self.status = ResultStatus.Allowed
                return
            try:
                encoding = 'utf-8'
                decoded_content = content.decode(encoding)
                decoded_lines = decoded_content.splitlines()
                one_line_content = ' '.join(decoded_lines)
            except UnicodeDecodeError as ude:
                print(colorize(f'UnicodeDecodeError (encoding supposed: {encoding}) {ude} ', Fore.YELLOW), end='')
                self.status = ResultStatus.Allowed
                return
        if response.status_code == 503:
            if re.match(r'.*<!-- ERR_DNS_FAIL -->.*', one_line_content):
                print(colorize(f'ERR_DNS_FAIL ', Fore.YELLOW), end='')
                self.status = ResultStatus.DnsError
                return
            if re.match(r'.*<!-- ERR_CONNECT_FAIL -->.*', one_line_content):
                print(colorize(f'ERR_CONNECT_FAIL ', Fore.YELLOW), end='')
                self.status = ResultStatus.ConnectError
                return
            if re.match(r'.*<h1>page web bloquée</h1>.*', one_line_content.lower()):
                blocked_category: str | None = None
                blocked_url: str | None = None
                if matches := re.match(r'.*<p><b>url:</b>(.+)</p>\s*<p><b>category:</b>(.+)</p>.*', one_line_content.lower()):
                    blocked_url = matches.group(1).strip()
                    blocked_category = matches.group(2).strip()
                print(colorize(f'URL {blocked_url} blocked for category {blocked_category} ', Fore.YELLOW), end='')
                self.status = ResultStatus.Denied
                return
            else:
                print(colorize(f'[<h1>page web bloquée</h1> not found] one_line_content={one_line_content}', Fore.BLUE))
            for line in decoded_lines:
                match: bool = False
                if re.match(r'.*<h1>page web bloquée</h1>.*', line.lower()):
                    match = True
                if re.match(r'.*<b>category:\s*</b>.*', line.lower()):
                    match = True
                if re.match(r'.*<b>url:\s*</b>.*', line.lower()):
                    match = True
                print(colorize(line[:256], Fore.BLUE if match else Fore.YELLOW))
            self.status = ResultStatus.Denied
            return
        if response.status_code == 202:  # Stormshield
            title_https_web_site_blocked: int = False
            for line in decoded_lines:
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
                for line in decoded_lines:
                    print(colorize(line[:256], Fore.YELLOW))
                self.status = ResultStatus.Denied
                return
            print(colorize('No blocking pattern found ', Fore.YELLOW), end='')
            for line in decoded_lines:
                print(colorize(line[:256], Fore.YELLOW))
            self.status = ResultStatus.Allowed
            return
        if response.status_code == 200:
            for line in decoded_lines:
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

    def set_compliant(self, compliant: bool):
        self.compliant = compliant


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
                item_percent = 100 * item // items
                if item > 10:
                    average_time = (time.time() - start) / item
                    estimated_time = math.ceil((items - item) * average_time)
                    eta = f'{estimated_time // 60:02}:{estimated_time % 60:02}'
                url = f'{scheme}://{domain}/'
                if verbose:
                    print(f'[{item_percent:02}%] [ETA: {eta}] Testing {url}... ', end='')
                self.web_results[url] = WebResult(url, web)
                if self.web_results[url].status not in [ResultStatus.Denied]:
                    parse_result = urlparse(url)
                    if (not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parse_result.netloc)
                            and not parse_result.netloc.startswith('www.')):
                        # TEST WWW.DOMAIN
                        www_url = url.replace('://', '://www.')
                        if verbose:
                            print(f'{www_url}... ', end='')
                        self.web_results[url] = WebResult(url, web)
                match self.web_results[url].status:
                    case ResultStatus.SslError | ResultStatus.DnsError | ResultStatus.ConnectError:
                        print(colorize(f'error', Fore.YELLOW))
                        self.error_urls.append(url)
                    case ResultStatus.NotAuthenticated:
                        print(colorize(f'error', Fore.YELLOW))
                        self.error_urls.append(url)
                    case ResultStatus.Allowed:
                        self.web_results[url].set_compliant(self.policy_expected_results[domain].allowed)
                        if self.web_results[url].compliant:
                            self.compliant_urls.append(url)
                            print(colorize('OK', Fore.GREEN))
                        else:
                            self.too_permissive_urls.append(url)
                            print(colorize('too permissive', Fore.RED))
                    case ResultStatus.Denied:
                        self.web_results[url].set_compliant(not self.policy_expected_results[domain].allowed)
                        if self.web_results[url].compliant:
                            self.compliant_urls.append(url)
                            print(colorize('OK', Fore.GREEN))
                        else:
                            self.too_strict_urls.append(url)
                            print(colorize('too strict', Fore.RED))
                item += 1

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
        print('TESTS:')
        url_width: int = 0
        control_strings: dict[str, str] = {}
        compliance_strings: dict[str, str] = {}
        policy_strings: dict[str, str] = {}
        domain_strings: dict[str, str] = {}
        category_strings: dict[str, str] = {}
        control_width = len('Control')
        compliance_width = len('Compliance')
        policy_width = len('Policy')
        domain_width = len('Domain')
        category_width = len('Category')
        for url in self.web_results:
            url_width = max(url_width, len(url))
            domain = urlparse(url).netloc
            policy_result: PolicyResult = self.policy_expected_results[domain]
            policy_strings[url] = 'allowed' if policy_result.allowed else 'denied'
            policy_width = max(policy_width, len(policy_strings[url]))
            domain_strings[url] = '-' if policy_result.matching_domain is None else policy_result.matching_domain
            domain_width = max(domain_width, len(domain_strings[url]))
            category_strings[url] = '-' if policy_result.matching_category is None else policy_result.matching_category
            category_width = max(category_width, len(category_strings[url]))
            web_result: WebResult = self.web_results[url]
            control_strings[url] = str(web_result.status)
            control_width = max(control_width, len(control_strings[url]))
            match web_result.status:
                case ResultStatus.SslError:
                    compliance_strings[url] = 'error'
                case ResultStatus.DnsError:
                    compliance_strings[url] = 'error'
                case ResultStatus.ConnectError:
                    compliance_strings[url] = 'error'
                case ResultStatus.NotAuthenticated:
                    compliance_strings[url] = 'error'
                case ResultStatus.Allowed:
                    compliance_strings[url] = 'OK' if web_result.compliant else 'too permissive'
                case ResultStatus.Denied:
                    compliance_strings[url] = 'OK' if web_result.compliant else 'too strict'
            compliance_width = max(compliance_width, len(compliance_strings[url]))
        header: str = '+-{}-+-{}-+-{}-+-{}-+-{}-+-{}-+'.format(
            '-' * url_width, '-' * category_width, '-' * domain_width, '-' * policy_width, '-' * control_width,
            '-' * compliance_width)
        print(header)
        print('| {} | {} | {} | {} | {} | {} |'.format(
            'URL'.ljust(url_width), 'Matching category'.ljust(category_width),
            'Matching domain'.ljust(domain_width), 'Policy'.ljust(policy_width),
            'Control'.ljust(control_width), 'Compliance'.ljust(compliance_width)))
        print(header)
        for url in self.web_results:
            policy_color: str
            control_color: str
            compliance_color: str
            if self.web_results[url].error:
                policy_color = ''
                control_color = Fore.YELLOW
                compliance_color = Fore.YELLOW
            elif self.web_results[url].compliant:
                policy_color = ''
                control_color = ''
                compliance_color = Fore.GREEN
            else:
                policy_color = Fore.RED
                control_color = Fore.RED
                compliance_color = Fore.RED
            print('| {} | {} | {} | {} | {} | {} |'.format(
                url.ljust(url_width), category_strings[url].ljust(category_width),
                domain_strings[url].ljust(domain_width),
                colorize(policy_strings[url].ljust(policy_width), policy_color),
                colorize(control_strings[url].ljust(control_width), control_color),
                colorize(compliance_strings[url].ljust(compliance_width), compliance_color)
            ))
        total_nb: int = self.error_nb + self.compliant_nb + self.too_strict_nb + self.too_permissive_nb
        print(header)
        print(f'POLICY COMPLIANCE: {self.compliance_str}')
        label_width: int = 15
        number_width = 4
        header = '+-{}-+-{}-+'.format('-' * label_width, '-' * number_width)
        print(header)
        print('| {} | {: 4d} |'.format(
            'URLs tested'.ljust(label_width), total_nb))
        print(header)
        print('| {} | {: 4d} |'.format(colorize('Compliant'.ljust(label_width), Fore.GREEN), self.compliant_nb))
        print('| {} | {: 4d} |'.format(colorize('Too permissive'.ljust(label_width), Fore.RED), self.too_permissive_nb))
        print('| {} | {: 4d} |'.format(colorize('Too strict'.ljust(label_width), Fore.RED), self.too_strict_nb))
        print('| {} | {: 4d} |'.format(colorize('Error'.ljust(label_width), Fore.YELLOW), self.error_nb))
        print(header)
        date: str = datetime.now().strftime("%Y%m%d")
        html_file: Path = Path(
            f'ac_rennes_eple_filter-{VERSION}-{self.profile.upper()}-{self.public_ip}-{date}-{ProxyConfig().type}.html')
        HTMLRenderer().render(
            'report.html',
            {
                'controller': self,
                'proxy_config': ProxyConfig(),
            },
            html_file)
