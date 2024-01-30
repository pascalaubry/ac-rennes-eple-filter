import re
from contextlib import suppress
from pathlib import Path

from domain_checker import DomainChecker
from common import colorize, VERSION, COPYRIGHT, get_download_cache_dir, get_reports_dir
import colorama
from colorama import Fore, Style
import argparse

from policy_controller import PolicyController
from database import Database
from policy import Policy, Rule
from pattern_searcher import PatternSearcher
from database_updater import DatabaseUpdater, RennesOrigin
from proxy import read_proxy_configs, set_proxy_config, get_proxy_config
from web_client import WebClient


class Filter:

    expected_results_file: Path = Path('ac_rennes_eple_filter_expected_results.json')

    def __init__(self, database: Database, policy: Policy, update_database_if_needed: bool = False):
        self.__database: Database = database
        self.__policy: Policy = policy
        if update_database_if_needed:
            update: bool = False
            if not self.__database.exists:
                print(colorize('Database not found, building...', Fore.YELLOW))
                update = True
            elif database.too_old:
                update = True
                print(colorize('Database is too old, updating...', Fore.RED))
            elif self.__policy.empty_database:
                print(colorize('Database is empty, updating...', Fore.RED))
                update = True
            if update:
                get_proxy_config()  # choose the proxy if not set
                self.update_database()

    def update_database(self):
        web: WebClient = WebClient()
        if DatabaseUpdater(database=self.__database, web=web).update():
            self.__policy.reload()

    def print_policy(self):
        self.__policy.print()

    def check_domain(self, url: str):
        DomainChecker(policy=self.__policy, database=self.__database, domain=url).print()

    def search_pattern(self, pattern: str):
        PatternSearcher(policy=self.__policy, database=self.__database, pattern=pattern).print()

    def control_policy(self, profile: str):
        web: WebClient = WebClient()
        PolicyController(self.__policy, self.__database, web, profile).print()

    def optimize_local_rules(self):
        for category in RennesOrigin.category_names:
            print(f'Verifying category {category}...')
            category_rule: Rule | None = None
            for rule in self.__policy.active_rules:
                if rule.category == category:
                    category_rule = rule
                    break
            if category_rule is None:
                print(f'Category {category} not find in active rules.')
                break
            useless_domain_texts: dict[str, str] = {}
            query = 'SELECT domain FROM data WHERE category = ?'
            self.__database.execute(query, (category, ))
            for result in self.__database.fetchall():
                domain = result[0]
                checker: DomainChecker = DomainChecker(
                    policy=self.__policy, database=self.__database, domain=domain, excluded_category=category,
                    verbose=False)
                useful: bool = False
                useless_texts: dict[str, str] = {}
                for public in Policy.profiles:
                    auth: bool | None = category_rule.auth[public]
                    if auth is not None:
                        result = checker.result(public)
                        if result.allowed == auth:
                            reason: str = \
                                f'domain {result.matching_domain} matches category {result.matching_category}' \
                                if result.matching_category else 'by default'
                            useless_texts[public] = f'Access already {"allowed" if auth else "denied"} ({reason})'
                        else:
                            useful = True
                            break
                if not useful:
                    domain_text: str
                    if len(set(useless_texts.values())) == 1:
                        useless_domain_texts[domain] = \
                            f'### Domain {domain} is useless: {list(useless_texts.values())[0]}'
                    else:
                        useless_domain_texts[domain] = '\n'.join([
                            f'### [{public}] Domain {domain} is useless: {list(useless_texts.values())[0]}'
                            for public, reason in useless_texts.items()
                        ])
                    print(colorize(useless_domain_texts[domain], Fore.YELLOW))
            orig_file: Path = get_download_cache_dir() / 'rennes' / (category + '.txt')
            optimized_file: Path = get_reports_dir() / (category + '-optimized.txt')
            if optimized_file.exists():
                optimized_file.unlink()
            if len(useless_domain_texts):
                print(colorize(f'{len(useless_domain_texts)} useless domains found.', Fore.YELLOW))
                print(f'Reading {orig_file}... ', end='')
                orig_lines: list[str]
                with open(orig_file) as orig:
                    orig_lines = [line.strip() for line in orig]
                print(f'Read {len(orig_lines)} lines.')
                for domain in useless_domain_texts:
                    comp = re.compile('^' + domain.replace('.', '\\.') + '(\\s+\\.*)?')
                    for i in range(len(orig_lines)):
                        if comp.match(orig_lines[i]):
                            orig_lines[i] = useless_domain_texts[domain]
                with open(optimized_file, 'w') as f:
                    f.write('\n'.join(orig_lines))
                print(colorize(f'Wrote {optimized_file}.', Fore.YELLOW))
            else:
                print(colorize(f'File {orig_file} already optimized.', Fore.GREEN))

    def interactive(self):
        try:
            while 1:
                color = Fore.LIGHTWHITE_EX
                on_color = None
                style = Style.BRIGHT
                choices: dict[str, str] = {
                    'U': f'[{colorize("U", color, on_color, style)}]pdate the database',
                    'P': f'[{colorize("P", color, on_color, style)}]rint the policy',
                }
                allow_more_actions: bool = True
                if not self.__database.exists:
                    allow_more_actions = False
                elif self.__database.too_old:
                    print(colorize('Database is too old, please update', Fore.RED))
                    allow_more_actions = False
                elif self.__policy.empty_database:
                    allow_more_actions = False
                if allow_more_actions:
                    choices['T'] = f'[{colorize("T", color, on_color, style)}]est URLs or domains'
                    choices['S'] = f'[{colorize("S", color, on_color, style)}]earch a pattern in the database'
                    choices['C'] = f'[{colorize("C", color, on_color, style)}]ontrol the policy'
                    choices['O'] = f'[{colorize("O", color, on_color, style)}]ptimize local rules'
                choices['Q'] = f'[{colorize("Q", color, on_color, style)}]uit'
                print(f'What do you want to do?')
                for accepted_choice_text in choices.values():
                    print(f'- {accepted_choice_text}')
                choice = input('Your choice: ').upper().strip()
                if choice not in choices:
                    print(colorize(f'Invalid choice [{choice}]', Fore.RED))
                elif choice == 'U':
                    self.update_database()
                elif choice == 'P':
                    self.print_policy()
                elif choice == 'T':
                    while 1:
                        url = input('Enter the URL or domain to test (Enter to cancel): ').lower().strip()
                        if url == '':
                            break
                        self.check_domain(url)
                elif choice == 'S':
                    while 1:
                        pattern = input(
                            'Enter the pattern to search (Enter to return): ').upper().strip()
                        if pattern == '':
                            break
                        self.search_pattern(pattern)
                elif choice == 'C':
                    while 1:
                        print('- [' + colorize('C', color, on_color, style) + ']LG')
                        print('- [' + colorize('L', color, on_color, style) + ']YC')
                        print('- [' + colorize('P', color, on_color, style) + ']ER')
                        print('- [' + colorize('Q', color, on_color, style) + ']uit')
                        profile: str = input('Votre choix : ').upper().strip()
                        accepted_profiles: dict[str, str] = {'C': 'clg', 'L': 'lyc', 'P': 'per', }
                        profiles: list[str]
                        if profile == 'Q':
                            break
                        if profile not in accepted_profiles:
                            print(f'Invalid profile [{profile}]')
                            continue
                        self.control_policy(accepted_profiles[profile])
                        break
                elif choice == 'O':
                    self.optimize_local_rules()
                else:  # choice == 'Q'
                    break
        except KeyboardInterrupt:
            print(f'Press Enter to continue ', end='')
            input()


def main():
    colorama.init()
    print(f'ac-rennes-eple-filter {VERSION} Copyright (c) {COPYRIGHT}')
    parser = argparse.ArgumentParser()
    parser.add_argument('--update', help='update the database', action='store_true')
    parser.add_argument('--policy', help='print the policy rules', action='store_true')
    parser.add_argument('--check', help='test URLs or domains', dest='urls', type=str)
    parser.add_argument('--search', help='search for a pattern', dest='pattern', type=str)
    parser.add_argument('--control', help='control the policy', dest='profile', type=str)
    parser.add_argument('--proxy', help='use the given proxy', dest='proxy_id', type=str)
    parser.add_argument('--optimize', help='optimize local rules', action='store_true')
    args = parser.parse_args()
    with suppress(KeyboardInterrupt):
        read_proxy_configs()  # detect errors ASAP
        if args.proxy_id:
            set_proxy_config(args.proxy_id)
        database: Database = Database()
        policy: Policy = Policy(database)
        if args.update:
            set_proxy_config(args.proxy_id)
            Filter(database, policy).update_database()
        elif args.policy:
            Filter(database, policy).print_policy()
        elif args.urls:
            filt: Filter = Filter(database, policy, update_database_if_needed=True)
            for url in args.urls.split(','):
                url = url.strip()
                if url:
                    filt.check_domain(url)
        elif args.pattern:
            Filter(database, policy, update_database_if_needed=True).search_pattern(args.pattern)
        elif args.profile:
            set_proxy_config(args.proxy_id)
            Filter(database, policy, update_database_if_needed=True).control_policy(args.profile)
        elif args.optimize:
            Filter(database, policy, update_database_if_needed=True).optimize_local_rules()
        else:
            Filter(database, policy, update_database_if_needed=True).interactive()


if __name__ == '__main__':
    main()
