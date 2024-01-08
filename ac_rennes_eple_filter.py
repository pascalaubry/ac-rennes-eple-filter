import re
from pathlib import Path

from domain_checker import DomainChecker
from common import colorize, exit_program, VERSION, COPYRIGHT
import colorama
from colorama import Fore, Style
import argparse

from policy_controller import PolicyController
from database import Database
from policy import Policy, Rule
from pattern_searcher import PatternSearcher
from database_updater import DatabaseUpdater, RennesOrigin
from web_client import WebClient, ProxyConfig


class Filter:

    expected_results_file: Path = Path('ac_rennes_eple_filter_expected_results.json')

    def __init__(self, database: Database, policy: Policy):
        self.__database: Database = database
        self.__policy: Policy = policy

    def update_database(self):
        web: WebClient = WebClient()
        if DatabaseUpdater(database=self.__database, web=web).update():
            self.__policy.reload()

    def print_policy(self):
        self.__policy.print()

    def test_url(self, domain: str):
        DomainChecker(policy=self.__policy, database=self.__database, domain=domain).print()

    def search_pattern(self, pattern: str):
        PatternSearcher(policy=self.__policy, database=self.__database, pattern=pattern).print()

    def control_policy(self, profile: str):
        web: WebClient = WebClient()
        PolicyController(self.__policy, self.__database, web, profile, verbose=True).print()

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
                            useless_texts[public] = (
                                f"Access already {'allowed' if auth else 'denied'} "
                                f"({f'domain {result.matching_domain} matches category {result.matching_category}' if result.matching_category else 'by default'})")
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
            orig_file: Path = Path('download') / 'rennes' / (category + '.txt')
            optimized_file: Path = Path(category + '-optimized.txt')
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
                accepted_choices: dict[str, str] = {
                    'U': '[' + colorize('U', color, on_color, style) + ']pdate the database',
                    'P': '[' + colorize('P', color, on_color, style) + ']rint the policy',
                    'T': '[' + colorize('T', color, on_color, style) + ']est URLS',
                    'S': '[' + colorize('S', color, on_color, style) + ']earch a pattern in the database',
                    'C': '[' + colorize('C', color, on_color, style) + ']ontrol the policy',
                    'O': '[' + colorize('O', color, on_color, style) + ']ptimize local rules',
                    'Q': '[' + colorize('Q', color, on_color, style) + ']uit',
                }
                for accepted_choice_text in accepted_choices.values():
                    print(accepted_choice_text)
                choice = input('Your choice: ').upper().strip()
                if choice not in accepted_choices:
                    print(f'Invalid choice [{choice}]')
                elif choice == 'U':
                    self.update_database()
                elif choice == 'P':
                    self.print_policy()
                elif choice == 'T':
                    while 1:
                        url = input('Enter the URL to test (Enter to cancel): ').lower().strip()
                        if url == '':
                            break
                        self.test_url(url)
                elif choice == 'S':
                    while 1:
                        pattern = input(
                            'Enter the pattern to search (Enter to return): ').upper().strip()
                        if pattern == '':
                            break
                        self.search_pattern(pattern)
                elif choice == 'C':
                    while 1:
                        print('[' + colorize('C', color, on_color, style) + ']LG')
                        print('[' + colorize('L', color, on_color, style) + ']YC')
                        print('[' + colorize('P', color, on_color, style) + ']ER')
                        print('[' + colorize('Q', color, on_color, style) + ']uit')
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
#        except Exception as e:
#            print(e)
#            print(colorize(str(e), Fore.RED))
#            print(f'Press Enter to continue ', end='')
#           input()


def main():
    try:
        colorama.init()
        print(f'ac-rennes-eple-filter {VERSION} Copyright (c) {COPYRIGHT}')
        parser = argparse.ArgumentParser()
        parser.add_argument('--update', help='update the database', action='store_true')
        parser.add_argument('--print', help='print the policy rules', action='store_true')
        parser.add_argument('--test', help='test a URL', dest='test_url', type=str)
        parser.add_argument('--search', help='search for a pattern', dest='pattern', type=str)
        parser.add_argument('--control', help='control the policy', dest='profile', type=str)
        parser.add_argument('--optimize', help='optimize local rules', action='store_true')
        args = parser.parse_args()
        ProxyConfig()
        database: Database = Database()
        policy: Policy = Policy(database)
        f: Filter = Filter(database, policy)
        if args.update:
            f.update_database()
        elif args.print:
            f.print_policy()
        elif args.test_url:
            for url in args.test_url.split(','):
                f.test_url(url)
        elif args.pattern:
            f.search_pattern(args.pattern)
        elif args.profile:
            f.control_policy(args.profile)
        elif args.optimize:
            f.optimize_local_rules()
        else:
            f.interactive()
    except ConnectionError as e:
        exit_program('An error occurred: {}'.format(e))


if __name__ == '__main__':
    main()
