from datetime import datetime
from pathlib import Path

import yaml
from yaml.loader import SafeLoader

from common import colorize, exit_program, VERSION
from database import Database
from colorama import Fore

from html_renderer import HTMLRenderer


class PolicyResult:
    def __init__(self, allowed: bool, matching_domain: str | None = None, matching_category: str | None = None):
        super().__init__()
        self.__allowed: bool = allowed
        self.__matching_domain: str | None = matching_domain
        self.__matching_category: str | None = matching_category

    @property
    def allowed(self) -> bool:
        return self.__allowed

    @property
    def matching_domain(self) -> str | None:
        return self.__matching_domain

    @property
    def matching_category(self) -> str | None:
        return self.__matching_category


class Rule:

    def __init__(self, category: str, description: str, auth: dict[str, bool | None], domains_number: int | None):
        self.__category: str = category
        self.__description: str = description
        self.__auth: dict[str, bool | None] = {}
        self.__printable_auth: dict[str, str] = {}
        self.__html_auth: dict[str, str] = {}
        for profile in Policy.profiles:
            self.__auth[profile] = auth[profile]
            if self.__auth[profile] is None:
                self.__printable_auth[profile] = '-'
                self.__html_auth[profile] = '<i class="bi bi-arrow-down" style="color: gray"></i>'
            elif self.__auth[profile]:
                self.__printable_auth[profile] = 'A'
                self.__html_auth[profile] = '<i class="bi bi-check-square-fill" style="color: green"></i>'
            else:
                self.__printable_auth[profile] = 'X'
                self.__html_auth[profile] = '<i class="bi bi-sign-do-not-enter-fill" style="color: red"></i>'
        self.__domains_number: int | None = domains_number

    @property
    def category(self) -> str:
        return self.__category

    @property
    def description(self) -> str:
        return self.__description

    @property
    def auth(self) -> dict[str, bool | None]:
        return self.__auth

    @property
    def html_auth(self) -> dict[str, str]:
        return self.__html_auth

    @property
    def active(self) -> bool:
        for public in Policy.profiles:
            if self.__auth[public] is not None:
                return True
        return False

    @property
    def domains_number(self) -> int | None:
        return self.__domains_number

    @property
    def matches(self) -> bool:
        return self.matching_domain is not None

    @property
    def matching_domain(self) -> str | None:
        return None

    @property
    def printable_auth(self) -> dict[str, str]:
        return self.__printable_auth

    def print(
            self, policy_results: dict[str, PolicyResult] | None, description_width: int, category_width: int):
        colors: dict[str, str | None] = {
            'rule': Fore.BLUE if self.matches else None,
        }
        for public in Policy.profiles:
            if policy_results is not None and policy_results[public].matching_category == self.category:
                colors[public] = Fore.GREEN if self.auth[public] else Fore.RED
            else:
                colors[public] = colors['rule']
        print('| {} |{} |  {}  |  {}  |  {}  | {} | {}'.format(
            colorize(self.category.ljust(category_width), colors['rule']),
            colorize('?'.rjust(8) if self.domains_number is None else f'{self.domains_number: 8d}', colors['rule']),
            colorize(self.printable_auth['clg'], colors['clg']),
            colorize(self.printable_auth['lyc'], colors['lyc']),
            colorize(self.printable_auth['per'], colors['per']),
            colorize(self.description.ljust(description_width), colors['rule']),
            colorize('MATCHED {}'.format(self.matching_domain) if self.matches else '', colors['rule'])))


class Policy:

    profiles: list[str] = ['clg', 'lyc', 'per', ]

    def __init__(self, database: Database):
        self.__database: Database = database
        self.__active_rules: list[Rule]
        self.__inactive_rules: list[Rule]
        self.__category_width: int
        self.__description_width: int
        self.__active_rules: list[Rule]
        self.__inactive_rules: list[Rule]
        self.__category_width: int
        self.__description_width: int
        print('Loading policy... ', end='')
        self.__load()
        self.__domains_number: int
        self.__categories_number: int
        self.__not_found_in_database_categories: list[str]
        self.__not_used_in_rules_categories: list[str]

    def __load(self):
        self.__active_rules = []
        self.__inactive_rules = []
        policy_config_file: Path = Path('policy.yml')
        policy_config: dict[str, list[dict[str, str | dict[str, str]]]]
        with open(policy_config_file, 'rt', encoding='utf8') as file:
            policy_config = yaml.load(file.read().encode('utf-8'), Loader=SafeLoader)
        category_domain_counts: dict[str, int] = {}
        self.__database.execute('SELECT category, COUNT(*) FROM data GROUP BY category')
        for result in self.__database.fetchall():
            category: str = result[0]
            count: int = result[1]
            category_domain_counts[category] = count
        for rule_config in policy_config['rules']:
            if 'category' not in rule_config:
                exit_program(colorize(f'Category not set for a rule in {policy_config_file}', Fore.RED))
            category = rule_config['category']
            if 'description' not in rule_config:
                exit_program(colorize(f'Description not set for category {category} in {policy_config_file}', Fore.RED))
            auth: dict[str, bool | None] = {}
            for public in Policy.profiles:
                auth[public] = None
            if 'auth' in rule_config:
                auth_config = rule_config['auth']
                all: bool | None = None
                if 'all' in auth_config:
                    if auth_config['all'].lower() == 'allow':
                        all = True
                    elif auth_config['all'].lower() == 'deny':
                        all = False
                    else:
                        exit_program(colorize(f"Invalid value for rules.x.auth.all in {policy_config_file}: "
                                     f"{auth_config['all']}", Fore.RED))
                if all is not None:
                    for public in Policy.profiles:
                        auth[public] = all
                else:
                    for public in Policy.profiles:
                        if public in auth_config:
                            if auth_config[public].lower() == 'allow':
                                auth[public] = True
                            elif auth_config[public].lower() == 'deny':
                                auth[public] = False
                            else:
                                exit_program(colorize(f"Invalid value for rules.x.auth.{public} "
                                             f"in {policy_config_file}: {auth_config[public]}", Fore.RED))
            count: int = category_domain_counts[category] if category in category_domain_counts else 0
            rule: Rule = Rule(category, rule_config['description'], auth, count)
            if rule.active:
                self.__active_rules.append(rule)
            else:
                self.__inactive_rules.append(rule)
        self.__category_width = 0
        self.__description_width = 0
        for rule in self.__active_rules + self.__inactive_rules:
            self.__category_width = max(self.__category_width, len(rule.category))
            self.__description_width = max(self.__description_width, len(rule.description))
        print(colorize(f'Loaded {len(self.__active_rules) + len(self.__inactive_rules)} rules.', Fore.GREEN))
        self.__analyze()

    def reload(self):
        print('Reloading policy... ', end='')
        self.__load()

    def __analyze(self):
        print('Analyzing the database... ', end='')
        query = 'SELECT category, COUNT(id) FROM data GROUP BY category'
        self.__database.execute(query)
        self.__domains_number = 0
        database_domains_number_by_category: dict[str, int] = {}
        self.__categories_number = 0
        for result in self.__database.fetchall():
            category = result[0]
            count = result[1]
            database_domains_number_by_category[category] = count
            self.__domains_number += count
            self.__categories_number += 1
        self.__not_found_in_database_categories: list[str] = []
        self.__not_used_in_rules_categories: list[str] = []
        if self.__domains_number:
            print(colorize(
                f'Found {self.__categories_number} categories and {self.__domains_number} domains.', Fore.GREEN))
            for rule in self.active_rules + self.inactive_rules:
                if rule.category not in database_domains_number_by_category:
                    self.__not_found_in_database_categories.append(rule.category)
                else:
                    del database_domains_number_by_category[rule.category]
            for category in database_domains_number_by_category:
                self.__not_used_in_rules_categories.append(category)
        else:
            print(colorize(f'Database is empty, please update the database', Fore.RED))

    @property
    def active_rules(self) -> list[Rule]:
        return self.__active_rules

    @property
    def inactive_rules(self) -> list[Rule]:
        return self.__inactive_rules

    @property
    def rules(self) -> list[Rule]:
        return self.__active_rules + self.__inactive_rules

    @property
    def description_width(self) -> int:
        return self.__description_width

    @property
    def category_width(self) -> int:
        return self.__category_width

    @property
    def categories_number(self) -> int:
        return self.__categories_number

    @property
    def domains_number(self) -> int:
        return self.__domains_number

    def print_rules_header(self):
        print('| {} |{} | {} | {} | {} | {} |'.format(
            'Category'.ljust(self.__category_width), '#'.rjust(8), 'clg', 'lyc', 'per',
            'Description'.ljust(self.__description_width)))

    def __print_rules_separator(self):
        print('+-{}-+{}-+-----+-----+-----+-{}-+'.format(
            '-' * self.__category_width, '-' * 8, '-' * self.__description_width))

    def print(self):
        for active in [True, False, ]:
            print('ACTIVE RULES:' if active else 'INACTIVE RULES:')
            self.__print_rules_separator()
            self.print_rules_header()
            self.__print_rules_separator()
            for rule in self.active_rules if active else self.inactive_rules:
                if rule.active == active:
                    rule.print(None, self.__description_width, self.__category_width)
            self.__print_rules_separator()
        if self.__domains_number == 0:
            print(colorize(f"No category found in the database", Fore.RED))
        else:
            if len(self.__not_found_in_database_categories):
                print(colorize(f"Warning: categories used in rules but not found in database: "
                               f"{', '.join(self.__not_found_in_database_categories)}", Fore.YELLOW))
            else:
                print(colorize(f'All the categories used in rules are found in the database.', Fore.GREEN))
            if len(self.__not_used_in_rules_categories):
                print(colorize(f"Warning: categories found in database but not used in rules: "
                               f"{', '.join(self.__not_used_in_rules_categories)}", Fore.YELLOW))
            else:
                print(colorize(f'All the categories found in the database are used in rules.', Fore.GREEN))
        date: str = datetime.now().strftime("%Y%m%d")
        html_file: Path = Path(f'ac_rennes_eple_filter-{VERSION}-policy-{date}.html')
        HTMLRenderer().render(
            'policy.html',
            {
                'policy': self,
            },
            html_file)
