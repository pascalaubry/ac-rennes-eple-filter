from datetime import datetime
from pathlib import Path

import yaml
from yaml.loader import SafeLoader

from common import colorize, exit_program, VERSION, get_reports_dir
from database import Database
from colorama import Fore

from html_renderer import HTMLRenderer


class PolicyResult:

    def __init__(self, allowed: bool, matching_domain: str | None = None, matching_category: str | None = None):
        super().__init__()
        self.allowed: bool = allowed
        self.matching_domain: str | None = matching_domain
        self.matching_category: str | None = matching_category


class Rule:

    def __init__(self, category: str, description: str, auth: dict[str, bool | None], domains_number: int | None):
        self.category: str = category
        self.description: str = description
        self.auth: dict[str, bool | None] = {}
        self.printable_auth: dict[str, str] = {}
        self.html_auth: dict[str, str] = {}
        for profile in Policy.profiles:
            self.auth[profile] = auth[profile]
            if self.auth[profile] is None:
                self.printable_auth[profile] = '-'
                self.html_auth[profile] = '<i class="bi bi-arrow-down access"></i>'
            elif self.auth[profile]:
                self.printable_auth[profile] = 'A'
                self.html_auth[profile] = '<i class="bi bi-check-square-fill access-allowed"></i>'
            else:
                self.printable_auth[profile] = 'X'
                self.html_auth[profile] = '<i class="bi bi-sign-do-not-enter-fill access-denied"></i>'
        self.domains_number: int | None = domains_number
        self.matching_domain: str | None = None

    @property
    def active(self) -> bool:
        for public in Policy.profiles:
            if self.auth[public] is not None:
                return True
        return False

    @property
    def matches(self) -> bool:
        return self.matching_domain is not None


class Policy:

    profiles: list[str] = ['clg', 'lyc', 'per', ]

    def __init__(self, database: Database):
        self.__database: Database = database
        self.active_rules: list[Rule] = []
        self.inactive_rules: list[Rule] = []
        self.category_width: int = 0
        self.description_width: int = 0
        self.domains_number: int = 0
        self.categories_number: int = 0
        self.not_found_in_database_categories: list[str] = []
        self.not_used_in_rules_categories: list[str] = []
        print('Loading policy... ', end='')
        self.__load()

    def reload(self):
        print('Reloading policy... ', end='')
        self.__load()

    def __load(self):
        self.active_rules = []
        self.inactive_rules = []
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
                self.active_rules.append(rule)
            else:
                self.inactive_rules.append(rule)
        print(colorize(f'Loaded {len(self.active_rules) + len(self.inactive_rules)} rules.', Fore.GREEN))
        print('Analyzing the database... ', end='')
        query = 'SELECT category, COUNT(id) FROM data GROUP BY category'
        self.__database.execute(query)
        self.domains_number = 0
        database_domains_number_by_category: dict[str, int] = {}
        self.categories_number = 0
        for result in self.__database.fetchall():
            category = result[0]
            count = result[1]
            database_domains_number_by_category[category] = count
            self.domains_number += count
            self.categories_number += 1
        self.not_found_in_database_categories: list[str] = []
        self.not_used_in_rules_categories: list[str] = []
        if self.domains_number:
            print(colorize(
                f'Found {self.categories_number} categories and {self.domains_number} domains.', Fore.GREEN))
            for rule in self.rules:
                if rule.category not in database_domains_number_by_category:
                    self.not_found_in_database_categories.append(rule.category)
                else:
                    del database_domains_number_by_category[rule.category]
            for category in database_domains_number_by_category:
                self.not_used_in_rules_categories.append(category)
        else:
            print(colorize(f'Database is empty', Fore.RED))

    @property
    def rules(self) -> list[Rule]:
        return self.active_rules + self.inactive_rules

    @property
    def empty_database(self) -> bool:
        return self.domains_number == 0

    def print(self):
        html_file: Path = (get_reports_dir() / f'policy-{VERSION}.html')
        HTMLRenderer().render(
            'policy.html',
            {
                'policy': self,
            },
            html_file)
