from datetime import datetime
from pathlib import Path

from common import colorize, get_reports_dir, VERSION
from database import Database
from html_renderer import HTMLRenderer
from policy import Policy, Rule, PolicyResult
from colorama import Fore
from urllib.parse import urlparse


class FilterRuleEval(Rule):

    def __init__(self, rule: Rule, matching_domain: str | None = None):
        super().__init__(rule.category, rule.description, rule.auth, rule.domains_number)
        self.matching_domain = matching_domain


class DomainChecker:

    def __init__(self, policy: Policy, database: Database, domain: str, excluded_category: str = None,
                 verbose: bool = True):
        self.__policy = policy
        self.__database = database
        self.domain = domain
        if self.domain.startswith('http'):
            self.domain = urlparse(self.domain).netloc
        self.rule_evals: list[FilterRuleEval] = []
        self.results: dict[str, PolicyResult] = {}
        self.sub_domains: list[str] = []
        parts: list[str] = self.domain.split('.')
        while len(parts) > 0:
            self.sub_domains.append('.'.join(parts))
            parts.pop(0)
        # search the domains in the database
        if verbose:
            print(f'Checking domain {self.sub_domains[0]}...')
            highlighted_domains = [colorize(domain, Fore.YELLOW) for domain in self.sub_domains]
            print(f"Domains searched: {', '.join(highlighted_domains)}")
        query = f"SELECT domain, category FROM data WHERE domain IN ({', '.join(['?'] * len(self.sub_domains))})"
        self.__database.execute(query, tuple(self.sub_domains))
        results = self.__database.fetchall()
        # evaluate the rules
        for rule in self.__policy.rules:
            rule_eval: FilterRuleEval | None = None
            for result in results:
                domain = result[0]
                category = result[1]
                if rule.category == category and category != excluded_category:
                    if verbose:
                        print(f'Found domain {colorize(domain, Fore.BLUE)} in category {colorize(category, Fore.BLUE)}')
                    rule_eval = FilterRuleEval(rule, domain)
                    break
            if rule_eval is None:
                rule_eval = FilterRuleEval(rule)
            self.rule_evals.append(rule_eval)
        # set the authorizations for every public
        for public in Policy.profiles:
            for rule_eval in self.rule_evals:
                if rule_eval.matches and rule_eval.auth[public] is not None:
                    self.results[public] = PolicyResult(
                        rule_eval.auth[public], rule_eval.matching_domain, rule_eval.category)
                    break
            if public not in self.results:
                self.results[public] = PolicyResult(True)

    @property
    def sub_domains_str(self) -> str:
        return ', '.join(self.sub_domains)

    def print(self):
        date: str = datetime.now().strftime("%Y%m%d")
        html_file: Path = (get_reports_dir() / f'check-{VERSION}-{self.domain}-{date}.html')
        HTMLRenderer().render(
            'check.html',
            {
                'checker': self,
            },
            html_file)

    def result(self, public: str) -> PolicyResult:
        return self.results[public]
