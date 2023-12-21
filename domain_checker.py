from common import colorize
from database import Database
from policy import Policy, Rule, PolicyResult
from colorama import Fore


class FilterRuleEval(Rule):

    def __init__(self, rule: Rule, matching_domain: str | None = None):
        super().__init__(rule.category, rule.description, rule.auth, rule.domains_number)
        self.__matching_domain: str | None = matching_domain

    @property
    def matching_domain(self) -> str | None:
        return self.__matching_domain


class DomainChecker:

    def __init__(self, policy: Policy, database: Database, domain: str, excluded_category: str = None,
                 verbose: bool = True):
        self.__policy = policy
        self.__database = database
        self.__domain = domain
        self.__rule_evals: list[FilterRuleEval] = []
        self.__results: dict[str, PolicyResult] = {}
        self.__sub_domains: list[str] = []
        parts: list[str] = domain.split('.')
        while len(parts) > 0:
            self.__sub_domains.append('.'.join(parts))
            parts.pop(0)
        # search the domains in the database
        if verbose:
            print(f'Checking domain {self.__sub_domains[0]}...')
            highlighted_domains = [colorize(domain, Fore.YELLOW) for domain in self.__sub_domains]
            print(f"Domains searched: {', '.join(highlighted_domains)}")
        query = f"SELECT domain, category FROM data WHERE domain IN ({', '.join(['?'] * len(self.__sub_domains))})"
        self.__database.execute(query, tuple(self.__sub_domains))
        results = self.__database.fetchall()
        # evaluate the rules
        for rule in self.__policy.active_rules + self.__policy.inactive_rules:
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
            self.__rule_evals.append(rule_eval)
        # set the authorizations for every public
        for public in Policy.profiles:
            for rule_eval in self.__rule_evals:
                if rule_eval.matches and rule_eval.auth[public] is not None:
                    self.__results[public] = PolicyResult(
                        rule_eval.auth[public], rule_eval.matching_domain, rule_eval.category)
                    break
            if public not in self.__results:
                self.__results[public] = PolicyResult(True)

    def print(self):
        print(f'Domain:           {self.__sub_domains[0]}')
        highlighted_domains = [colorize(domain, Fore.YELLOW) for domain in self.__sub_domains]
        print(f"Domains searched: {', '.join(highlighted_domains)}")
        for active in [True, False, ]:
            print('ACTIVE RULES:' if active else 'INACTIVE RULES:')
            self.__policy.print_rules_header()
            for rule_eval in self.__rule_evals:
                if rule_eval.active == active:
                    rule_eval.print(
                        self.__results, self.__policy.description_width, self.__policy.category_width)
        for public in Policy.profiles:
            if self.__results[public].allowed:
                result = 'allowed'
                result_color = Fore.GREEN
            else:
                result = 'denied'
                result_color = Fore.RED
            if self.__results[public].matching_category is None:
                reason = 'by default'
            else:
                reason = (f'domain {colorize(self.__results[public].matching_domain, result_color)} '
                          f'in category {colorize(self.__results[public].matching_category, result_color)}')
            print(f'Access for {public.upper()}: {colorize(result, result_color)} ({reason})')

    def result(self, public: str) -> PolicyResult:
        return self.__results[public]
