from common import colorize
from colorama import Fore, Back

from database import Database
from policy import Policy


class PatternSearcher:

    def __init__(self, policy: Policy, database: Database, pattern: str, verbose: bool = True):
        self.__policy = policy
        self.__database = database
        self.__pattern = pattern.replace('%', '').lower()
        pattern_color = Fore.BLUE
        if verbose:
            print(f'Searching pattern {colorize(self.__pattern, pattern_color)}...')
        self.__max_domain_count_by_category = 5
        query = (f"SELECT category, COUNT(domain) FROM data "
                 f"WHERE domain LIKE '%{self.__pattern}%' "
                 f"GROUP BY category ORDER BY category")
        self.__database.execute(query)
        self.__matching_categories: list[str] = []
        self.__domain_counts_by_category: dict[str, int] = {}
        self.__domains_by_category: dict[str, list[str]] = {}
        self.__domain_count: int = 0
        for count_result in self.__database.fetchall():
            category = count_result[0]
            count = count_result[1]
            self.__matching_categories.append(category)
            self.__domain_counts_by_category[category] = count
            self.__domain_count += count
            query = (f"SELECT DISTINCT domain FROM data "
                     f"WHERE category = ? AND domain LIKE '%{self.__pattern}%' "
                     f"LIMIT {self.__max_domain_count_by_category}")
            self.__database.execute(query, (category, ))
            self.__domains_by_category[category] = [domain_result[0] for domain_result in self.__database.fetchall()]
        if verbose:
            print(f'Total domains for pattern {colorize(self.__pattern, pattern_color)}: '
                  f'{colorize(str(self.__domain_count), pattern_color)}')

    def print(self):
        pattern_color = Fore.BLUE
        print(f'Pattern searched for: {colorize(self.__pattern, pattern_color)}')
        for category in self.__matching_categories:
            category_str = colorize(category, pattern_color)
            count_str: str = colorize(str(self.__domain_counts_by_category[category]), pattern_color)
            domains_str: str = ', '.join([
                    domain.replace(self.__pattern, colorize(self.__pattern, Fore.BLACK, Back.LIGHTWHITE_EX))
                    for domain in self.__domains_by_category[category]
                ])
            if self.__domain_counts_by_category[category] > self.__max_domain_count_by_category:
                more: int = self.__domain_counts_by_category[category] - self.__max_domain_count_by_category
                domains_str += f', ... ({self.__max_domain_count_by_category} shown, {more} more)'
            print(f"Category {category_str} ({count_str}): {domains_str}")
        print(f'Total domains for pattern {colorize(self.__pattern, pattern_color)}: '
              f'{colorize(str(self.__domain_count), pattern_color)}')
