from datetime import datetime
from pathlib import Path

from common import colorize, get_reports_dir, VERSION
from colorama import Fore

from database import Database
from html_renderer import HTMLRenderer
from policy import Policy


class PatternSearcher:

    def __init__(self, policy: Policy, database: Database, pattern: str, verbose: bool = True):
        self.__policy = policy
        self.__database = database
        self.pattern = pattern.replace('%', '').replace('/', '').lower()
        pattern_color = Fore.BLUE
        if verbose:
            print(f'Searching pattern {colorize(self.pattern, pattern_color)}...')
        query = (f"SELECT category, COUNT(domain) FROM data "
                 f"WHERE domain LIKE '%{self.pattern}%' "
                 f"GROUP BY category")
        self.__database.execute(query)
        self.matching_categories: list[str] = []
        self.domain_counts_by_category: dict[str, int] = {}
        self.domains_by_category: dict[str, list[str]] = {}
        self.domain_count: int = 0
        for count_result in self.__database.fetchall():
            category = count_result[0]
            count = count_result[1]
            self.matching_categories.append(category)
            self.domain_counts_by_category[category] = count
            self.domain_count += count
            query = (f"SELECT DISTINCT domain FROM data "
                     f"WHERE category = ? AND domain LIKE '%{self.pattern}%'")
            self.__database.execute(query, (category, ))
            self.domains_by_category[category] = [domain_result[0] for domain_result in self.__database.fetchall()]
        if verbose:
            print(f'Total domains for pattern {colorize(self.pattern, pattern_color)}: '
                  f'{colorize(str(self.domain_count), pattern_color)}')

    def domains_by_category_html(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for category in self.matching_categories:
            result[category] = ', '.join([
                    domain.replace(self.pattern, f'<span class="pattern">{self.pattern}</span>')
                    for domain in self.domains_by_category[category]
                ])
        return result

    def print(self):
        date: str = datetime.now().strftime("%Y%m%d")
        html_file: Path = (get_reports_dir() / f'search-{VERSION}-{self.pattern}-{date}.html')
        HTMLRenderer().render(
            'search.html',
            {
                'searcher': self,
            },
            html_file)
