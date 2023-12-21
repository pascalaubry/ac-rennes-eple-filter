from pathlib import Path
from sqlite3 import Error
import sqlite3
import yaml
from yaml import SafeLoader
from common import exit_program, colorize
from colorama import Fore


class Database:

    def __init__(self):
        print('Initializing database... ', end='')
        self.__test: bool | None = None
        self.__config: dict[str, str | int] = {
            'file': 'ac_rennes_eple_filter.db',
        }
        config_file: str = 'database.yml'
        with open(config_file, 'rt', encoding='utf8') as file:
            file_config: dict[str, str | int] = yaml.load(file.read().encode('utf-8'), Loader=SafeLoader)
        self.__url: str
        if file_config is not None:
            if 'file' in file_config:
                self.__config['file'] = file_config['file']
        self.__url = f"sqlite://{self.__config['file']}"
        self.__db = None
        self.__cursor = None
        print(colorize('OK', Fore.GREEN))
        self.__open()

    def __open(self):
        if self.__cursor is None:
            print(f"Opening database connection {self.__url}... ", end='')
            if not Path(self.__config['file']).exists():
                print(colorize(f"{self.__config['file']} not found, file will be created ", Fore.YELLOW), end='')
            try:
                self.__db = sqlite3.connect(self.__config['file'])
                self.__cursor = self.__db.cursor()
            except Error as e:
                exit_program(colorize(f'Could not connect to {self.__url} ({e}), exiting.', Fore.RED))
            query = 'SELECT name FROM sqlite_master WHERE type = ?'
            self.execute(query, ('table', ))
            if len(self.__cursor.fetchall()) == 0:
                print('Creating tables... ', end='')
                self.execute(
                    'CREATE TABLE `data` ('
                    '`id` INTEGER PRIMARY KEY AUTOINCREMENT,'
                    '`origin` TEXT NOT NULL,'
                    '`category` TEXT NOT NULL,'
                    '`domain` TEXT NOT NULL'
                    ')')
            print(colorize('OK', Fore.GREEN))

    def close(self):
        if self.__cursor is not None:
            print(f'Closing database...', end='')
            self.__cursor.__close()
            self.__cursor = None
            self.__db = None
            print(colorize('OK', Fore.GREEN))

    def execute(self, query: str, params: tuple = ()):
        self.__open()
        self.__cursor.execute(query, params)

    def executemany(self, query: str, params: tuple = ()):
        self.__open()
        self.__cursor.executemany(query, params)

    def fetchall(self):
        return self.__cursor.fetchall()

    def fetchone(self):
        return self.__cursor.fetchone()

    def commit(self):
        self.__db.commit()
