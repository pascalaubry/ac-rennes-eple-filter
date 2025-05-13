import os
import shutil
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from PyInstaller.__main__ import run
from colorama import Fore

from common import colorize, COPYRIGHT, APP_NAME, VERSION

BUILD_DIR: Path = Path('build')
DIST_DIR: Path = Path('dist')
basename: str = f'{APP_NAME}-{VERSION}'
EXPORT_DIR: Path = Path('export')
EXPORT_DATA_DIR: Path = Path('export-data')
PROJECT_DIR: Path = EXPORT_DIR / basename
ZIP_FILE: Path = Path(str(PROJECT_DIR) + '.zip')
EXE_FILENAME = basename + '.exe'
SPEC_FILE: Path = Path(basename + '.spec')
TEST_DIR: Path = Path('test')


def clean(before_build: bool):
    os.chdir(Path(__file__).resolve().parents[0])
    dirs: list[Path] = [BUILD_DIR, DIST_DIR, ]
    if before_build:
        dirs.append(PROJECT_DIR)
    for d in dirs:
        if d.is_dir():
            print(f'Deleting folder {d}... ', end='')
            try:
                shutil.rmtree(d)
                print(colorize(f'OK', Fore.GREEN))
            except PermissionError as pe:
                print(colorize(f'{pe}', Fore.RED))
    if SPEC_FILE.is_file():
        print(f'Deleting file {SPEC_FILE}... ', end='')
        SPEC_FILE.unlink()
        print(colorize(f'OK', Fore.GREEN))
    if before_build:
        if ZIP_FILE.is_file():
            print(f'Deleting file {ZIP_FILE}... ', end='')
            ZIP_FILE.unlink()
            print(colorize(f'OK', Fore.GREEN))


def build_exe():
    os.chdir(Path(__file__).resolve().parents[0])
    pyinstaller_params = [
        '--clean',
        '--noconfirm',
        '--name=' + basename,
        '--copy-metadata',
        'ac_rennes_eple_filter',
        '--onefile',
        '--add-data=policy.yml;.',
        '--add-data=templates/base.html;templates',
        '--add-data=templates/control.html;templates',
        '--add-data=templates/control_domains.html;templates',
        '--add-data=templates/policy.html;templates',
        '--add-data=templates/check.html;templates',
        '--add-data=templates/check_rules.html;templates',
        '--add-data=templates/search.html;templates',
        '--add-data=templates/logo.css;templates',
        '--paths=.',
        '--icon=ac_rennes_eple_filter.ico',
        'ac_rennes_eple_filter.py',
    ]
    run(pyinstaller_params)


def create_project():
    os.chdir(Path(__file__).resolve().parents[0])
    if not PROJECT_DIR.exists():
        print(f'Creating folder {PROJECT_DIR}... ', end='')
        PROJECT_DIR.mkdir(parents=True)
        print(colorize(f'OK', Fore.GREEN))
    dist_exe_file: Path = DIST_DIR / EXE_FILENAME
    print(f'Moving {dist_exe_file} to {PROJECT_DIR}... ', end='')
    shutil.move(str(dist_exe_file), str(PROJECT_DIR))
    print(colorize(f'OK', Fore.GREEN))
    """
    for file in ['policy.yml', ]:
        print(f'Copying {file} to {PROJECT_DIR}... ', end='')
        shutil.copy(file, PROJECT_DIR / file)
        print(colorize(f'OK', Fore.GREEN))
    """
    for file in ['proxy.yml', ]:
        print(f'Copying {EXPORT_DATA_DIR}/{file} to {PROJECT_DIR}... ', end='')
        shutil.copy(EXPORT_DATA_DIR / file, PROJECT_DIR / file)
        print(colorize(f'OK', Fore.GREEN))
    targets: dict[str, str] = {
        'filter': '',
        'update': '--update',
        'control_clg': '--control=clg',
        'control_lyc': '--control=lyc',
        'control_per': '--control=per',
    }
    for target_id in targets:
        target_file = PROJECT_DIR / f'{target_id}.bat'
        print(f'Creating batch file {target_file}...')
        with open(target_file, 'wt') as f:
            f.write(f'@echo off\n'
                    f'echo {APP_NAME} {VERSION} - {COPYRIGHT}\n'
                    f'echo Chargement du programme, veuillez patienter...\n'
                    f'{EXE_FILENAME} {targets[target_id]}\n'
                    f'pause\n')


def create_zip():
    print(f'Creating archive {ZIP_FILE}... ', end='')
    with ZipFile(ZIP_FILE, 'w', ZIP_DEFLATED) as zip_file:
        os.chdir(PROJECT_DIR.resolve())
        for folder_name, sub_folders, file_names in os.walk('.'):
            zip_file.write(folder_name, folder_name)
        for folder_name, sub_folders, file_names in os.walk('.'):
            for filename in file_names:
                file_path: Path = Path(folder_name, filename)
                zip_file.write(file_path, file_path)
    print(colorize(f'OK', Fore.GREEN))


def build_test():
    os.chdir(Path(__file__).resolve().parents[0])
    if not TEST_DIR.is_dir():
        print(f'Creating test environment in {TEST_DIR}... ', end='')
        TEST_DIR.mkdir(parents=True)
    else:
        print(f'Updating test environment in {TEST_DIR}... ', end='')
    with ZipFile(ZIP_FILE, 'r') as zip_file:
        zip_file.extractall(TEST_DIR)
    print(colorize(f'OK', Fore.GREEN))


def main():
    clean(before_build=True)
    build_exe()
    create_project()
    create_zip()
    build_test()
    clean(before_build=False)


main()
