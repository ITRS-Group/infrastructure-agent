#!/usr/bin/env python3
"""
Builds the version of the Agent, returning in STDOUT and optionally storing in
the 'VERSION' file.
The source for the version comes from the 'AGENT_VERSION' template file that
contains the real major and minor version and a marker for the build/commit tag.
(e.g. 1.1.$COMMIT$)
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime

SCRIPT_DIR = os.path.dirname(__file__)
VERSION_TEMPLATE_FILE = os.path.join(SCRIPT_DIR, 'AGENT_VERSION')
VERSION_FILE_PATH = os.path.join(SCRIPT_DIR, 'VERSION')
COMMIT_MARKER = '$COMMIT$'
RE_MAJOR = re.compile(r'^\d+')
SECS_PER_HOUR = 3600
TOPIC_MAJOR_BASE = 128
CMD_FETCH_GIT_COMMIT_DATE = 'git log -1 --format=%cd --date=raw'


def calc_hour_of_year(dt_value: datetime) -> int:
    start_of_year = datetime(dt_value.year, 1, 1, tzinfo=dt_value.tzinfo)
    return int((dt_value - start_of_year).total_seconds() / SECS_PER_HOUR)


def get_template() -> str:
    """Returns the Agent Version template file"""
    template = ''
    with open(VERSION_TEMPLATE_FILE, 'r') as f_in:
        for line in f_in:
            if not line.startswith('#'):
                template = line.strip()
                if template:
                    break
    if not template:
        raise Exception(f"Failed to find Agent Version template from file '{VERSION_TEMPLATE_FILE}'")
    return template


def get_commit_timestamp(directory) -> int:
    """Returns an integer UTC git commit timestamp of a specified directory"""
    command_parts = CMD_FETCH_GIT_COMMIT_DATE.split()
    try:
        result = subprocess.run(command_parts, stdout=subprocess.PIPE, cwd=directory)
        if result.returncode == 0:
            return int(result.stdout.decode('utf-8').strip().split(' ')[0])
    except (subprocess.SubprocessError, FileNotFoundError) as ex:
        print(ex, file=sys.stderr)
    return 0


def get_version(optional_dirs: list[str]) -> str:
    """Returns the overall Agent version number based on the Agent Version template file,
    which is expected to contain <major>.<minor>.$COMMIT$
    COMMIT tag is of the form: <single-digit-year 0-4><four-digit-hour-of-year>.
    TOPICS always have a major version of 128+<major>.
    """
    # Attempt to find the latest commit timestamp, or use current time as backup
    commit_timestamp = 0
    dirs = ['.']
    if optional_dirs:
        dirs += optional_dirs
    for directory in dirs:
        commit_timestamp = max(commit_timestamp, get_commit_timestamp(directory))
    if not commit_timestamp:
        commit_timestamp = int(time.time())

    commit_datetime = datetime.utcfromtimestamp(int(commit_timestamp))
    hour_of_year = calc_hour_of_year(commit_datetime)
    year_mod_5 = commit_datetime.year % 5
    commit_tag = f'{year_mod_5}{hour_of_year:04}'
    template = get_template()
    ver_str = template.replace(COMMIT_MARKER, commit_tag)
    if os.getenv('GERRIT_TOPIC'):
        def major_ver_updater(match):
            major_ver = int(match.group(0))
            return str(TOPIC_MAJOR_BASE + major_ver)
        ver_str = RE_MAJOR.sub(major_ver_updater, ver_str)
    return ver_str


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build version tag")
    parser.add_argument('-w', '--write-file', help="Write the version tag to the 'VERSION' file", action='store_true')
    parser.add_argument('-d', '--directories', nargs='*', help="Additional directories to get git commit from")
    return parser.parse_args()


if __name__ == '__main__':
    cl_args = get_args()
    version_str = get_version(cl_args.directories)
    if cl_args.write_file:
        with open(VERSION_FILE_PATH, 'w') as f_out:
            f_out.write(version_str)
    print(version_str, end='')
