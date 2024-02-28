"""
Infrastructure Agent: Self check platform and version variables
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

import csv
import pathlib
import platform

OS_RELEASE_PATH = '/etc/os-release'
DISTRO_NAME = 'PRETTY_NAME'


def format_platform_info(agent_name: str, agent_version: str, is_windows: bool) -> str:
    """Return a formatted string of platform summary info"""
    if is_windows:
        os_version = platform.version()
        os_description = platform.win32_edition()
    else:
        os_version = platform.release()
        os_description = get_linux_distro()

    return (
        f"{agent_name} {agent_version}; hostname={platform.node()}"
        f" osname={platform.system()} osvers={os_version} desc={os_description}"
    )


def get_linux_distro() -> str:
    path = pathlib.Path(OS_RELEASE_PATH)
    with open(path) as stream:
        reader = csv.reader(stream, delimiter='=')
        os_release = dict(parts for parts in reader if len(parts) == 2)

    if DISTRO_NAME in os_release:
        return os_release[DISTRO_NAME]
    else:
        return platform.version()
