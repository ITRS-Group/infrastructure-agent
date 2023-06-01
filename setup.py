"""
Infrastructure Agent: Setup configuration
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

import os
import sys

TOX = 'TOX_WORK_DIR' in os.environ
SCRIPT_DIR = os.path.dirname(__file__)

if TOX:
    from distutils.core import setup
else:
    from cx_Freeze import Executable, setup

try:
    with open(os.path.join(SCRIPT_DIR, 'VERSION'), 'r') as f_in:
        VERSION = f_in.read().strip()
except FileNotFoundError:
    VERSION = '0.0.0'  # Probably from `make test` or similar

EXECUTABLE_CONFIG = {
    "copyright": "Copyright 2023 ITRS Group Ltd.",
    "icon": "icon.ico"
}

build_exe_options = {
    'excludes': ['asyncio', 'unittest', 'tkinter', 'test', 'mock'],
}

if TOX:
    executables = []
elif sys.platform.startswith('win32'):
    executables = [
        # Service Executable
        Executable(script="win_svce_config.py", target_name="infra-svce.exe", base="Win32Service", **EXECUTABLE_CONFIG),
        # Main Executable
        Executable(script="main.py", target_name="infra-agent.exe", **EXECUTABLE_CONFIG)
    ]
    build_exe_options = build_exe_options | {
        "include_files": ["icon.ico"],
        "includes": ["cx_Logging", "win_svce_handler"],
        "include_msvcr": True
    }
else:
    executables = [
        Executable(script='main.py', target_name="infrastructure-agent", base='Console', **EXECUTABLE_CONFIG)
    ]

setup(
    name='infrastructure-agent',
    version=VERSION,
    description="Infrastructure Agent",
    author="ITRS Group Ltd",
    author_email="support@itrsgroup.com",
    url="https://itrsgroup.com/",
    options={'build_exe': build_exe_options},
    executables=executables,
    tests_require=[
        'coverage',
        'flake8',
        'pytest',
        'pytest-cov',
        'pytest-mock',
    ],
)
