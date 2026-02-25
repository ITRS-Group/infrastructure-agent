"""
Infrastructure Agent: Helper classes used by other submodules.
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

import dataclasses
from uuid import UUID


@dataclasses.dataclass
class Result:
    uuid: UUID
    rc: int
    stdout: str


@dataclasses.dataclass
class Platform:
    system: str
    architecture: str
    windows_version: tuple

    @property
    def is_windows(self) -> bool:
        return bool(self.windows_version)

    def __str__(self) -> str:
        base_str = f"{self.system} ({self.architecture})"
        if self.is_windows:
            return f"{base_str} {self.windows_version}"
        return base_str
