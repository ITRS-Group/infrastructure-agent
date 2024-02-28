"""
Implements the Infrastructure Agent Service for Windows
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

import logging
import os
import pathlib
import psutil
import subprocess
import sys
import time

AGENT_WORKER_EXE = 'infra-agent.exe'
PROCESS_REST_SECS = 10

LOG_PATH = pathlib.Path(sys.executable).parent.resolve().joinpath("infra-svce.log")
logging.basicConfig(filename=LOG_PATH, format='%(asctime)s %(name)s : [%(levelname)s] %(message)s', level=logging.INFO)
logger = logging.getLogger()


class WinSvceHandler:

    def __init__(self) -> None:
        self._worker_process = None

    def initialize(self, *args, **kwargs):
        """Required Service method"""
        logger.info("Started logging")

    def run(self):
        """Required Service method to start the Agent (blocking)"""
        self._kill_orphan_agent()
        working_dir = os.path.dirname(sys.executable)
        try:
            while True:
                logger.info("Starting Agent worker process")
                env = os.environ.copy()
                env['PYTHONUTF8'] = "1"
                self._worker_process = subprocess.Popen([AGENT_WORKER_EXE], cwd=working_dir, env=env)
                self._worker_process.communicate()
                self._worker_process = None
                logger.error("Agent worker process ended early. Waiting for %ss before re-starting", PROCESS_REST_SECS)
                time.sleep(PROCESS_REST_SECS)
        except Exception as ex:
            self._worker_process = None
            logger.exception(ex)

    def stop(self):
        """Required Service method to stop the Agent"""
        if self._worker_process:
            logger.info("Stopping Agent worker process")
            try:
                self._worker_process.kill()
            except Exception as ex:
                logger.exception(ex)
            finally:
                self._worker_process = None

    def _kill_orphan_agent(self):
        """Remove an existing Agent process that has been orphaned"""
        for proc in psutil.process_iter():
            if proc.name() == AGENT_WORKER_EXE:
                proc.kill()
                logger.warning("Killed orphan Agent process")
                break
