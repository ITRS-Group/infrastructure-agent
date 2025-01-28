"""
Infrastructure Agent: Main launcher/worker file
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
import os
import sys
import time
import traceback
from typing import TYPE_CHECKING

from agent.config import (
    create_default_user_config_if_required,
    get_config,
    get_startup_log_path,
)
from agent.logger import init_logging
from config_importer import import_config_if_required
from returncodes import (
    RETURN_CODE_OK,
    RETURN_CODE_CONFIG_ERROR,
    RETURN_CODE_ERROR,
)

if TYPE_CHECKING:
    from agent.agent import Agent
    from agent.config import AgentConfig


logger: logging.Logger = None
infrastructure_agent: Agent = None

STARTUP_LOG_FILE = get_startup_log_path()


def start_agent(config: AgentConfig) -> int:
    """Blocking function to start the Agent"""
    global infrastructure_agent

    from agent.agent import Agent
    from agent.cachemanager import CacheManager

    if infrastructure_agent:
        stop_agent()  # Ensure we're stopped
        time.sleep(1)
    logger.info("Starting the Agent")
    cache_manager = CacheManager(config.cachemanager)
    infrastructure_agent = Agent(cache_manager, config)
    return infrastructure_agent.run()


def stop_agent():
    """Blocking function to stop the Agent"""
    global infrastructure_agent

    if infrastructure_agent:
        logger.info("Stopping the Agent")
        infrastructure_agent.stop()
        infrastructure_agent = None


def startup_log(message: str, prefix: str = "[INFO]"):
    """Writes a message to STARTUP_LOG_FILE and stderr"""
    message = f"{prefix} {message}"
    with STARTUP_LOG_FILE.open('a') as f:
        for handler in [sys.stderr, f]:
            print(message, file=handler)


def config_error(message: str):
    """Writes an error to STARTUP_LOG_FILE and stderr and then exits"""
    startup_log(message, "[ERROR]")
    sys.exit(RETURN_CODE_CONFIG_ERROR)


def main():
    """Main entry point for the Infrastructure Agent"""
    global logger

    try:
        os.remove(STARTUP_LOG_FILE)
    except FileNotFoundError:
        pass

    startup_log("Starting Infrastructure Agent")
    startup_log(f"Running with Python version '{sys.version.split()[0]}', encoding '{sys.getfilesystemencoding()}'")

    try:
        if create_default_user_config_if_required():
            startup_log("Created default user config file")
    except Exception as ex:
        config_error(f"Error creating default user config file: {ex}")

    # read the configuration
    try:
        startup_log("Reading configuration file(s)")
        config = get_config(logger=startup_log)
    except Exception as ex:
        config_error(f"Configuration error: {ex}")

    # initialise logging
    try:
        startup_log("Initialising logger from config")
        init_logging(config.logging)
        logger = logging.getLogger('main')
        startup_log("Logger successfully initiated")
    except Exception as ex:
        config_error(f"Logging configuration error: {ex}")

    # attempt to read in previous config
    try:
        startup_log("Checking for previous config import")
        if import_config_if_required(config):
            config = get_config(logger=startup_log)  # Config has changed, so read it in again
    except Exception as ex:
        config_error(f"Config import error: {ex}")

    # start the agent
    exitcode = RETURN_CODE_OK
    try:
        exitcode = start_agent(config)
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.error(traceback.format_exc())
        exitcode = RETURN_CODE_ERROR

    finally:
        stop_agent()
        sys.exit(exitcode)


if __name__ == '__main__':
    main()
