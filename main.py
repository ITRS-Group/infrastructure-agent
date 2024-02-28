"""
Infrastructure Agent: Main launcher/worker file
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
import os
import sys
import time
import traceback
from typing import TYPE_CHECKING

from agent.config import get_config, create_default_user_config_if_required
from agent.logger import init_logging
from config_importer import import_config_if_required

if TYPE_CHECKING:
    from agent.agent import Agent
    from agent.config import AgentConfig


logger: logging.Logger = None
infrastructure_agent: Agent = None

STARTUP_LOG_FILE = 'startup.log'


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


def log(message: str, prefix: str = "[INFO]"):
    """Writes a message to STARTUP_LOG_FILE and stderr"""
    message = f"{prefix} {message}"
    with open(STARTUP_LOG_FILE, 'a') as f:
        for handler in [sys.stderr, f]:
            print(message, file=handler)


def error(message: str):
    """Writes an error to STARTUP_LOG_FILE and stderr and then exits"""
    log(message, "[ERROR]")
    sys.exit(1)


def main():
    """Main entry point for the Infrastructure Agent"""
    global logger

    try:
        os.remove(STARTUP_LOG_FILE)
    except FileNotFoundError:
        pass

    log("Starting Infrastructure Agent")
    log(f"Running with encoding '{sys.getfilesystemencoding()}'")

    try:
        if create_default_user_config_if_required():
            log("Created default user config file")
    except Exception as ex:
        error(f"Error creating default user config file: {ex}")

    # read the configuration
    try:
        log("Reading configuration file(s)")
        config = get_config()
    except Exception as ex:
        error(f"Configuration error: {ex}")

    # initialise logging
    try:
        log("Initialising logger from config")
        init_logging(config.logging)
        logger = logging.getLogger('main')
        log("Logger successfully initiated")
    except Exception as ex:
        error(f"Logging configuration error: {ex}")

    # attempt to read in previous config
    try:
        log("Checking for previous config import")
        if import_config_if_required(config):
            config = get_config()  # Config has changed, so read it in again
    except Exception as ex:
        error(f"Config import error: {ex}")

    # start the agent
    exitcode = 0
    try:
        exitcode = start_agent(config)
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.error(traceback.format_exc())
        exitcode = 1

    finally:
        stop_agent()
        sys.exit(exitcode)


if __name__ == '__main__':
    main()
