"""
Infrastructure Agent: Sets up logger for other modules to use.
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
import logging.config
from typing import TYPE_CHECKING

from agent.config import ConfigurationError
from agent.helpers import merge_dictionary

if TYPE_CHECKING:
    from typing import Any

logger: logging.Logger = None

# Base logging config dictionary in the following format
# https://docs.python.org/3/library/logging.config.html#logging-config-dictschema
# This is built upon in init_logging() to build a full default logging configuration
# based on the handlers requested in the users configuration file.
# This is done to avoid wasting time/potentially failing setting up logging handlers
# that the customer hasn't requested.
BASE_LOGGING_CONFIG_DICT = {
    'version': 1,
    'disable_existing_loggers': True,
    'loggers': {},
    'handlers': {
        'console': {
            'formatter': 'time_formatter',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout'
        },
    },
    'formatters': {
        'time_formatter': {
            'class': 'logging.Formatter',
            'format': '%(asctime)s %(name)s : [%(levelname)s] %(message)s'
        },
        'default_formatter': {
            'class': 'logging.Formatter',
            'format': '%(name)s : [%(levelname)s] %(message)s'
        }
    }
}

# Names of the loggers to be created. These map to directories/files under src/
PROJECT_LOGGERS = ('main', 'agent', 'cache', 'nrpe')

# Default configuration for loggers under BASE_LOGGING_CONFIG_DICT.loggers
BASE_LOGGER_CONFIG = {
    'level': 'INFO',
    'handlers': ['console'],
    'propagate': False,
}

# Default configuration for the loggers handlers.
HANDLERS = {
    'file': {
        'class': 'logging.handlers.RotatingFileHandler',
        'maxBytes': 1024 ** 2,  # 1MB
        'backupCount': 4,
        'mode': 'a',
        'filename': '',
        'formatter': 'time_formatter',
        'delay': False,
    },
    'syslog': {
        'formatter': 'default_formatter',
        'facility': 'local6',
        'class': 'logging.handlers.SysLogHandler',
        'address': '/dev/log'
    }
}


def init_logging(config: dict):
    """
    Initialises logging by:
    * Building a default logging config dictionary by combining BASE_LOGGING_CONFIG_DICT
      with the loggers needed (from PROJECT_LOGGERS) and the handlers requested (from
      config['handlers']
    * Merging the users config dictionary with this default logging dictionary
    * Passing the dictionary to logging.config.dictConfig to configure the logging module
    * Creating and setting the logger for this file (logger.py)
    """
    new_config = BASE_LOGGING_CONFIG_DICT
    requested_handlers = config.get('handlers', {}) or {}

    for handler_name in requested_handlers:
        try:
            # Populate our default config with default handler definitions based on name
            # We always use the console handler to print to stdout, but we don't always
            # want syslog or file depending on the OS
            new_config['handlers'][handler_name] = HANDLERS[handler_name]
            BASE_LOGGER_CONFIG['handlers'].append(handler_name)
        except KeyError:
            raise ConfigurationError(
                f"'{handler_name}' is an invalid logging handler (choices = {', '.join(HANDLERS.keys())})"
            )

    for logger_name in PROJECT_LOGGERS:
        new_config['loggers'][logger_name] = BASE_LOGGER_CONFIG.copy()

    merge_dictionary(new_config, config)

    logging.root.manager.loggerDict = {}
    for section in ('loggers', 'handlers', 'formatters'):
        if new_config[section] is None:
            raise ConfigurationError(f"'logging' section '{section}' is empty")

    logging.config.dictConfig(new_config)

    global logger
    logger = logging.getLogger(__name__)

    logger.info("Logging initiated.")
    logger.debug("Logger handlers: %s", logger.handlers)


def log_dict(level: int, dict_object: dict, dict_name: str):
    """Logs the content of a dictionary to the requested level"""
    logger.log(level, dict_name)

    dict_len = len(dict_object)
    for i, (k, v) in enumerate(dict_object.items()):
        prefix = '├─ ' if i + 1 != dict_len else '└─ '
        logger.log(level, "%s%s: %s", prefix, k, v)


def log_object_attr(level: int, obj: Any, object_name: str):
    """
    Logs the content of an arbitrary Python object to the requested level
    NOTE: The object must have a .__dict__ attribute for this function to work
    """
    logger.log(level, object_name)
    dir_len = len(dir(obj))
    for i, attr in enumerate(sorted(dir(obj))):
        prefix = '├─ ' if i + 1 != dir_len else '└─ '
        logger.log(level, "%s%s: %s", prefix, attr, getattr(obj, attr))
