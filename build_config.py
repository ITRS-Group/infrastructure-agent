"""
Infrastructure Agent: Default config file builder
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""
import argparse
import glob
import logging
import platform

import yaml

from agent.helpers import merge_dictionary

CONFIG_TEMPLATE_DIR = 'cfg'
DEFAULT_CONFIG_PATH = f'{CONFIG_TEMPLATE_DIR}/agent.default.yml'
DEFAULT_CONFIG_COMMENT = f'{CONFIG_TEMPLATE_DIR}/default_comment'
YAML_LINE_WIDTH = 999

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


class AliaslessDumper(yaml.SafeDumper):
    """
    Subclass of yaml.SafeDumper that overwrites ignore_aliases so that agent.default.yml
    is written out with no anchors/pointers regardless of the yamls fed in to make it.
    """
    def ignore_aliases(self, data):
        return True


def read_yaml(path: str) -> dict:
    logger.info("Reading config from '%s'", path)
    with open(path) as f:
        return yaml.safe_load(f)


def build_config_file(install_dir: str, plugin_config_dir: str):
    default_comment = read_default_comment()
    platform_config = get_base_platform_config()
    plugin_config = get_plugin_config(plugin_config_dir)

    merge_dictionary(platform_config, plugin_config)
    final_config_str = yaml.dump(platform_config, Dumper=AliaslessDumper, width=YAML_LINE_WIDTH)
    final_config_str = final_config_str.replace('{PLUGIN_DIR}', f'{install_dir}/plugins')
    with open(DEFAULT_CONFIG_PATH, 'w') as f:
        logger.info(f"Writing to '{DEFAULT_CONFIG_PATH}'")
        f.write(f'---\n{default_comment}\n{final_config_str}')


def get_plugin_config(plugin_config_dir: str) -> dict:
    config_parts = glob.glob(f'{plugin_config_dir}/*.yml')
    logger.info("Found %d plugin config part(s) in '%s'", len(config_parts), plugin_config_dir)

    plugin_config = {}
    for part in config_parts:
        logger.debug("Reading part '%s'", part)
        merge_dictionary(plugin_config, read_yaml(part))

    return plugin_config


def get_base_platform_config() -> dict:
    # Read in platform-agnostic vars
    all_vars_yaml = f'{CONFIG_TEMPLATE_DIR}/platform_vars/all.yml'
    try:
        all_vars = read_yaml(all_vars_yaml)
    except FileNotFoundError:
        logger.error("'all.yml' configuration file missing!")
        raise

    # Read in platform-specific vars (if they exist)
    platform_yaml = f'{CONFIG_TEMPLATE_DIR}/platform_vars/{platform.system().lower()}.yml'
    platform_config = {}
    try:
        platform_config = read_yaml(platform_yaml)
    except FileNotFoundError:
        logger.warning(f"Building for OS ({platform.system().lower()}) without a platform-specific config YML.")

    merge_dictionary(all_vars, platform_config)
    return all_vars


def read_default_comment() -> str:
    with open(DEFAULT_CONFIG_COMMENT, 'r') as f:
        return f.read()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--install-dir', type=str, required=True)
    parser.add_argument('-p', '--plugin-config-dir', type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()
    logger.info("Building default config file")
    build_config_file(args.install_dir, args.plugin_config_dir)
    logger.info("Done!")
