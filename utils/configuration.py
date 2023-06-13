#!/usr/bin/env python3
import logging
import os
import re
from configparser import ConfigParser

logger = logging.getLogger("PEP")
config = ConfigParser()


def load_configuration(path: os.PathLike | str) -> ConfigParser:
    """
    Loads entire configuration into memory
    """
    conf = __load_configuration_file(path)
    # load environment variables
    for c in conf['Keycloak'].keys():
        v = os.environ.get('PEP_' + c.upper())
        if v:
            v = v.replace('"', '')
            config['Keycloak'][c] = v
    return config


def save_configuration(path: os.PathLike | str, c: ConfigParser):
    """
    Saves updated config file
    """
    with open(path, 'w') as file:
        c.write(file)


def __load_configuration_file(path: os.PathLike | str) -> ConfigParser:
    config.read(path)
    return config


def edit_keycloak_config(path: os.PathLike | str, setting, value):
    with open(path, 'r') as file:
        content = file.read()
    # Define the pattern to match the line containing the needed setting
    pattern = setting + r'="(.*)"'
    match = re.search(pattern, content)
    if match:
        # Replace the current value with the new value
        modified_content = re.sub(pattern, setting + f'="{value}"', content)
        # Write the modified content back to the file
        with open(path, 'w') as file:
            file.write(modified_content)
    else:
        print(f"Unable to find {setting} in {path} file.")
