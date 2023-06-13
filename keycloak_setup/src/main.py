#!/usr/bin/env python3
import base64
import logging
import os

import utils.logger as logger
from utils.configuration import load_configuration, edit_keycloak_config
from utils.keycloak_client import KeycloakClient

config_path = os.path.join(os.path.dirname(__file__), "../conf/config.ini")
keycloak_config_path = os.path.join(os.path.dirname(__file__), "../conf/keycloak.cfg")
logger.Logger.get_instance().load_configuration(os.path.join(os.path.dirname(__file__), "../conf/logging.yaml"))
logger = logging.getLogger("AUTH_PROXY_SERVER")


def register_default_resources():
    """
    Create default resources and policies associated
    """
    # TODO


def register_default_users():
    """
    Create default users
    """
    eric_id = keycloak.create_user("eric", "eric")
    print('Created Eric user: ' + eric_id)
    alice_id = keycloak.create_user("alice", "alice")
    print('Created Alice user: ' + alice_id)


def register_oauth2_proxy_client():
    proxy_server_endpoint = config.get("Keycloak", "proxy_server_endpoint")
    options = {
        'clientId': 'oauth2-proxy',
        'secret': 'secret',  # TODO changeme
        "bearerOnly": False,
        "publicClient": False,
        'baseUrl': proxy_server_endpoint,
        'redirectUris': [
            proxy_server_endpoint + '/*'
        ]
    }
    keycloak.register_client(options=options)


if __name__ == '__main__':
    config = load_configuration(config_path)
    # regenerate cookie secret
    edit_keycloak_config(keycloak_config_path, "cookie_secret", base64.urlsafe_b64encode(os.urandom(32)).decode())
    keycloak = KeycloakClient(server_url=config.get("Keycloak", "auth_server_url"),
                              realm=config.get("Keycloak", "realm"),
                              resource_server_endpoint=config.get("Keycloak", "resource_server_endpoint"),
                              username=config.get("Keycloak", "admin_username"),
                              password=config.get("Keycloak", "admin_password")
                              )
    register_oauth2_proxy_client()
    register_default_resources()
    register_default_users()
