#!/usr/bin/env python3
import configparser
import json
import logging
import os
import threading
from random import choice
from string import ascii_lowercase
import base64

from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint

import blueprints.proxy as proxy
from utils.configuration import load_configuration, save_configuration, edit_keycloak_config
import utils.logger as logger

from waitress import serve
from utils.keycloak_client import KeycloakClient

config_path = os.path.join(os.path.dirname(__file__), "../conf/config.ini")
keycloak_config_path = os.path.join(os.path.dirname(__file__), "../conf/keycloak.cfg")
logger.Logger.get_instance().load_configuration(os.path.join(os.path.dirname(__file__), "../conf/logging.yaml"))
logger = logging.getLogger("AUTH_PROXY_SERVER")

def start_auth_proxy_server():
    proxy_app = Flask(__name__)
    proxy_app.secret_key = ''.join(choice(ascii_lowercase) for _ in range(30))  # Random key
    proxy_app.register_blueprint(proxy.construct_blueprint(config=config, keycloak_client=keycloak))

    swagger_spec_ext_interface = json.load(open("../conf/swagger.json"))
    swaggerui_proxy_blueprint = get_swaggerui_blueprint(
        config['swagger_url'],
        config['swagger_api_url'],
        config={
            'app_name': config['swagger_app_name'],
            'spec': swagger_spec_ext_interface
        },
    )
    proxy_app.register_blueprint(swaggerui_proxy_blueprint)

    if os.environ.get('FLASK_ENV') == 'production':
        serve(
            proxy_app,
            host=config.get('Server', 'host'),
            port=int(config.get('Server', 'port')
                     )
        )
    else:
        proxy_app.run(
            debug=False,
            threaded=True,
            host=config.get('Server', 'host'),
            port=int(config.get('Server', 'port')
                     )
        )

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

if __name__ == '__main__':
    config = load_configuration(config_path)
    # regenerate cookie secret
    edit_keycloak_config(keycloak_config_path, "cookie_secret", base64.urlsafe_b64encode(os.urandom(32)).decode())
    keycloak = KeycloakClient(server_url=config.get("Keycloak", "auth_server_url"),
                              realm=config.get("Keycloak", "realm"),
                              resource_server=config.get("Keycloak", "resource_server_endpoint"),
                              username=config.get("Keycloak", "admin_username"),
                              password=config.get("Keycloak", "admin_password"),
                              init=True
                              )
    register_default_resources()
    register_default_users()
