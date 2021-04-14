#!/usr/bin/env python3

from WellKnownHandler import WellKnownHandler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT

from flask import Flask, request, Response
from flask_swagger_ui import get_swaggerui_blueprint
from werkzeug.datastructures import Headers
from random import choice
from string import ascii_lowercase
from requests import get, post, put, delete
import json

from config import get_config, get_verb_config, get_default_resources
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from handlers.oidc_handler import OIDCHandler
from handlers.uma_handler import UMA_Handler, resource
from handlers.uma_handler import rpt as class_rpt
from handlers.mongo_handler import Mongo_Handler
from handlers.policy_handler import policy_handler
import blueprints.resources as resources
import blueprints.proxy as proxy
import os
import sys
import traceback
import threading

from jwkest.jws import JWS
from jwkest.jwk import RSAKey, import_rsa_key_from_file, load_jwks_from_url, import_rsa_key
from jwkest.jwk import load_jwks
from Crypto.PublicKey import RSA
import logging
from handlers.log_handler import LogHandler

log_handler = LogHandler
log_handler.load_config("PEP", "./config/log_config.yaml")
logger = logging.getLogger("PEP_ENGINE")

logger.info("==========Starting load config==========")
### INITIAL SETUP
g_config, g_wkh = get_config("config/config.json")
#Load HTTP verb mapping
g_config = get_verb_config("config/verb_config.json", g_config)

oidc_client = OIDCHandler(g_wkh,
                            client_id = g_config["client_id"],
                            client_secret = g_config["client_secret"],
                            redirect_uri = "",
                            scopes = ['openid', 'uma_protection', 'permission'],
                            verify_ssl = g_config["check_ssl_certs"])

uma_handler = UMA_Handler(g_wkh, oidc_client, g_config["check_ssl_certs"])
uma_handler.status()

#Default behavior is open_access
#Creation of default resources
try:
    path = g_config["default_resource_path"]
    kube_resources= get_default_resources(path)
    for k in kube_resources['default_resources']:
        id_res=""
        if "description" in k and "default_owner" in k:
            id_res=uma_handler.create(k["name"], [k["scopes"]], k["description"], k["default_owner"], k["resource_uri"])
        elif "default_owner" in k:
            id_res=uma_handler.create(k["name"], [k["scopes"]], "Default description", k["default_owner"], k["resource_uri"])
        else:
            id_res=uma_handler.create(k["name"], [k["scopes"]], "Default description", "0000000000000", k["resource_uri"])
        logger.info("==========New Resource for path: \""+k["resource_uri"]+"\" with ID: \""+id_res+"\"==========")
    logger.info("==========Default resources inserted in DB==========")
        
except Exception as e:
    
    logger.info("==========Couldnt process the default resources==========")
    logger.info("==========Reason: "+str(e)+"==========")


#PDP Policy Handler
pdp_policy_handler = policy_handler(pdp_url=g_config["pdp_url"], pdp_port=g_config["pdp_port"], pdp_policy_endpoint=g_config["pdp_policy_endpoint"])

def generateRSAKeyPair():
    _rsakey = RSA.generate(2048)
    private_key = _rsakey.exportKey()
    public_key = _rsakey.publickey().exportKey()

    file_out = open("config/private.pem", "wb+")
    file_out.write(private_key)
    file_out.close()

    file_out = open("config/public.pem", "wb+")
    file_out.write(public_key)
    file_out.close()

    return private_key

private_key = generateRSAKeyPair()
logger.info("==========Configuration loaded==========")

proxy_app = Flask(__name__)
proxy_app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

resources_app = Flask(__name__)
resources_app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# SWAGGER initiation
SWAGGER_URL = '/swagger-ui'  # URL for exposing Swagger UI (without trailing '/')
API_URL = "" # Our local swagger resource for PEP. Not used here as 'spec' parameter is used in config
SWAGGER_SPEC_PROXY = json.load(open("./static/swagger_pep_proxy_ui.json"))
SWAGGER_SPEC_RESOURCES = json.load(open("./static/swagger_pep_resources_ui.json"))
SWAGGER_APP_NAME = "Policy Enforcement Point Interfaces"

swaggerui_proxy_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': SWAGGER_APP_NAME,
        'spec': SWAGGER_SPEC_PROXY
    },
)

swaggerui_resources_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': SWAGGER_APP_NAME,
        'spec': SWAGGER_SPEC_RESOURCES
    },
)

# Register api blueprints (module endpoints)
resources_app.register_blueprint(resources.construct_blueprint(oidc_client, uma_handler, pdp_policy_handler, g_config))
proxy_app.register_blueprint(proxy.construct_blueprint(oidc_client, uma_handler, g_config, private_key))
logger.info("==========Resources endpoint Loaded==========")

# SWAGGER UI respective bindings
resources_app.register_blueprint(swaggerui_resources_blueprint)
proxy_app.register_blueprint(swaggerui_proxy_blueprint)
logger.info("==========Proxy endpoint Loaded==========")
logger.info("==========Startup complete. PEP Engine is available!==========")

# Define run methods for both Flask instances
# Start reverse proxy for proxy endpoint
def run_proxy_app():
    proxy_app.run(
        debug=False,
        threaded=True,
        port=int(g_config["proxy_service_port"]),
        host=g_config["service_host"]
    )

# Start reverse proxy for resources endpoint
def run_resources_app():
    resources_app.run(
        debug=False,
        threaded=True,
        port=int(g_config["resources_service_port"]),
        host=g_config["service_host"]
    )

if __name__ == '__main__':
    # Executing the Threads seperatly.
    proxy_thread = threading.Thread(target=run_proxy_app)
    resource_thread = threading.Thread(target=run_resources_app)
    proxy_thread.start()
    resource_thread.start()
