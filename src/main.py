#!/usr/bin/env python3

from WellKnownHandler import WellKnownHandler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT

from flask import Flask, request, Response
from werkzeug.datastructures import Headers
from random import choice
from string import ascii_lowercase
from requests import get, post, put, delete
import json

from config import load_config, save_config
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

from jwkest.jws import JWS
from jwkest.jwk import RSAKey, import_rsa_key_from_file, load_jwks_from_url, import_rsa_key
from jwkest.jwk import load_jwks
from Crypto.PublicKey import RSA
import logging
logging.getLogger().setLevel(logging.INFO)
### INITIAL SETUP

env_vars = [
"PEP_REALM",
"PEP_AUTH_SERVER_URL",
"PEP_PROXY_ENDPOINT",
"PEP_SERVICE_HOST",
"PEP_SERVICE_PORT",
"PEP_S_MARGIN_RPT_VALID",
"PEP_CHECK_SSL_CERTS",
"PEP_USE_THREADS",
"PEP_DEBUG_MODE",
"PEP_RESOURCE_SERVER_ENDPOINT",
"PEP_API_RPT_UMA_VALIDATION",
"PEP_RPT_LIMIT_USES",
"PEP_PDP_URL",
"PEP_PDP_PORT",
"PEP_PDP_POLICY_ENDPOINT",
"PEP_VERIFY_SIGNATURE"]

use_env_var = True

for env_var in env_vars:
    if env_var not in os.environ:
        use_env_var = False

g_config = {}
# Global config objects
if use_env_var is False:
    g_config = load_config("config/config.json")
else:
    for env_var in env_vars:
        env_var_config = env_var.replace('PEP_', '')

        if "true" in os.environ[env_var].replace('"', ''):
            g_config[env_var_config.lower()] = True
        elif "false" in os.environ[env_var].replace('"', ''):
            g_config[env_var_config.lower()] = False
        else:
            g_config[env_var_config.lower()] = os.environ[env_var].replace('"', '')

# Sanitize proxy endpoint config value, VERY IMPORTANT to ensure proper function of the endpoint
proxy_endpoint_reject_list = ["/", "/resources", "resources"]
if g_config["proxy_endpoint"] in proxy_endpoint_reject_list:
    raise Exception("PROXY_ENDPOINT value contains one of invalid values: " + str(proxy_endpoint_reject_list))
if g_config["proxy_endpoint"][0] is not "/":
    g_config["proxy_endpoint"] = "/" + g_config["proxy_endpoint"]
if g_config["proxy_endpoint"][-1] is "/":
    g_config["proxy_endpoint"] = g_config["proxy_endpoint"][:-1]

# Sanitize PDP "policy" endpoint config value, VERY IMPORTANT to ensure proper function of the endpoint
if g_config["pdp_policy_endpoint"][0] is not "/":
    g_config["pdp_policy_endpoint"] = "/" + g_config["pdp_policy_endpoint"]
if g_config["pdp_policy_endpoint"][-1] is not "/":
    g_config["pdp_policy_endpoint"] = g_config["pdp_policy_endpoint"] + "/"

# Global handlers
g_wkh = WellKnownHandler(g_config["auth_server_url"], secure=False)

# Global setting to validate RPTs received at endpoints
api_rpt_uma_validation = g_config["api_rpt_uma_validation"]
if api_rpt_uma_validation: print("UMA RPT validation is ON.")
else: print("UMA RPT validation is OFF.")

# Generate client dynamically if one is not configured.
if "client_id" not in g_config or "client_secret" not in g_config:
    print ("NOTICE: Client not found, generating one... ")
    scim_client = EOEPCA_Scim(g_config["auth_server_url"])
    new_client = scim_client.registerClient("PEP Dynamic Client",
                                grantTypes = ["client_credentials", "password"],
                                redirectURIs = [""],
                                logoutURI = "", 
                                responseTypes = ["code","token","id_token"],
                                scopes = ['openid', 'uma_protection', 'permission', 'profile', 'is_operator'],
                                token_endpoint_auth_method = ENDPOINT_AUTH_CLIENT_POST)
    print("NEW CLIENT created with ID '"+new_client["client_id"]+"', since no client config was found on config.json or environment")

    g_config["client_id"] = new_client["client_id"]
    g_config["client_secret"] = new_client["client_secret"]
    if use_env_var is False:
        save_config("config/config.json", g_config)
    else:
        os.environ["PEP_CLIENT_ID"] = new_client["client_id"]
        os.environ["PEP_CLIENT_SECRET"] = new_client["client_secret"]
    print("New client saved to config!")
else:
    print("Client found in config, using: "+g_config["client_id"])

save_config("config/config.json", g_config)

oidc_client = OIDCHandler(g_wkh,
                            client_id = g_config["client_id"],
                            client_secret = g_config["client_secret"],
                            redirect_uri = "",
                            scopes = ['openid', 'uma_protection', 'permission'],
                            verify_ssl = g_config["check_ssl_certs"])

uma_handler = UMA_Handler(g_wkh, oidc_client, g_config["check_ssl_certs"])
uma_handler.status()
# Demo: register a new resource if it doesn't exist
# try:
#     pass
#     #uma_handler.create("ADES", ["Authenticated"], description="", ownership_id= '55b8f51f-4634-4bb0-a1dd-070ec5869d70', icon_uri="/pep/ADES")
# except Exception as e:
#     if "already exists" in str(e):
#         print("Resource already existed, moving on")
#     else: raise e

#PDP Policy Handler
pdp_policy_handler = policy_handler(pdp_url=g_config["pdp_url"], pdp_port=g_config["pdp_port"], pdp_policy_endpoint=g_config["pdp_policy_endpoint"])

def generateRSAKeyPair():
    _rsakey = RSA.generate(2048)
    private_key = _rsakey.exportKey()
    public_key = _rsakey.publickey().exportKey()

    file_out = open("config/private.pem", "wb+")
    file_out.write(private_key)
    file_out.close()

    return private_key

private_key = generateRSAKeyPair()

app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# Register api blueprints (module endpoints)
app.register_blueprint(resources.construct_blueprint(oidc_client, uma_handler, pdp_policy_handler, g_config))
app.register_blueprint(proxy.construct_blueprint(oidc_client, uma_handler, g_config, private_key))

# Start reverse proxy for x endpoint
app.run(
    debug=g_config["debug_mode"],
    threaded=g_config["use_threads"],
    port=int(g_config["service_port"]),
    host=g_config["service_host"]
)
