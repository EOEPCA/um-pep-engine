#!/usr/bin/env python3

from WellKnownHandler import WellKnownHandler

from flask import Flask, request, Response
from random import choice
from string import ascii_lowercase
from requests import get, post, put, delete
import json

from config import load_config, save_config
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from custom_oidc import OIDCHandler
from custom_uma import UMA_Handler
import os
import sys
import traceback

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
"PEP_RESOURCE_SERVER_ENDPOINT"]

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

# Global handlers
g_wkh = WellKnownHandler(g_config["auth_server_url"], secure=False)

# Generate client dynamically if one is not configured.
if "client_id" not in g_config or "client_secret" not in g_config:
    print ("NOTICE: Client not found, generating one... ")
    scim_client = EOEPCA_Scim(g_config["auth_server_url"])
    new_client = scim_client.registerClient("PEP Dynamic Client",
                                grantTypes = ["client_credentials"],
                                redirectURIs = [""],
                                logoutURI = "", 
                                responseTypes = ["code","token","id_token"],
                                scopes = ['openid', 'uma_protection', 'permission'],
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

oidc_client = OIDCHandler(g_wkh,
                            client_id = g_config["client_id"],
                            client_secret = g_config["client_secret"],
                            redirect_uri = "",
                            scopes = ['openid', 'uma_protection', 'permission'],
                            verify_ssl = g_config["check_ssl_certs"])

uma_handler = UMA_Handler(g_wkh, oidc_client, g_config["check_ssl_certs"])
uma_handler.status()
# Demo: register a new resource if it doesn't exist
try:
    uma_handler.create("ADES Service", ["Authenticated"], description="", icon_uri="/ADES")
except Exception as e:
    if "already exists" in str(e):
        print("Resource already existed, moving on")
    else: raise e

app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key


def proxy_request(request):
    try:
        if request.method == 'POST':
            res = post(g_config["resource_server_endpoint"]+"/"+request.full_path, headers=request.headers, data=request.data, stream=False)           
        elif request.method == 'GET':
            res = get(g_config["resource_server_endpoint"]+"/"+request.full_path, headers=request.headers, stream=False)
        elif request.method == 'PUT':
            res = put(g_config["resource_server_endpoint"]+"/"+request.full_path, headers=request.headers, data=request.data, stream=False)           
        elif request.method == 'DELETE':
            res = delete(g_config["resource_server_endpoint"]+"/"+request.full_path, headers=request.headers, stream=False)
        else:
            response = Response()
            response.status_code = 501
            return response
        excluded_headers = ['transfer-encoding']
        headers = [(name, value) for (name, value) in     res.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(res.content, res.status_code, headers)
        return response
    except Exception as e:
        response = Response()
        print("Error while redirecting to resource: "+ traceback.format_exc(),file=sys.stderr)
        response.status_code = 500
        response.content = "Error while redirecting to resource: "+str(e)
        return response


@app.route(g_config["proxy_endpoint"], defaults={'path': ''})
@app.route(g_config["proxy_endpoint"]+"/<path:path>", methods=["GET","POST","PUT","DELETE"])
def resource_request(path):
    # Check for token
    print("Processing path: '"+path+"'")
    rpt = request.headers.get('Authorization')
    # Get resource
    resource_id, scopes = uma_handler.resource_exists("/"+path) # TODO: Request all scopes? How can a user set custom scopes?

    if rpt:
        print("Token found: "+rpt)
        rpt = rpt.replace("Bearer ","").strip()
        # Validate for a specific resource
        if uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": scopes }], int(g_config["s_margin_rpt_valid"])):
            print("RPT valid, accesing ")
            # redirect to resource
            return proxy_request(request)
        print("Invalid RPT!, sending ticket")
        # In any other case, we have an invalid RPT, so send a ticket.
        # Fallthrough intentional
    print("No auth token, or auth token is invalid")
    response = Response()
    if resource_id is not None:
        print("Matched resource: "+str(resource_id))
        # Generate ticket if token is not present
        ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": scopes }])
        # Return ticket
        response.headers["WWW-Authenticate"] = "UMA realm="+g_config["realm"]+",as_uri="+g_config["auth_server_url"]+",ticket="+ticket
        response.status_code = 401 # Answer with "Unauthorized" as per the standard spec.
        return response
    else:
        print("No matched resource, passing through to resource server to handle")
        # In this case, the PEP doesn't have that resource handled, and just redirects to it.
        try:
            cont = get(g_config["resource_server_endpoint"]+"/"+path).content
            return cont
        except Exception as e:
            print("Error while redirecting to resource: "+str(e))
            response.status_code = 500
            return response

# Start reverse proxy for x endpoint
app.run(
    debug=g_config["debug_mode"],
    threaded=g_config["use_threads"],
    port=int(g_config["service_port"]),
    host=g_config["service_host"]
)
