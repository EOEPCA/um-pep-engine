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
import resources.resources as resources
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

app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# Register api blueprints (module endpoints)
app.register_blueprint(resources.construct_blueprint(oidc_client, uma_handler, pdp_policy_handler, g_config))

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

    return private_key, public_key

private_key, public_key = generateRSAKeyPair()

def create_jwt(payload, p_key):
    rsajwk = RSAKey(kid="RSA1", key=import_rsa_key(p_key))
    jws = JWS(payload, alg="RS256")
    return jws.sign_compact(keys=[rsajwk])

def split_headers(headers):
    headers_tmp = headers.splitlines()
    d = {}

    for h in headers_tmp:
        h = h.split(': ')
        if len(h) < 2:
            continue
        field=h[0]
        value= h[1]
        d[field] = value

    return d

def proxy_request(request, new_header):
    try:
        endpoint_path = request.full_path.replace(g_config["proxy_endpoint"], '', 1)
        if request.method == 'POST':
            res = post(g_config["resource_server_endpoint"]+endpoint_path, headers=new_header, data=request.data, stream=False)           
        elif request.method == 'GET':
            res = get(g_config["resource_server_endpoint"]+endpoint_path, headers=new_header, stream=False)
        elif request.method == 'PUT':
            res = put(g_config["resource_server_endpoint"]+endpoint_path, headers=new_header, data=request.data, stream=False)           
        elif request.method == 'DELETE':
            res = delete(g_config["resource_server_endpoint"]+endpoint_path, headers=new_header, stream=False)
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
    custom_mongo = Mongo_Handler("resource_db", "resources")
    rpt = request.headers.get('Authorization')
    # Get resource
    resource_id = custom_mongo.get_id_from_uri("/"+path)
    scopes= None
    if resource_id:
        scopes = uma_handler.get_resource_scopes(resource_id)
    
    uid = None
    
    #If UUID exists and resource requested has same UUID
   
    if rpt:
        print("Token found: "+rpt)
        rpt = rpt.replace("Bearer ","").strip()

        # Validate for a specific resource
        if uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": scopes }], int(g_config["s_margin_rpt_valid"]), int(g_config["rpt_limit_uses"]), g_config["verify_signature"]) or not api_rpt_uma_validation:
            print("RPT valid, accesing ")

            rpt_splitted = rpt.split('.')
            
            if  len(rpt_splitted) == 3:
                jwt_rpt_response = rpt
            else:
                introspection_endpoint=g_wkh.get(TYPE_UMA_V2, KEY_UMA_V2_INTROSPECTION_ENDPOINT)
                pat = oidc_client.get_new_pat()
                rpt_class = class_rpt.introspect(rpt=rpt, pat=pat, introspection_endpoint=introspection_endpoint, secure=False)
                jwt_rpt_response = create_jwt(rpt_class, private_key)
                
            headers_splitted = split_headers(str(request.headers))
            headers_splitted['Authorization'] = "Bearer "+str(jwt_rpt_response)

            new_header = Headers()
            for key, value in headers_splitted.items():
                new_header.add(key, value)

            # redirect to resource
            return proxy_request(request, new_header)
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
            #Takes the full path, which contains query parameters, and removes the proxy_endpoint at the start
            endpoint_path = request.full_path.replace(g_config["proxy_endpoint"], '', 1)
            cont = get(g_config["resource_server_endpoint"]+endpoint_path, headers=request.headers).content
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
