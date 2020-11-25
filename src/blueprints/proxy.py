import json
from flask import Blueprint, request, Response, jsonify
from handlers.mongo_handler import Mongo_Handler
from handlers.uma_handler import UMA_Handler, resource
from handlers.uma_handler import rpt as class_rpt
from werkzeug.datastructures import Headers
from random import choice
from string import ascii_lowercase
from requests import get, post, put, delete
import json

from WellKnownHandler import WellKnownHandler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT

from jwkest.jws import JWS
from jwkest.jwk import RSAKey, import_rsa_key_from_file, load_jwks_from_url, import_rsa_key
from jwkest.jwk import load_jwks
from Crypto.PublicKey import RSA
import logging
logging.getLogger().setLevel(logging.INFO)


def construct_blueprint(oidc_client, uma_handler, g_config, private_key):
    proxy_bp = Blueprint('proxy_bp', __name__)

    @proxy_bp.route(g_config["proxy_endpoint"], defaults={'path': ''})
    @proxy_bp.route(g_config["proxy_endpoint"]+"/<path:path>", methods=["GET","POST","PUT","DELETE"])
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
            if "Location" in response.headers:
                response.autocorrect_location_header = False
                response.headers["Location"] = g_config["proxy_endpoint"] + response.headers["Location"].replace(g_config["resource_server_endpoint"], '')
            return response
        except Exception as e:
            response = Response()
            print("Error while redirecting to resource: "+ traceback.format_exc(),file=sys.stderr)
            response.status_code = 500
            response.content = "Error while redirecting to resource: "+str(e)
            return response

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
    
    return proxy_bp