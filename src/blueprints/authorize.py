import json
from flask import Blueprint, request, Response, jsonify
from handlers.mongo_handler import Mongo_Handler
from handlers.uma_handler import UMA_Handler, resource
from handlers.uma_handler import rpt as class_rpt
from handlers.log_handler import LogHandler
from werkzeug.datastructures import Headers
from random import choice
from string import ascii_lowercase
from requests import get, post, put, delete, head, patch
import json

from WellKnownHandler import WellKnownHandler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT

from jwkest.jws import JWS
from jwkest.jwk import RSAKey, import_rsa_key_from_file, load_jwks_from_url, import_rsa_key
from jwkest.jwk import load_jwks
from Crypto.PublicKey import RSA
import logging

def construct_blueprint(oidc_client, uma_handler, g_config, private_key):
    authorize_bp = Blueprint('authorize_bp', __name__)
    logger = logging.getLogger("PEP_ENGINE")
    log_handler = LogHandler.get_instance()

    @authorize_bp.route("/authorize", methods=["GET","POST","PUT","DELETE","HEAD","PATCH"])
    def resource_request():
        # Check for token
        logger.debug("Processing authorization request...")
        custom_mongo = Mongo_Handler("resource_db", "resources")
        rpt = request.headers.get('Authorization')
        if "X-Original-Uri" in request.headers:
            path = request.headers.get('X-Original-Uri')
        else:
            path = ""
        if "X-Original-Method" in request.headers:
            http_method = request.headers.get('X-Original-Method')
        else:
            #Defaults to GET method if X-Original-Method is not sent
            http_method = "GET"
        # Get resource
        resource_id = custom_mongo.get_id_from_uri(path)
        scopes= None
        if resource_id:
            scopes = []
            if http_method == 'GET':
                scopes.append('protected_get')
            elif http_method == 'POST':
                scopes.append('protected_post')
            elif http_method == 'PUT':
                scopes.append('protected_put')
            elif http_method == 'DELETE':
                scopes.append('protected_delete')
            elif http_method == 'HEAD':
                scopes.append('protected_head')
            elif http_method == 'PATCH':
                scopes.append('protected_patch')
        
        uid = None
        
        #If UUID exists and resource requested has same UUID
        api_rpt_uma_validation = g_config["api_rpt_uma_validation"]
    
        response = Response()
        if rpt:
            logger.debug("Token found: "+rpt)
            rpt = rpt.replace("Bearer ","").strip()

            # Validate for a specific resource for any other HTTP method call
            if (uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": ["public_access"] }], int(g_config["s_margin_rpt_valid"]), int(g_config["rpt_limit_uses"]), g_config["verify_signature"]) or
              uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": ["Authenticated"] }], int(g_config["s_margin_rpt_valid"]), int(g_config["rpt_limit_uses"]), g_config["verify_signature"]) or
              uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": scopes }], int(g_config["s_margin_rpt_valid"]), int(g_config["rpt_limit_uses"]), g_config["verify_signature"]) or
              not api_rpt_uma_validation):
                logger.debug("RPT valid, accessing ")

                # RPT validated, allow nginx to redirect request to Resource Server
                activity = {"User":uid,"Resource":resource_id,"Description":"Token validated"}
                logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2103,activity=activity))
                response.status_code = 200
                return response
            logger.debug("Invalid RPT!, sending ticket")
            # In any other case, we have an invalid RPT, so send a ticket.
            # Fallthrough intentional
        logger.debug("No auth token, or auth token is invalid")
        if resource_id is not None:
            try:
                logger.debug("Matched resource: "+str(resource_id))
                # Generate ticket if token is not present        
                ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": scopes }])
                # Return ticket
                response.headers["WWW-Authenticate"] = "UMA realm="+g_config["realm"]+",as_uri="+g_config["auth_server_url"]+",ticket="+ticket
                response.status_code = 401 # Answer with "Unauthorized" as per the standard spec.
                activity = {"Ticket":ticket,"Description":"Invalid token, generating ticket for resource:"+resource_id}
                logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2104,activity=activity))
                return response
            except Exception as e:
                response.status_code = int(str(e).split(":")[1].strip())
                response.headers["Error"] = str(e)
                activity = {"Ticket":None,"Error":str(e)}
                logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2104,activity=activity))
                return response
        else:
            logger.debug("No matched resource, cannot handle authorization.")
            # In this case, the PEP doesn't have that resource handled, and in this partial mode it simply rejects the request with a 400 Bad Request
            response.status_code = 400
            activity = {"User":uid,"Description":"No resource found, rejecting authorization request."}
            logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2105,activity=activity))
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
    
    return authorize_bp
