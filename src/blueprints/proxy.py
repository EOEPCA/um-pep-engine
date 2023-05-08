import logging

from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_INTROSPECTION_ENDPOINT
from flask import Blueprint, request, Response
from handlers.log_handler import LogHandler
from handlers.mongo_handler import Mongo_Handler
from handlers.uma_handler import rpt as class_rpt
from jwkest.jwk import RSAKey, import_rsa_key
from jwkest.jws import JWS
from requests import get, post, put, delete, head, patch
from werkzeug.datastructures import Headers


def construct_blueprint(oidc_client, uma_handler, g_wkh, g_config, private_key):
    proxy_bp = Blueprint('proxy_bp', __name__)
    logger = logging.getLogger("PEP_ENGINE")
    log_handler = LogHandler.get_instance()

    @proxy_bp.route('/', defaults={'path': ''}, methods=["GET"])
    @proxy_bp.route("/<path:path>", methods=["GET"])
    def get_resource(path):
        logger.debug("Getting resource: " + path)
        response = Response()
        custom_mongo = Mongo_Handler("resource_db", "resources")
        # Get resource
        resource_id = custom_mongo.get_id_from_uri("/" + path)
        resource = custom_mongo.get_from_mongo("resource_id", resource_id)

        uid = None
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
        except Exception as e:
            logger.debug("Error while getting uid: " + str(e))

        if resource_id is None or resource is None:
            logger.debug("No matched resource, passing through to resource server to handle")
            # In this case, the PEP doesn't have that resource handled, and just redirects to it.
            try:
                endpoint_path = request.full_path
                cont = get(g_config["resource_server_endpoint"] + endpoint_path, headers=request.headers).content
                log(2105, request.method, {"User": uid, "Description": "No resource found, forwarding request for path " + path})
                return cont
            except Exception as e:
                response.status_code = 500
                log(2106, request.method, {"User": uid, "Description": "Error while redirecting to resource:" + str(e)})
                return response

        resource_scopes = None
        if "scopes" in resource:
            resource_scopes = resource.get('scopes')
        if resource_scopes and 'open' in resource_scopes:
            headers_splitted = split_headers(str(request.headers))
            new_header = Headers()
            for key, value in headers_splitted.items():
                new_header.add(key, value)
            return proxy_request(request, new_header)

        scopes = ['protected_get'] if resource_id else None
        # If UUID exists and resource requested has same UUID
        api_rpt_uma_validation = g_config["api_rpt_uma_validation"]
        rpt = request.headers.get('Authorization')
        logger.debug("Token found: " + rpt)
        rpt = rpt.replace("Bearer ", "").strip()
        # Validate for a specific resource
        s_margin_rpt_valid = int(g_config["s_margin_rpt_valid"])
        rpt_limit_uses = int(g_config["rpt_limit_uses"])
        verify_signature = g_config["verify_signature"]
        if (not api_rpt_uma_validation or
            uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": ["public_access"]}],
                                     s_margin_rpt_valid, rpt_limit_uses, verify_signature) or
            uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": ["Authenticated"]}],
                                     s_margin_rpt_valid, rpt_limit_uses, verify_signature) or
            uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": scopes}], s_margin_rpt_valid,
                                     rpt_limit_uses, verify_signature)):
            logger.debug("RPT valid, accessing ")
            rpt_splitted = rpt.split('.')
            if len(rpt_splitted) == 3:
                jwt_rpt_response = rpt
            else:
                introspection_endpoint = g_wkh.get(TYPE_UMA_V2, KEY_UMA_V2_INTROSPECTION_ENDPOINT)
                pat = oidc_client.get_new_pat()
                rpt_class = class_rpt.introspect(rpt=rpt, pat=pat, introspection_endpoint=introspection_endpoint,
                                                 secure=False)
                jwt_rpt_response = create_jwt(rpt_class, private_key)

            headers_splitted = split_headers(str(request.headers))
            headers_splitted['Authorization'] = "Bearer " + str(jwt_rpt_response)

            new_header = Headers()
            for key, value in headers_splitted.items():
                new_header.add(key, value)

            # redirect to resource
            log(2103, request.method, {"User": uid,
                                       "Resource": resource_id,
                                       "Description": "Token validated, forwarding to RM"})
            return proxy_request(request, new_header)

        logger.debug("Invalid RPT!, sending ticket")
        try:
            logger.debug("Matched resource: " + str(resource_id))
            # Generate ticket if token is not present
            for s in [scopes, ["Authenticated"], ["public_access"]]:
                try:
                    ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": s}])
                    response.headers["WWW-Authenticate"] = "UMA realm=" \
                                                           + g_config["realm"] \
                                                           + ",as_uri=" + g_config["auth_server_url"] \
                                                           + ",ticket=" + ticket
                    response.status_code = 401  # Answer with "Unauthorized" as per the standard spec.
                    log(2104, request.method, {"Ticket": ticket,
                                               "Description": "Invalid token, generating ticket for resource: "
                                                              + resource_id})
                    return response
                except Exception as e:
                    pass  # Resource is not registered with current scopes
            raise Exception(
                "An error occurred while requesting permission for a resource: 500: no valid scopes found for "
                "specified resource")
        except Exception as e:
            response.status_code = int(str(e).split(":")[1].strip())
            response.headers["Error"] = str(e)
            log(2104, request.method, {"Ticket": None, "Error": str(e)})
            return response

    @proxy_bp.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"])
    @proxy_bp.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"])
    def resource_request(path):
        # Check for token
        logger.debug("Processing path: '" + path + "'")
        response = Response()

        # Get resource
        custom_mongo = Mongo_Handler("resource_db", "resources")
        resource_id = custom_mongo.get_id_from_uri("/" + path)
        resource = custom_mongo.get_from_mongo("resource_id", resource_id)
        resource_scopes = None
        if resource and "scopes" in resource:
            resource_scopes = resource.get('scopes') if resource else None
        if resource_scopes and 'open' in resource_scopes:
            log(2103, request.method, {"Resource": resource_id, "Description": "Open resource, forwarding to RM"})
            headers_splitted = split_headers(str(request.headers))
            new_header = Headers()
            for key, value in headers_splitted.items():
                new_header.add(key, value)
            return proxy_request(request, new_header)

        scopes = None
        if resource_id:
            scopes = []
            if request.method == 'GET':
                scopes.append('protected_get')
            elif request.method == 'POST':
                scopes.append('protected_post')
            elif request.method == 'PUT':
                scopes.append('protected_put')
            elif request.method == 'DELETE':
                scopes.append('protected_delete')
            elif request.method == 'HEAD':
                scopes.append('protected_head')
            elif request.method == 'PATCH':
                scopes.append('protected_patch')

        rpt = request.headers.get('Authorization')
        if not rpt:
            response.status_code = 401
            log(2104, request.method, {"Description: Token not found"})
            return response
        logger.debug("Token found: " + rpt)
        rpt = rpt.replace("Bearer ", "").strip()

        uid = None
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
        except Exception as e:
            logger.debug("Error while getting uid: " + str(e))

        # If UUID exists and resource requested has same UUID
        api_rpt_uma_validation = g_config["api_rpt_uma_validation"]

        # Validate for a specific resource
        s_margin_rpt_valid = int(g_config["s_margin_rpt_valid"])
        rpt_limit_uses = int(g_config["rpt_limit_uses"])
        verify_signature = g_config["verify_signature"]
        if (not api_rpt_uma_validation or
            uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": ["public_access"]}],
                                     s_margin_rpt_valid, rpt_limit_uses, verify_signature) or
            uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": ["Authenticated"]}],
                                     s_margin_rpt_valid, rpt_limit_uses, verify_signature) or
            uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": scopes}], s_margin_rpt_valid,
                                     rpt_limit_uses, verify_signature)):
            logger.debug("RPT valid, accessing ")
            rpt_splitted = rpt.split('.')
            if len(rpt_splitted) == 3:
                jwt_rpt_response = rpt
            else:
                introspection_endpoint = g_wkh.get(TYPE_UMA_V2, KEY_UMA_V2_INTROSPECTION_ENDPOINT)
                pat = oidc_client.get_new_pat()
                rpt_class = class_rpt.introspect(rpt=rpt, pat=pat, introspection_endpoint=introspection_endpoint,
                                                 secure=False)
                jwt_rpt_response = create_jwt(rpt_class, private_key)

            headers_splitted = split_headers(str(request.headers))
            headers_splitted['Authorization'] = "Bearer " + str(jwt_rpt_response)

            new_header = Headers()
            for key, value in headers_splitted.items():
                new_header.add(key, value)

            # redirect to resource
            log(2103, request.method, {"User": uid,
                                       "Resource": resource_id,
                                       "Description": "Token validated, forwarding to RM"})
            return proxy_request(request, new_header)
        logger.debug("Invalid RPT!, sending ticket")
        # In any other case, we have an invalid RPT, so send a ticket.
        # Fallthrough intentional

        if resource_id is not None:
            try:
                logger.debug("Matched resource: " + str(resource_id))
                # Generate ticket if token is not present
                for s in [scopes, ["Authenticated"], ["public_access"]]:
                    try:
                        # Ticket for default protected_XXX scopes
                        ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": s}])
                        response.headers["WWW-Authenticate"] = "UMA realm=" \
                                                               + g_config["realm"] \
                                                               + ",as_uri=" + g_config["auth_server_url"] \
                                                               + ",ticket=" + ticket
                        response.status_code = 401  # Answer with "Unauthorized" as per the standard spec.
                        log(2104, request.method, {"Ticket": ticket,
                                                   "Description": "Invalid token, generating ticket for resource: "
                                                                  + resource_id})
                        return response
                    except Exception as e:
                        pass  # Resource is not registered with default scopes
                raise Exception(
                    "An error occurred while requesting permission for a resource: 500: no valid scopes found for specified resource")
            except Exception as e:
                response.status_code = int(str(e).split(":")[1].strip())
                response.headers["Error"] = str(e)
                log(2104, request.method, {"Ticket": None, "Error": str(e)})
                return response
        else:
            logger.debug("No matched resource, passing through to resource server to handle")
            # In this case, the PEP doesn't have that resource handled, and just redirects to it.
            try:
                endpoint_path = request.full_path
                cont = get(g_config["resource_server_endpoint"] + endpoint_path, headers=request.headers).content
                log(2105, request.method, {"User": uid,
                                           "Description": "No resource found, forwarding request for path " + path})
                return cont
            except Exception as e:
                response.status_code = 500
                log(2106, request.method, {"User": uid, "Description": "Error while redirecting to resource:" + str(e)})
                return response

    def proxy_request(req, new_header):
        try:
            endpoint_path = req.full_path
            if req.method == 'POST':
                res = post(g_config["resource_server_endpoint"] + endpoint_path,
                           headers=new_header,
                           data=req.data,
                           stream=False
                           )
            elif req.method == 'GET':
                res = get(g_config["resource_server_endpoint"] + endpoint_path,
                          headers=new_header,
                          stream=False
                          )
            elif req.method == 'PUT':
                res = put(g_config["resource_server_endpoint"] + endpoint_path,
                          headers=new_header,
                          data=req.data,
                          stream=False
                          )
            elif req.method == 'DELETE':
                res = delete(g_config["resource_server_endpoint"] + endpoint_path,
                             headers=new_header,
                             stream=False
                             )
            elif req.method == 'HEAD':
                res = head(g_config["resource_server_endpoint"] + endpoint_path,
                           headers=new_header,
                           stream=False
                           )
            elif req.method == 'PATCH':
                res = patch(g_config["resource_server_endpoint"] + endpoint_path,
                            headers=new_header,
                            data=req.data,
                            stream=False
                            )
            else:
                response = Response()
                response.status_code = 501
                return response
            excluded_headers = ['transfer-encoding']
            headers = [(name, value) for (name, value) in res.raw.headers.items() if
                       name.lower() not in excluded_headers]
            response = Response(res.content, res.status_code, headers)
            if "Location" in response.headers:
                response.autocorrect_location_header = False
                response.headers["Location"] = response.headers["Location"].replace(
                    g_config["resource_server_endpoint"], '')
            return response
        except Exception as e:
            response = Response()
            logger.debug("Error while redirecting to resource: " + str(e))
            response.status_code = 500
            response.content = "Error while redirecting to resource: " + str(e)
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
            field = h[0]
            value = h[1]
            d[field] = value

        return d

    def log(code, http_method, activity):
        logger.info(log_handler.format_message(subcomponent="PROXY", action_id="HTTP",
                                               action_type=http_method, log_code=code,
                                               activity=activity))

    return proxy_bp
