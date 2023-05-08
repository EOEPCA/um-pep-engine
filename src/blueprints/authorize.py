import logging

from flask import Blueprint, request, Response
from handlers.log_handler import LogHandler
from handlers.mongo_handler import Mongo_Handler


def construct_blueprint(oidc_client, uma_handler, g_config):
    authorize_bp = Blueprint('authorize_bp', __name__)
    logger = logging.getLogger("PEP_ENGINE")
    log_handler = LogHandler.get_instance()

    @authorize_bp.route("/authorize", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"])
    def resource_request():
        logger.debug("Processing authorization request...")
        response = Response()

        # process headers
        rpt = request.headers.get('Authorization')
        if "X-Original-Uri" in request.headers:
            path = request.headers.get('X-Original-Uri')
        else:
            path = ""
        if "X-Original-Method" in request.headers:
            http_method = request.headers.get('X-Original-Method')
        else:
            # Defaults to GET method if X-Original-Method is not sent
            http_method = "GET"

        # Get resource
        # TODO we might not need mongodb if keycloak supports open resources
        custom_mongo = Mongo_Handler("resource_db", "resources")
        resource_id = custom_mongo.get_id_from_uri(path)
        resource = custom_mongo.get_from_mongo("resource_id", resource_id)
        if resource and "scopes" in resource and 'open' in resource.get('scopes'):
            log(2103, request.method, {"Resource": resource_id, "Description": "Scope is open"})
            response.status_code = 200
            return response

        scopes = None
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
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
        except Exception as e:
            logger.debug("Error while getting uid: " + str(e))

        # If UUID exists and resource requested has same UUID

        if rpt:
            logger.debug("Token found: " + rpt)
            rpt = rpt.replace("Bearer ", "").strip()

            # Validate for a specific resource for any other HTTP method call
            s_margin_rpt_valid = int(g_config["s_margin_rpt_valid"])
            rpt_limit_uses = int(g_config["rpt_limit_uses"])
            verify_signature = int(g_config["verify_signature"])
            if (not g_config["api_rpt_uma_validation"] or
                uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": ["public_access"]}],
                                         s_margin_rpt_valid, rpt_limit_uses, verify_signature) or
                uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": ["Authenticated"]}],
                                         s_margin_rpt_valid, rpt_limit_uses, verify_signature) or
                uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": scopes}],
                                         s_margin_rpt_valid, rpt_limit_uses, verify_signature)):
                logger.debug("RPT valid, accessing ")
                # RPT validated, allow nginx to redirect request to Resource Server
                log(2103, request.method, {"User": uid, "Resource": resource_id, "Description": "Token validated"})
                response.status_code = 200
                return response
            logger.debug("Invalid RPT!, sending ticket")
            # In any other case, we have an invalid RPT, so send a ticket.
            # Fallthrough intentional

        logger.debug("No auth token, or auth token is invalid")
        if resource_id is None:
            logger.debug("No matched resource, forward to Resource Server.")
            # In this case, the PEP doesn't have that resource handled, so it replies a 200 so the request is forwarded to the Resource Server
            response.status_code = 200
            log(2105, request.method, {"User": uid, "Description": "No resource found, forwarding to Resource Server."})
            return response

        try:
            logger.debug("Matched resource: " + str(resource_id))
            # Generate ticket if token is not present
            for s in [scopes, ["Authenticated"], ["public_access"]]:
                try:
                    ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": s}])
                    response.headers["WWW-Authenticate"] = "UMA realm=" \
                                                           + g_config["realm"] + ",as_uri=" \
                                                           + g_config["auth_server_url"] + ",ticket=" + ticket
                    response.status_code = 401  # Answer with "Unauthorized" as per the standard spec.
                    log(2104, request.method, {"Ticket": ticket,
                                               "Description": "Invalid token, generating ticket for resource:" + resource_id})
                    return response
                except Exception as e:
                    pass  # Resource is not registered with current scope
            # Resource is not registered with any known scope, throw generalized exception
            raise Exception("An error occurred while requesting permission for a resource: 500: no valid scopes "
                            "found for specified resource")
        except Exception as e:
            response.status_code = int(str(e).split(":")[1].strip())
            response.headers["Error"] = str(e)
            log(2104, request.method, {"Ticket": None, "Error": str(e)})
            return response

    def log(code, http_method, activity):
        logger.info(log_handler.format_message(subcomponent="AUTHORIZE", action_id="HTTP",
                                               action_type=http_method, log_code=code,
                                               activity=activity))

    return authorize_bp
