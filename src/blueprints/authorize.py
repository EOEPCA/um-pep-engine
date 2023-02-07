from flask import Blueprint, request, Response
from handlers.mongo_handler import Mongo_Handler
from handlers.log_handler import LogHandler

import logging

def construct_blueprint(oidc_client, uma_handler, g_config, private_key):
    authorize_bp = Blueprint('authorize_bp', __name__)
    logger = logging.getLogger("PEP_ENGINE")
    log_handler = LogHandler.get_instance()

    @authorize_bp.route("/authorize", methods=["GET","POST","PUT","DELETE","HEAD","PATCH"])
    def resource_request():
        # Check for token
        logger.debug("Processing authorization request...")
        response = Response()
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
        resource = custom_mongo.get_from_mongo("resource_id", resource_id)
        if "scopes" in resource and 'open' in resource.get('scopes'):
            activity = {"Resource":resource_id,"Description":"Scope is open"}
            logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2103,activity=activity))
            response.status_code = 200
            return response

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
                ticket = ""
                try:
                    #Ticket for default protected_XXX scopes
                    ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": scopes }])
                    response.headers["WWW-Authenticate"] = "UMA realm="+g_config["realm"]+",as_uri="+g_config["auth_server_url"]+",ticket="+ticket
                    response.status_code = 401 # Answer with "Unauthorized" as per the standard spec.
                    activity = {"Ticket":ticket,"Description":"Invalid token, generating ticket for resource:"+resource_id}
                    logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2104,activity=activity))
                    return response
                except Exception as e:
                    pass #Resource is not registered with default scopes
                try:
                    #Try again, but with "Authenticated" scope
                    ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": ["Authenticated"] }])
                    response.headers["WWW-Authenticate"] = "UMA realm="+g_config["realm"]+",as_uri="+g_config["auth_server_url"]+",ticket="+ticket
                    response.status_code = 401 # Answer with "Unauthorized" as per the standard spec.
                    activity = {"Ticket":ticket,"Description":"Invalid token, generating ticket for resource:"+resource_id}
                    logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2104,activity=activity))
                    return response
                except Exception as e:
                    pass #Resource is not registered with "Authenticated" scope
                try:
                    #Try again, but with "public_access" scope
                    ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": ["public_access"] }])
                    response.headers["WWW-Authenticate"] = "UMA realm="+g_config["realm"]+",as_uri="+g_config["auth_server_url"]+",ticket="+ticket
                    response.status_code = 401 # Answer with "Unauthorized" as per the standard spec.
                    activity = {"Ticket":ticket,"Description":"Invalid token, generating ticket for resource:"+resource_id}
                    logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2104,activity=activity))
                    return response
                except Exception as e:
                    #Resource is not registered with any known scope, throw generalized exception
                    raise Exception("An error occurred while requesting permission for a resource: 500: no valid scopes found for specified resource")
            except Exception as e:
                response.status_code = int(str(e).split(":")[1].strip())
                response.headers["Error"] = str(e)
                activity = {"Ticket":None,"Error":str(e)}
                logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2104,activity=activity))
                return response
        else:
            logger.debug("No matched resource, forward to Resource Server.")
            # In this case, the PEP doesn't have that resource handled, so it replies a 200 so the request is forwarded to the Resource Server
            response.status_code = 200
            activity = {"User":uid,"Description":"No resource found, forwarding to Resource Server."}
            logger.info(log_handler.format_message(subcomponent="AUTHORIZE",action_id="HTTP",action_type=http_method,log_code=2105,activity=activity))
            return response
    
    return authorize_bp
