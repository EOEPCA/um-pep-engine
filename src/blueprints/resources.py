import json
import logging

from flask import Blueprint, request, Response
from handlers.log_handler import LogHandler
from handlers.mongo_handler import Mongo_Handler


def construct_blueprint(oidc_client, uma_handler, pdp_policy_handler, g_config):
    resources_bp = Blueprint('resources_bp', __name__)
    logger = logging.getLogger("PEP_ENGINE")
    log_handler = LogHandler.get_instance()
    custom_mongo = Mongo_Handler("resource_db", "resources")

    @resources_bp.route("/resources", methods=["GET", "HEAD"])
    def get_resource_list():
        logger.debug("Retrieving all registered resources...")
        response = Response()

        # get uid
        uid = None
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            is_operator = oidc_client.verify_uid_headers(headers_protected, "isOperator")
            # Above query returns a None in case of Exception, following condition asserts False for that case
            if not is_operator:
                is_operator = False
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
        except Exception as e:
            logger.debug("Error while parsing token: " + str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            log(2001, request.method, {"Description": "Error reading token: " + str(e)})
            return response

        path = request.args.get('path')
        if path:
            # get one resource
            resource = custom_mongo.get_from_mongo("reverse_match_url", str(path))
            if not resource:
                response.status_code = 404
                response.headers["Error"] = "No user-owned resources found!"
                log(2008, request.method, {"User": uid, "Description": "No matching resources found for user!"})
                return response

            validated, reason = authenticate_user_for_resource(custom_mongo, uid, is_operator, resource)
            if not validated and reason:
                response.status_code = 401
                response.headers["Error"] = reason
                log(2001, request.method, {"Description": reason})
                return response
            log(2007, request.method, {"User": uid,
                                       "Description": "Returning matched resource by path: "
                                                      + str({'_id': resource["resource_id"], '_name': resource["name"],
                                                             '_reverse_match_url': resource["reverse_match_url"]})})
            if request.method == "HEAD":
                return

            return {'_id': resource["resource_id"], '_name': resource["name"],
                    '_reverse_match_url': resource["reverse_match_url"]}

        # gets all resources registered on local DB
        resources = custom_mongo.get_all_resources()
        valid_resources = []
        for rsrc in resources:
            authenticated, reason = authenticate_user_for_resource(custom_mongo, uid, is_operator, rsrc)
            if authenticated:
                resource_id = rsrc['resource_id']
                logger.debug("Matched resource: " + resource_id)
                valid_resources.append(
                    {'_id': resource_id, '_name': rsrc["name"], '_reverse_match_url': rsrc["reverse_match_url"]})
        log(2007, request.method, {"User": uid,
                                   "Description": "Returning resource list: " + json.dumps(valid_resources)})
        if request.method == "HEAD":
            return

        return json.dumps(valid_resources)

    def authenticate_user_for_resource(mongo, uid, is_operator, resource):
        scopes = resource.get('scopes', [])
        if 'open' in scopes:
            return True, None
        if "NO TOKEN FOUND" in uid:
            return False, 'No token found'
        if not is_operator:
            return False, 'User is not an operator'
        if not mongo.verify_uid(resource['resource_id'], uid):
            return False, 'No permissions'
        return True, None

    @resources_bp.route("/resources", methods=["POST"])
    def resource_creation():
        logger.debug("Processing " + request.method + " resource request...")
        response = Response()

        data = request.get_json()

        uid = None
        # Inspect JWT token (UMA) or query OIDC userinfo endpoint (OAuth) for user id
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            logger.debug(head_protected)
            is_operator = oidc_client.verify_uid_headers(headers_protected, "isOperator")
            # Above query returns a None in case of Exception, following condition asserts False for that case
            if not is_operator:
                is_operator = False
            if is_operator and "uuid" in request.get_json():
                uid = request.get_json()["uuid"]
            else:
                uid = oidc_client.verify_uid_headers(headers_protected, "sub")
            logger.debug(uid)
            if "NO TOKEN FOUND" in uid:
                response.status_code = 401
                response.headers["Error"] = 'no token passed!'
                log(2001, request.method, {"Description": "No token found/error reading token"})
                return response
        except Exception as e:
            logger.debug("Error While passing the token: " + str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            log(2001, request.method, {"Description": "No token found/error reading token: " + str(e)})
            return response

        if not uid:
            logger.debug("UID for the user not found")
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            log(2002, request.method, {"Description": "User not found in token"})
            return response

        if is_operator or custom_mongo.verify_previous_uri_ownership(uid, data.get("icon_uri")):
            resource_reply = create_resource(uid, request, uma_handler, response)
        else:
            response.status_code = 401
            response.headers["Error"] = "Operator constraint, no authorization for given UID"
            return response
        logger.debug("Creating resource!")
        logger.debug(resource_reply)
        config = []
        # If the reply is not of type Response, the creation was successful
        # Here we register a default ownership policy to the new resource, with the PDP
        if not isinstance(resource_reply, Response):
            if "T&C" in data:
                config = data.get("T&C")
            resource_id = resource_reply["id"]
            reply_failed = False
            # If the public or authenticated scopes were used to register resource, skip policy registration
            if is_public_or_authenticated_or_open(request.get_json()):
                log(2009, request.method, {"User": uid, "Description": "Resource created", "Resource_id": resource_id,
                                           "Policy": "None, Public/Authenticated access"})
                return resource_reply
            # else, continue with ownership policies for default scopes
            failed_scope = None
            def_policy_reply = None
            for scope in g_config["default_scopes"]:
                def_policy_reply = pdp_policy_handler.create_policy(
                    policy_body=get_default_ownership_policy_body(resource_id, uid, scope, config),
                    input_headers=request.headers)
                if def_policy_reply.status_code != 200:
                    reply_failed = True
                    failed_scope = scope
                    def_policy_reply_text = def_policy_reply.text
                    break
            if not reply_failed:
                log(2009, request.method, {"User": uid, "Description": "Resource created", "Resource_id": resource_id,
                                           str(g_config[failed_scope])
                                           + " Policy": def_policy_reply.text if def_policy_reply else None})
                return resource_reply
            if def_policy_reply:
                response.status_code = def_policy_reply.status_code
            if def_policy_reply and "Error" in def_policy_reply.headers:
                response.headers["Error"] = def_policy_reply.headers["Error"]
            else:
                response.headers["Error"] = "Un-parseable error coming from server"
            logger.debug(response.headers["Error"])
            log(2010, request.method, {"User": uid,
                                       "Description": "Error occured with HTTP code "
                                                      + str(resource_reply.status_code) + ": "
                                                      + resource_reply.headers["Error"]})
            return response
        return resource_reply

    @resources_bp.route("/resources/<resource_id>", methods=["PUT", "DELETE", "HEAD", "PATCH"])
    def resource_operation(resource_id):
        logger.debug("Processing " + request.method + " resource request...")
        response = Response()
        uid = None
        # Inspect JWT token (UMA) or query OIDC userinfo endpoint (OAuth) for user id
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
            if "NO TOKEN FOUND" in uid:
                response.status_code = 401
                response.headers["Error"] = 'no token passed!'
                log(2001, request.method, {"Description": "No token found/error reading token"})
                return response
        except Exception as e:
            logger.debug("Error While passing the token: " + str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            log(2001, request.method, {"Description": "No token found/error reading token: " + str(e)})
            return response

        # If UUID does not exist
        if not uid:
            logger.debug("UID for the user not found")
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            log(2002, request.method, {"Description": "User not found in token"})
            return response

        try:
            # otherwise continue with validations
            # Is this user the resource's owner?
            is_owner = custom_mongo.verify_uid(resource_id, uid)
            # Is this user an operator?
            is_operator = oidc_client.verify_uid_headers(headers_protected, "isOperator")
            # Above query returns a None in case of Exception, following condition asserts False for that case
            if not is_operator:
                is_operator = False
        except Exception as e:
            logger.debug("Error while reading token: " + str(e))
            response.status_code = 500
            log(2001, request.method, {"Description": "No token found/error reading token"})
            return response

        # Process the remainder GET/PUT(Update)/DELETE scenarios
        try:
            # retrieve resource
            # This is outside owner/operator check as reading authorization should be solely determined by rpt validation
            if request.method == "GET":
                reply = get_resource(custom_mongo, resource_id, response)
                log(2011, request.method, {"User": uid,
                                           "Description": "GET operation called",
                                           "Reply": reply.headers["Error"] if isinstance(reply, Response) else json.dumps(reply)})
                return reply
            # Same for HEAD requests
            if request.method == "HEAD":
                reply = get_resource_head(custom_mongo, resource_id, response)
                log(2011, request.method, {"User": uid,
                                           "Description": "HEAD operation called",
                                           "Reply": reply.headers["Error"] if reply.status_code != 200 else "Resource found."})
                return reply
            # Update/Delete requests should only be done by resource owners or operators
            if is_owner or is_operator:
                # update resource
                if request.method == "PUT":
                    reply = update_resource(request, resource_id, uid, response)
                    log(2011, request.method, {"User": uid,
                                               "Description": "PUT operation called",
                                               "Reply": "OK" if reply.status_code == 200 else reply.headers["Error"]})
                    return reply
                # patch resource
                if request.method == "PATCH":
                    # Not currently being used, PATCH operation defaulting to PUT - 04/2021
                    # reply = patch_resource(request, custom_mongo, resource_id, uid, response)
                    reply = update_resource(request, resource_id, uid, response)
                    if reply.status_code == 200:
                        activity = {"User": uid, "Description": "PATCH operation called", "Reply": "OK"}
                    else:
                        log(2011, request.method, {"User": uid,
                                                   "Description": "PATCH operation called",
                                                   "Reply": reply.headers["Error"]})
                    return reply
                # delete resource
                elif request.method == "DELETE":
                    logger.debug("Deleting resource called for resource: " + str(resource_id))
                    reply = delete_resource(uma_handler, resource_id, response)
                    log(2012, request.method, {"User": uid,
                                               "Description": "DELETE operation called on " + resource_id + ".",
                                               "Reply": reply.status_code})
                    return reply
            else:
                log(2014, request.method, {"User": uid,
                                           "Description": "User not authorized for resource management",
                                           "Resource": resource_id})
                return set_user_not_authorized(response)
        except Exception as e:
            logger.debug("Error while redirecting to resource: " + str(e))
            response.status_code = 500
            log(2010, request.method, {"User": uid, "Description": "Error occured: " + str(e)})
            return response

    def create_resource(uid, req, uma, response):
        """
        Creates a new resource. Returns either the full resource data, or an error response
        :param uid: unique user ID used to register as owner of the resource
        :type uid: str
        :param req: resource data in JSON format
        :type req: Dictionary
        :param uma: Custom handler for UMA operations
        :type uma: Object of Class custom_uma
        :param response: response object
        :type response: Response
        """
        try:
            if req.is_json:
                data = req.get_json()
                if data.get("name"):
                    if 'resource_scopes' not in data.keys():
                        data['resource_scopes'] = []
                        for scope in g_config["default_scopes"]:
                            data['resource_scopes'].append(scope)
                    # Skip default scopes if registering scope is public or authenticated or open access
                    elif not is_public_or_authenticated_or_open(data):
                        for scope in g_config["default_scopes"]:
                            if scope not in data.get("resource_scopes"):
                                data['resource_scopes'].append(scope)

                    resource_id = uma.create(data.get("name"), data.get("resource_scopes"),
                                             data.get("description"), uid, data.get("icon_uri"))
                    data["ownership_id"] = uid
                    data["id"] = resource_id
                    return data
                else:
                    response.status_code = 500
                    response.headers["Error"] = "Invalid data passed on URL called for resource creation!"
                    return response
            else:
                response.status_code = 415
                response.headers["Error"] = "Content-Type must be application/json"
                return response
        except Exception as e:
            logger.debug("Error while creating resource: " + str(e))
            if "already exists for URI" in str(e):
                response.status_code = 422
            else:
                response.status_code = 500
            response.headers["Error"] = str(e)
            return response

    def update_resource(request, resource_id, uid, response):
        """
        Updates an existing resource. Returns a 200 OK, or nothing (in order to trigger a ticket generation)
        :param uid: unique user ID used to register as owner of the resource
        :type uid: str
        :param resource_id: unique resource ID
        :type resource_id: str
        :param request: resource data in JSON format
        :type request: Dictionary
        :param response: response object
        :type response: Response
        """
        if request.is_json:
            data = request.get_json()
            if data.get("name") and data.get("resource_scopes"):
                if "ownership_id" in data:
                    uma_handler.update(resource_id, data.get("name"), data.get("resource_scopes"),
                                       data.get("description"), data.get("ownership_id"), data.get("icon_uri"))
                else:
                    uma_handler.update(resource_id, data.get("name"), data.get("resource_scopes"),
                                       data.get("description"), uid, data.get("icon_uri"))
                response.status_code = 200
                return response
            else:
                response.status_code = 500
                response.headers["Error"] = "Invalid request"
                return response

    def patch_resource(request, custom_mongo, resource_id, uid, response):
        """
        Updates a specific field in an existing resource. Returns a 200 OK, or nothing (in order to trigger a ticket generation)
        :param uid: unique user ID used to register as owner of the resource
        :type uid: str
        :param resource_id: unique resource ID
        :type resource_id: str
        :param request: resource data in JSON format
        :type request: Dictionary
        :param custom_mongo: Custom handler for Mongo DB operations
        :type custom_mongo: Object of Class custom_mongo
        :param response: response object
        :type response: Response
        """
        resource = get_resource(custom_mongo, resource_id, response)
        if not isinstance(resource, Response):
            # Get data from database resource
            mem_data = {'name': resource['name'], 'icon_uri': resource['icon_uri']}

            if request.is_json:
                data = request.get_json()
                if "name" in data:
                    mem_data['name'] = data['name']
                if "icon_uri" in data:
                    mem_data['icon_uri'] = data['icon_uri']

                if data.get("resource_scopes"):
                    if "ownership_id" in data:
                        uma_handler.update(resource_id, mem_data.get("name"), data.get("resource_scopes"),
                                           data.get("description"), data.get("ownership_id"), mem_data.get("icon_uri"))
                    else:
                        uma_handler.update(resource_id, mem_data.get("name"), data.get("resource_scopes"),
                                           data.get("description"), uid, mem_data.get("icon_uri"))
                    response.status_code = 200
                    return response
                else:
                    response.status_code = 500
                    response.headers["Error"] = "Invalid request"
                    return response

    def delete_resource(uma, resource_id, response):
        """
        Deletes an existing resource.
        :param resource_id: unique resource ID
        :type resource_id: str
        :param uma: Custom handler for UMA operations
        :type uma: Object of Class custom_uma
        :param response: response object
        :type response: Response
        """
        logger.debug("Deleting Resource...")
        uma.delete(resource_id)
        response.status_code = 204
        return response

    def get_resource(mongo, resource_id, response):
        """
        Gets an existing resource from local database.
        :param resource_id: unique resource ID
        :type resource_id: str
        :param mongo: Custom handler for Mongo DB operations
        :type mongo: Object of Class custom_mongo
        :param response: response object
        :type response: Response
        """
        resource = mongo.get_from_mongo("resource_id", resource_id)

        # If no resource was found, return a 404 Error
        if not resource:
            response.status_code = 404
            response.headers["Error"] = "Resource not found"
            return response

        # We only want to return resource_id (as "_id") and name, so we prune the other entries
        resource = {
            "_id": resource["resource_id"],
            "_name": resource["name"],
            "_reverse_match_url": resource["reverse_match_url"]
        }
        return resource

    def get_resource_head(mongo, resource_id, response):
        """
        Gets an existing resource HEAD from local database.
        :param resource_id: unique resource ID
        :type resource_id: str
        :param mongo: Custom handler for Mongo DB operations
        :type mongo: Object of Class custom_mongo
        :param response: response object
        :type response: Response
        """
        resource = mongo.get_from_mongo("resource_id", resource_id)

        # If no resource was found, return a 404 Error
        if not resource:
            response.status_code = 404
            response.headers["Error"] = "Resource not found"
            return response

        # We only intend to return response headers, not the body, so we reply with a response instead of the resource
        response.status_code = 200
        return response

    def set_user_not_authorized(response):
        """
        Method to generate error response when user does not have sufficient edit/delete privileges.
        :param response: response object
        :type response: Response
        """
        response.status_code = 403
        response.headers["Error"] = 'User lacking sufficient access privileges'
        return response

    def get_default_ownership_policy_cfg(resource_id, uid, action, config):
        return {
            "resource_id": resource_id,
            "action": action,
            "T&C": config,
            "rules": [{"AND": [{"EQUAL": {"isOperator": True}}]}] if check_default_ownership(uid)
            else [{"AND": [{"EQUAL": {"id": uid}}]}]
        }

    def get_default_ownership_policy_body(resource_id, uid, scope, config):
        name = "Default Ownership Policy of " + str(resource_id) + " with action " + str(g_config[scope])
        description = "This is the default ownership policy for created resources through PEP"
        policy_cfg = get_default_ownership_policy_cfg(resource_id, uid, str(g_config[scope]), config)
        return {
            "name": name,
            "description": description,
            "config": policy_cfg,
            "scopes": [str(scope)]
        }

    def check_default_ownership(uid):
        for character in uid:
            if character != '0':
                return False
        return True

    def is_public_or_authenticated_or_open(data):
        return any(x in data['resource_scopes'] for x in ["public_access", "Authenticated", "open"])

    def log(code, http_method, activity):
        logger.info(log_handler.format_message(subcomponent="RESOURCE", action_id="HTTP",
                                               action_type=http_method, log_code=code,
                                               activity=activity))

    return resources_bp
