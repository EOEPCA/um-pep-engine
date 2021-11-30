from flask import Blueprint, request, Response, jsonify
import json
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from handlers.oidc_handler import OIDCHandler
from handlers.uma_handler import UMA_Handler, resource
from handlers.uma_handler import rpt as class_rpt
from handlers.mongo_handler import Mongo_Handler
from handlers.policy_handler import policy_handler
from handlers.log_handler import LogHandler
import logging

def construct_blueprint(oidc_client, uma_handler, pdp_policy_handler, g_config):
    resources_bp = Blueprint('resources_bp', __name__)
    logger = logging.getLogger("PEP_ENGINE")
    log_handler = LogHandler.get_instance()

    @resources_bp.route("/resources", methods=["GET", "HEAD"])
    def get_resource_list():
        logger.debug("Retrieving all registered resources...")
        #gets all resources registered on local DB
        custom_mongo = Mongo_Handler("resource_db", "resources")
        resources = custom_mongo.get_all_resources()

        rpt = request.headers.get('Authorization')
        response = Response()
        resourceListToReturn = []

        uid = None
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            is_operator = oidc_client.verify_uid_headers(headers_protected, "isOperator")
            #Above query returns a None in case of Exception, following condition asserts False for that case
            if not is_operator:
                is_operator = False
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
            if "NO TOKEN FOUND" in uid:
                response.status_code = 401
                response.headers["Error"] = 'no token passed!'
                activity = {"Description":"No token found/error reading token"}
                logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2001,activity=activity))
                return response
        except Exception as e:
            logger.debug("Error While passing the token: "+str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            activity = {"Description":"No token found/error reading token: "+str(e)}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2001,activity=activity))
            return response

        if not uid and not is_operator:
            logger.debug("UID for the user not found")
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            activity = {"Description":"User not found in token"}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2002,activity=activity))
            return response
        
        found_uid = False

        path = request.args.get('path')
        if path:
            resource = custom_mongo.get_from_mongo("reverse_match_url", str(path))            
            if resource:
                activity = {"User":uid,"Description":"Returning matched resource by path: "+ str({'_id': resource["resource_id"], '_name': resource["name"], '_reverse_match_url': resource["reverse_match_url"]})}
                logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2007,activity=activity))
                if request.method == "HEAD":
                    return
                return {'_id': resource["resource_id"], '_name': resource["name"], '_reverse_match_url': resource["reverse_match_url"]}
            else:
                response.status_code = 404
                response.headers["Error"] = "No user-owned resources found!"
                activity = {"User":uid,"Description":"No matching resources found for user!"}
                logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2008,activity=activity))
                return response
        else:
            #We will search for any resources that are owned by the user that is making this call
            for rsrc in resources:
                #If UUID exists and owns the requested resource
                if uid and custom_mongo.verify_uid(rsrc["resource_id"], uid):
                    logger.debug("Matching owned-resource found!")
                    #Add resource to return list
                    resourceListToReturn.append({'_id': rsrc["resource_id"], '_name': rsrc["name"], '_reverse_match_url': rsrc["reverse_match_url"]})
                    found_uid = True
        
        #If user-owned resources were found, return the list
        if found_uid:
            activity = {"User":uid,"Description":"Returning resource list: "+json.dumps(resourceListToReturn)}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2007,activity=activity))
            if request.method == "HEAD":
                return
            return json.dumps(resourceListToReturn)
        #Otherwise
        response.status_code = 404
        response.headers["Error"] = "No user-owned resources found!"
        activity = {"User":uid,"Description":"No matching resources found for user!"}
        logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2008,activity=activity))
        return response

    @resources_bp.route("/resources", methods=["POST"])
    def resource_creation():
        logger.debug("Processing " + request.method + " resource request...")
        response = Response()
        uid = None
        #Inspect JWT token (UMA) or query OIDC userinfo endpoint (OAuth) for user id
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            logger.debug(head_protected)
            is_operator = oidc_client.verify_uid_headers(headers_protected, "isOperator")
            #Above query returns a None in case of Exception, following condition asserts False for that case
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
                activity = {"Description":"No token found/error reading token"}
                logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2001,activity=activity))
                return response
        except Exception as e:
            logger.debug("Error While passing the token: "+str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            activity = {"Description":"No token found/error reading token: "+str(e)}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2001,activity=activity))
            return response
        
        #If UUID does not exist
        if not uid:
            logger.debug("UID for the user not found")
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            activity = {"Description":"User not found in token"}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2002,activity=activity))
            return response

        #Above query returns a None in case of Exception, following condition asserts False for that case
        if not is_operator:
            is_operator = False
        
        data = request.get_json()
        custom_mongo = Mongo_Handler("resource_db", "resources")

        if is_operator or custom_mongo.verify_previous_uri_ownership(uid,data.get("icon_uri")): 
            resource_reply = create_resource(uid, request, uma_handler, response)
        else:
            response.status_code = 401
            response.headers["Error"] = "Operator constraint, no authorization for given UID"
            return response
        logger.debug("Creating resource!")
        logger.debug(resource_reply)
        #If the reply is not of type Response, the creation was successful
        #Here we register a default ownership policy to the new resource, with the PDP
        if not isinstance(resource_reply, Response):
            resource_id = resource_reply["id"]
            reply_failed = False
            #If the public or authenticated scopes were used to register resource, skip policy registration
            if is_public_or_authenticated(request.get_json()):
                activity = {"User":uid,"Description":"Resource created","Resource_id":resource_id,"Policy":"None, Public/Authenticated access"}
                logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2009,activity=activity))
                return resource_reply
            #else, continue with ownership policies for default scopes
            for scope in g_config["default_scopes"]:
                def_policy_reply = pdp_policy_handler.create_policy(policy_body=get_default_ownership_policy_body(resource_id, uid, scope), input_headers=request.headers)
                if def_policy_reply.status_code != 200:
                    reply_failed = True
                    break
            if not reply_failed:
                activity = {"User":uid,"Description":"Resource created","Resource_id":resource_id,str(g_config[scope])+" Policy":def_policy_reply.text}
                logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2009,activity=activity))
                return resource_reply
            response.status_code = def_policy_reply.status_code
            if "Error" in def_policy_reply.headers:
                response.headers["Error"] = def_policy_reply.headers["Error"]
            else:
                response.headers["Error"] = "Un-parseable error coming from server"
            logger.debug(response.headers["Error"])
            activity = {"User":uid,"Description":"Error occured: "+response.headers["Error"]}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2010,activity=activity))
            return response
        activity = {"User":uid,"Description":"Error occured with HTTP code "+ str(resource_reply.status_code) +": "+resource_reply.headers["Error"]}
        logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2010,activity=activity))
        return resource_reply

    @resources_bp.route("/resources/<resource_id>", methods=["GET", "PUT", "DELETE", "HEAD", "PATCH"])
    def resource_operation(resource_id):
        logger.debug("Processing " + request.method + " resource request...")
        response = Response()
        custom_mongo = Mongo_Handler("resource_db", "resources")
        uid = None
        #Inspect JWT token (UMA) or query OIDC userinfo endpoint (OAuth) for user id
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
            if "NO TOKEN FOUND" in uid:
                response.status_code = 401
                response.headers["Error"] = 'no token passed!'
                activity = {"Description":"No token found/error reading token"}
                logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2001,activity=activity))
                return response
        except Exception as e:
            logger.debug("Error While passing the token: "+str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            activity = {"Description":"No token found/error reading token: "+str(e)}
            logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2001,activity=activity))
            return response
        
        #If UUID does not exist
        if not uid:
            logger.debug("UID for the user not found")
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            activity = {"Description":"User not found in token"}
            logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2002,activity=activity))
            return response

        try:
            #otherwise continue with validations
            #Is this user the resource's owner?
            is_owner = custom_mongo.verify_uid(resource_id, uid)
            #Is this user an operator?
            is_operator = oidc_client.verify_uid_headers(headers_protected, "isOperator")
            #Above query returns a None in case of Exception, following condition asserts False for that case
            if not is_operator:
                is_operator = False
        except Exception as e:
            logger.debug("Error while reading token: "+str(e))
            response.status_code = 500
            activity = {"Description":"No token found/error reading token"}
            logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2001,activity=activity))
            return response
        
        #Process the remainder GET/PUT(Update)/DELETE scenarios
        try:
            #retrieve resource
            #This is outside owner/operator check as reading authorization should be solely determined by rpt validation
            if request.method == "GET":
                reply = get_resource(custom_mongo, resource_id, response)
                if isinstance(reply, Response):
                    activity = {"User":uid,"Description":"GET operation called","Reply":reply.headers["Error"]}
                else:
                    activity = {"User":uid,"Description":"GET operation called","Reply":json.dumps(reply)}
                logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2011,activity=activity))
                return reply
            #Same for HEAD requests
            if request.method == "HEAD":
                reply = get_resource_head(custom_mongo, resource_id, response)
                if reply.status_code != 200:
                    activity = {"User":uid,"Description":"HEAD operation called","Reply":reply.headers["Error"]}
                else:
                    activity = {"User":uid,"Description":"HEAD operation called","Reply":"Resource found."}
                logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2011,activity=activity))
                return reply
            #Update/Delete requests should only be done by resource owners or operators
            if is_owner or is_operator:
                #update resource
                if request.method == "PUT":
                    reply = update_resource(request, resource_id, uid, response)
                    if reply.status_code == 200:
                        activity = {"User":uid,"Description":"PUT operation called","Reply":"OK"}
                    else:
                        activity = {"User":uid,"Description":"PUT operation called","Reply":reply.headers["Error"]}
                    logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2011,activity=activity))
                    return reply
                #patch resource
                if request.method == "PATCH":
                    # Not currently being used, PATCH operation defaulting to PUT - 04/2021
                    # reply = patch_resource(request, custom_mongo, resource_id, uid, response)
                    reply = update_resource(request, resource_id, uid, response)
                    if reply.status_code == 200:
                        activity = {"User":uid,"Description":"PATCH operation called","Reply":"OK"}
                    else:
                        activity = {"User":uid,"Description":"PATCH operation called","Reply":reply.headers["Error"]}
                    logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2011,activity=activity))
                    return reply
                #delete resource
                elif request.method == "DELETE":
                    reply = delete_resource(uma_handler, resource_id, response)
                    activity = {"User":uid,"Description":"DELETE operation called on "+resource_id+".","Reply":reply.status_code}
                    logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2012,activity=activity))
                    return reply
            else:
                activity = {"User":uid,"Description":"User not authorized for resource management","Resource":resource_id}
                logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2014,activity=activity))
                return user_not_authorized(response)
        except Exception as e:
            logger.debug("Error while redirecting to resource: "+str(e))
            response.status_code = 500
            activity = {"User":uid,"Description":"Error occured: "+str(e)}
            logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2010,activity=activity))
            return response

    def create_resource(uid, request, uma_handler, response):
        '''
        Creates a new resource. Returns either the full resource data, or an error response
        :param uid: unique user ID used to register as owner of the resource
        :type uid: str
        :param request: resource data in JSON format
        :type request: Dictionary
        :param uma_handler: Custom handler for UMA operations
        :type uma_handler: Object of Class custom_uma
        :param response: response object
        :type response: Response
        '''
        try:
            if request.is_json:
                data = request.get_json()
                if data.get("name"):
                    if 'resource_scopes' not in data.keys():
                        data['resource_scopes'] = []
                        for scope in g_config["default_scopes"]:
                            data['resource_scopes'].append(scope)
                    #Skip default scopes if registering scope is public or authenticated access
                    elif not is_public_or_authenticated(data):
                        for scope in g_config["default_scopes"]:
                            if scope not in data.get("resource_scopes"):
                                data['resource_scopes'].append(scope)

                    resource_id = uma_handler.create(data.get("name"), data.get("resource_scopes"), data.get("description"), uid, data.get("icon_uri"))
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
            logger.debug("Error while creating resource: "+str(e))
            if "already exists for URI" in str(e):
                response.status_code = 422
            else:
                response.status_code = 500
            response.headers["Error"] = str(e)
            return response

    def update_resource(request, resource_id, uid, response):
        '''
        Updates an existing resource. Returns a 200 OK, or nothing (in order to trigger a ticket generation)
        :param uid: unique user ID used to register as owner of the resource
        :type uid: str
        :param resource_id: unique resource ID
        :type resource_id: str
        :param request: resource data in JSON format
        :type request: Dictionary
        :param response: response object
        :type response: Response
        '''
        if request.is_json:
            data = request.get_json()
            if data.get("name") and data.get("resource_scopes"):
                if "ownership_id" in data:
                    uma_handler.update(resource_id, data.get("name"), data.get("resource_scopes"), data.get("description"), data.get("ownership_id"), data.get("icon_uri"))
                else:
                    uma_handler.update(resource_id, data.get("name"), data.get("resource_scopes"), data.get("description"), uid, data.get("icon_uri"))
                response.status_code = 200
                return response
            else:
                response.status_code = 500
                response.headers["Error"] = "Invalid request"
                return response

    def patch_resource(request, custom_mongo, resource_id, uid, response):
        '''
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
        '''
        resource = get_resource(custom_mongo, resource_id, response)
        if not isinstance(resource, Response):
            #Get data from database resource
            mem_data = {}
            mem_data['name'] = resource['name']
            mem_data['icon_uri'] = resource['icon_uri']

            if request.is_json:
                data = request.get_json()
                if "name" in data:
                    mem_data['name'] = data['name']
                if "icon_uri" in data:
                    mem_data['icon_uri'] = data['icon_uri']

                if data.get("resource_scopes"):
                    if "ownership_id" in data:
                        uma_handler.update(resource_id, mem_data.get("name"), data.get("resource_scopes"), data.get("description"), data.get("ownership_id"), mem_data.get("icon_uri"))
                    else:
                        uma_handler.update(resource_id, mem_data.get("name"), data.get("resource_scopes"), data.get("description"), uid, mem_data.get("icon_uri"))
                    response.status_code = 200
                    return response
                else:
                    response.status_code = 500
                    response.headers["Error"] = "Invalid request"
                    return response

    def delete_resource(uma_handler, resource_id, response):
        '''
        Deletes an existing resource.
        :param resource_id: unique resource ID
        :type resource_id: str
        :param uma_handler: Custom handler for UMA operations
        :type uma_handler: Object of Class custom_uma
        :param response: response object
        :type response: Response
        '''
        uma_handler.delete(resource_id)
        response.status_code = 204
        return response

    def get_resource(custom_mongo, resource_id, response):
        '''
        Gets an existing resource from local database.
        :param resource_id: unique resource ID
        :type resource_id: str
        :param custom_mongo: Custom handler for Mongo DB operations
        :type custom_mongo: Object of Class custom_mongo
        :param response: response object
        :type response: Response
        '''    
        resource = custom_mongo.get_from_mongo("resource_id", resource_id)
        
        #If no resource was found, return a 404 Error
        if not resource:
            response.status_code = 404
            response.headers["Error"] = "Resource not found"
            return response
            
        #We only want to return resource_id (as "_id") and name, so we prune the other entries
        resource = {"_id": resource["resource_id"], "_name": resource["name"], "_reverse_match_url": resource["reverse_match_url"]}
        return resource

    def get_resource_head(custom_mongo, resource_id, response):
        '''
        Gets an existing resource HEAD from local database.
        :param resource_id: unique resource ID
        :type resource_id: str
        :param custom_mongo: Custom handler for Mongo DB operations
        :type custom_mongo: Object of Class custom_mongo
        :param response: response object
        :type response: Response
        '''    
        resource = custom_mongo.get_from_mongo("resource_id", resource_id)
        
        #If no resource was found, return a 404 Error
        if not resource:
            response.status_code = 404
            response.headers["Error"] = "Resource not found"
            return response

        #We only intend to return response headers, not the body, so we reply with a response instead of the resource
        response.status_code = 200    
        return response

    def user_not_authorized(response):
        '''
        Method to generate error response when user does not have sufficient edit/delete privileges.
        :param response: response object
        :type response: Response
        '''  
        response.status_code = 403
        response.headers["Error"] = 'User lacking sufficient access privileges'
        return response

    def get_default_ownership_policy_cfg(resource_id, uid, action):
        if check_default_ownership(uid):
            return { "resource_id": resource_id, "action": action, "rules": [{ "AND": [ {"EQUAL": {"isOperator" : True } }] }] }
        else:
            return { "resource_id": resource_id, "action": action, "rules": [{ "AND": [ {"EQUAL": {"id" : uid } }] }] }

    def get_default_ownership_policy_body(resource_id, uid, scope):
        name = "Default Ownership Policy of " + str(resource_id) + " with action " + str(g_config[scope])
        description = "This is the default ownership policy for created resources through PEP"
        policy_cfg = get_default_ownership_policy_cfg(resource_id, uid, str(g_config[scope]))
        return {"name": name, "description": description, "config": policy_cfg, "scopes": [str(scope)]}

    def check_default_ownership(uid):
        for character in uid:
            if character != '0':
                return False
        return True

    def is_public_or_authenticated(data):
        return any(x in data['resource_scopes'] for x in ["public_access", "Authenticated"])

    return resources_bp
