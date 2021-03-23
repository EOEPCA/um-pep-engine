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

    @resources_bp.route("/resources", methods=["GET"])
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
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
            if "NO TOKEN FOUND" in uid:
                logger.debug("Error: no token passed!")
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

        if not uid:
            logger.debug("UID for the user not found")
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            activity = {"Description":"User not found in token"}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2002,activity=activity))
            return response
        
        found_uid = False
        #We will search for any resources that are owned by the user that is making this call
        for rsrc in resources:
            #If UUID exists and owns the requested resource
            if uid and custom_mongo.verify_uid(rsrc["resource_id"], uid):
                logger.debug("Matching owned-resource found!")
                #Add resource to return list
                resourceListToReturn.append({'_id': rsrc["resource_id"], '_name': rsrc["name"]})
                found_uid = True
        
        #If user-owned resources were found, return the list
        if found_uid:
            activity = {"User":user,"Description":"Returning resource list: "+resource_list}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2007,activity=activity))
            return json.dumps(resourceListToReturn)
        #Otherwise
        response.status_code = 404
        response.headers["Error"] = "No user-owned resources found!"
        activity = {"User":user,"Description":"No matching resources found for requested path "+path}
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
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
            logger.debug(uid)
            if "NO TOKEN FOUND" in uid:
                logger.debug("Error: no token passed!")
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

        resource_reply = create_resource(uid, request, uma_handler, response)
        logger.debug("Creating resource!")
        logger.debug(resource_reply)
        #If the reply is not of type Response, the creation was successful
        #Here we register a default ownership policy to the new resource, with the PDP
        if not isinstance(resource_reply, Response):
            resource_id = resource_reply["id"]
            policy_reply = pdp_policy_handler.create_policy(policy_body=get_default_ownership_policy_body(resource_id, uid), input_headers=request.headers)
            logger.debug("CODE: "+str(policy_reply.status_code))
            logger.debug(policy_reply.text)
            if policy_reply.status_code == 200:
                activity = {"User":uid,"Description":"Resource created","Resource_id":resource_id,"Policy":policy_reply.text}
                logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2009,activity=activity))
                return resource_reply
            response.status_code = policy_reply.status_code
            response.headers["Error"] = "Error when registering resource ownership policy!"
            logger.debug(response.headers["Error"])
            activity = {"User":user,"Description":"Error occured: "+response.headers["Error"]}
            logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2010,activity=activity))
            return response
        activity = {"User":user,"Description":"Error occured: "+resource_reply}
        logger.info(log_handler.format_message(subcomponent="RESOURCES",action_id="HTTP",action_type=request.method,log_code=2010,activity=activity))
        return resource_reply

    @resources_bp.route("/resources/<resource_id>", methods=["GET", "PUT", "DELETE"])
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
                logger.debug("Error: no token passed!")
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
                activity = {"User":user,"Description":"Operation successful","Resource":resource_id}
                logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2011,activity=activity))
                return get_resource(custom_mongo, resource_id, response)
            #Update/Delete requests should only be done by resource owners or operators
            if is_owner or is_operator:
                #update resource
                if request.method == "PUT":
                    activity = {"User":user,"Description":"Operation successful","Resource":resource_id}
                    logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2011,activity=activity))
                    return update_resource(request, resource_id, uid, response)
                #delete resource
                elif request.method == "DELETE":
                    activity = {"User":user,"Description":"Resource "+resource_id+" deleted"}
                    logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2012,activity=activity))
                    return delete_resource(uma_handler, resource_id, response)
            else:
                activity = {"User":user,"Description":"User not authorized for resource management","Resource":resource_id}
                logger.info(log_handler.format_message(subcomponent="RESOURCE",action_id="HTTP",action_type=request.method,log_code=2014,activity=activity))
                return user_not_authorized(response)
        except Exception as e:
            logger.debug("Error while redirecting to resource: "+str(e))
            response.status_code = 500
            activity = {"User":user,"Description":"Error occured: "+resource_reply}
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
                if "resource_scopes" not in data.keys():
                    data["resource_scopes"] = ["protected_access"]
                if "name" in data.keys() and "resource_scopes" in data.keys():
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
        resource = {"_id": resource["resource_id"], "_name": resource["name"]}
        return resource

    def user_not_authorized(response):
        '''
        Method to generate error response when user does not have sufficient edit/delete privileges.
        :param response: response object
        :type response: Response
        '''  
        response.status_code = 403
        response.headers["Error"] = 'User lacking sufficient access privileges'
        return response

    def get_default_ownership_policy_cfg(resource_id, uid):
        return { "resource_id": resource_id, "action": "view", "rules": [{ "AND": [ {"EQUAL": {"id" : uid } }] }] }

    def get_default_ownership_policy_body(resource_id, uid):
        name = "Default Ownership Policy of " + str(resource_id)
        description = "This is the default ownership policy for created resources through PEP"
        policy_cfg = get_default_ownership_policy_cfg(resource_id, uid)
        scopes = ["protected_access"]
        logger.debug({"name": name, "description": description, "config": policy_cfg, "scopes": scopes})
        return {"name": name, "description": description, "config": policy_cfg, "scopes": scopes}

    return resources_bp
