from flask import Blueprint, request, Response, jsonify
import json
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from custom_oidc import OIDCHandler
from custom_uma import UMA_Handler, resource
from custom_uma import rpt as class_rpt
from custom_mongo import Mongo_Handler

def construct_blueprint(oidc_client, uma_handler, g_config):
    resources_bp = Blueprint('resources_bp', __name__)

    @resources_bp.route("/resources", methods=["GET"])
    def get_resource_list():
        print("Retrieving all registered resources...")
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
        except Exception as e:
            print("Error While passing the token: "+str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            return response

        if not uid:
            print("UID for the user not found")
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            return response
        
        found_uid = False
        #We will search for any resources that are owned by the user that is making this call
        for rsrc in resources:
            #If UUID exists and owns the requested resource
            if uid and custom_mongo.verify_uid(rsrc["resource_id"], uid):
                print("Matching owned-resource found!")
                #Add resource to return list
                resourceListToReturn.append({'_id': rsrc["resource_id"], '_name': rsrc["name"]})
                found_uid = True
        
        #If user-owned resources were found, return the list
        if found_uid:
            return json.dumps(resourceListToReturn)
        #Otherwise
        response.status_code = 404
        response.headers["Error"] = "No user-owned resources found!"
        return response


    @resources_bp.route("/resources/<resource_id>", methods=["GET", "PUT", "POST", "DELETE"])
    def resource_operation(resource_id):
        print("Processing " + request.method + " resource request...")
        response = Response()
        custom_mongo = Mongo_Handler("resource_db", "resources")
        uid = None
        #Inspect JWT token (UMA) or query OIDC userinfo endpoint (OAuth) for user id
        try:
            head_protected = str(request.headers)
            headers_protected = head_protected.split()
            uid = oidc_client.verify_uid_headers(headers_protected, "sub")
        except Exception as e:
            print("Error While passing the token: "+str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            return response
        
        #If UUID does not exist
        if not uid:
            print("UID for the user not found")
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            return response

        #add resource is outside of any extra validations, so it is called now
        if request.method == "POST":
            resource_reply = create_resource(uid, request, uma_handler, response)
            #If the reply does not contain a status_code, the creation was successful
            #Here we register a default ownership policy to the new resource, with the PDP
            if not resource_reply.status_code:
                resource_id = resource_reply
                policy_reply = #TODO call to policy_handler class
                if policy_reply.status_code == 200:
                    return resource_id
                response.status_code = policy_reply.status_code
                response.headers["Error"] = "Error when registering resource ownership policy!"
                return response
            return resource_reply

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
            print("Error while reading token: "+str(e))
            response.status_code = 500
            return response
        
        #Process the remainder GET/PUT(Update)/DELETE scenarios
        try:
            #retrieve resource
            #This is outside owner/operator check as reading authorization should be solely determined by rpt validation
            if request.method == "GET":
                return get_resource(custom_mongo, resource_id, response)
            #Update/Delete requests should only be done by resource owners or operators
            if is_owner or is_operator:
                #update resource
                if request.method == "PUT":
                    return update_resource(request, resource_id, uid, response)
                #delete resource
                elif request.method == "DELETE":
                    return delete_resource(uma_handler, resource_id, response)
            else:
                return user_not_authorized(response)
        except Exception as e:
            print("Error while redirecting to resource: "+str(e))
            response.status_code = 500
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
                if data.get("name") and data.get("resource_scopes"):
                    return uma_handler.create(data.get("name"), data.get("resource_scopes"), data.get("description"), uid, data.get("icon_uri"))
                else:
                    response.status_code = 500
                    response.headers["Error"] = "Invalid data passed on URL called for resource creation!"
                    return response
        except Exception as e:
            print("Error while creating resource: "+str(e))
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

    def get_default_ownership_policy_cfg(resource_id, user_name):
        return { "resource_id": resource_id, "rules": [{ "AND": [ {"EQUAL": {"user_name" : user_name } }] }] }

    def get_default_ownership_policy_body(resource_id, user_name):
        name = "Default Ownership Policy"
        description = "This is the default ownership policy for created resources through PEP"
        policy_cfg = get_default_ownership_policy_cfg(resource_id, user_name)
        scopes = ["Authenticated"]
        return {"name": name, "description": description, "policy_cfg": policy_cfg, "scopes": scopes}

    return resources_bp
