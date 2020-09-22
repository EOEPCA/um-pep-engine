from flask import Blueprint, request, Response, jsonify
import json
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from custom_oidc import OIDCHandler
from custom_uma import UMA_Handler, resource
from custom_uma import rpt as class_rpt
from custom_mongo import Mongo_Handler

from xacml import parser, decision
from utils import ClassEncoder

def construct_blueprint(oidc_client, uma_handler, g_config):
    policy_bp = Blueprint('resources_bp', __name__)

    #TODO switch to getting resources from DB instead of UMA queries
    @resources_bp.route("/resources", methods=["GET"])
    def get_resource_list():
        print("Retrieving all registed resources...")
        resources = uma_handler.get_all_resources()
        rpt = request.headers.get('Authorization')
        response = Response()
        resourceListToReturn = []
        resourceListToValidate = []

        custom_mongo = Mongo_Handler()
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

        found_uid = False
        for riD_uid in resources:
            #If UUID exists and resource requested has same UUID
            if uid and custom_mongo.verify_uid(riD_uid, uid):
                print("UID for the user found")
                found_uid = True
        
        if found_uid is False:
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            return response

        if rpt:
            print("Token found: " + rpt)
            rpt = rpt.replace("Bearer ","").strip()
            #Token was found, check for validation
            for rID in resources:
                #In here we will use the loop for 2 goals: build the resource list to validate (all of them) and the potential reply list of resources, to avoid a second loop
                scopes = uma_handler.get_resource_scopes(rID)
                resourceListToValidate.append({"resource_id": rID, "resource_scopes": scopes })
                r = uma_handler.get_resource(rID)
                entry = {'_id': r["_id"], 'name': r["name"]}
                resourceListToReturn.append(entry)
            if uma_handler.validate_rpt(rpt, resourceListToValidate, g_config["s_margin_rpt_valid"]) or not api_rpt_uma_validation:
                return json.dumps(resourceListToReturn)
        print("No auth token, or auth token is invalid")
        if resourceListToValidate:
            # Generate ticket if token is not present
            ticket = uma_handler.request_access_ticket(resourceListToValidate)

            # Return ticket
            response.headers["WWW-Authenticate"] = "UMA realm="+g_config["realm"]+",as_uri="+g_config["auth_server_url"]+",ticket="+ticket
            response.status_code = 401 # Answer with "Unauthorized" as per the standard spec.
            return response
        response.status_code = 500
        return response

    @resources_bp.route("/resources/<resource_id>", methods=["GET", "PUT", "POST", "DELETE"])
    def resource_operation(resource_id):
        print("Processing " + request.method + " resource request...")
        response = Response()
        custom_mongo = Mongo_Handler()
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

        #add resource is outside of rpt validation, as it only requires a client pat to register a new resource
        if request.method == "POST":
            return create_resource(uid, request, uma_handler, response)

        #Is this user the resource's owner?
        is_owner = custom_mongo.verify_uid(resource_id, uid)
        #Is this user an operator?
        is_operator = oidc_client.verify_uid_headers(headers_protected, "operator")
        #Above query returns a None in case of Exception, following condition asserts False for that case
        if not is_operator:
            is_operator = False

        #If UUID exists and the user has sufficient access privileges
        if uid and (is_owner or is_operator):
            print("UID for the user found and is authorized")
        else:
            response.status_code = 401
            response.headers["Error"] = 'No resource found for that ID or lack of access privilege'
            return response
        
        # Get resource scopes from resource_id
        try:
            scopes = uma_handler.get_resource_scopes(resource_id)
        except Exception as e:
            print("Error occured when retrieving resource scopes: " +str(e))
            scopes = None

        rpt = request.headers.get('Authorization')
        if rpt:
            #Token was found, check for validation
            print("Found rpt in request, validating...")
            rpt = rpt.replace("Bearer ","").strip()
            if uma_handler.validate_rpt(rpt, [{"resource_id": resource_id, "resource_scopes": scopes }], g_config["s_margin_rpt_valid"]) or not api_rpt_uma_validation:
                print("RPT valid, proceding...")
                try:
                    if is_owner or is_operator:
                        #retrieve resource
                        if request.method == "GET":
                            return get_resource(custom_mongo, resource_id)
                        #update resource
                        elif request.method == "PUT":
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
            
        print("No auth token, or auth token is invalid")
        #Scopes have already been queried at this time, so if they are not None, we know the resource has been found. This is to avoid a second query.
        if scopes is not None:
            print("Matched resource: "+str(resource_id))
            # Generate ticket if token is not present
            ticket = uma_handler.request_access_ticket([{"resource_id": resource_id, "resource_scopes": scopes }])

            # Return ticket
            response.headers["WWW-Authenticate"] = "UMA realm="+g_config["realm"]+",as_uri="+g_config["auth_server_url"]+",ticket="+ticket
            response.status_code = 401 # Answer with "Unauthorized" as per the standard spec.
            return response
        else:
            print("Error, resource not found!")
            response.status_code = 500
            return response

    def create_resource(uid, request, uma_handler, response):
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
        if request.is_json:
            data = request.get_json()
            if data.get("name") and data.get("resource_scopes"):
                #TODO determine how the ownership is changed
                uma_handler.update(resource_id, data.get("name"), data.get("resource_scopes"), data.get("description"), uid, data.get("icon_uri"))
                response.status_code = 200
                return response

    def delete_resource(uma_handler, resource_id, response):
        uma_handler.delete(resource_id)
        response.status_code = 204
        return response

    def get_resource(custom_mongo, resource_id):
        return custom_mongo.get_resource(resource_id)

    def user_not_authorized(response):
        response.status_code = 403
        response.headers["Error"] = 'User lacking sufficient access privileges'
        return response

    return resources_bp