#!/usr/bin/env python3
from eoepca_uma import rpt, resource
from handlers.mongo_handler import Mongo_Handler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT
from jwt_verification.signature_verification import JWT_Verification
from typing import List
import base64
import json
import pymongo
from datetime import datetime
import logging

class UMA_Handler:

    def __init__(self, wkhandler, oidc_handler, verify_ssl: bool = False ):
        self.logger = logging.getLogger("PEP_ENGINE")
        self.wkh = wkhandler
        self.mongo= Mongo_Handler("resource_db", "resources")
        self.mongo_rpt= Mongo_Handler("rpt_db", "rpts")
        self.oidch = oidc_handler
        self.verify = verify_ssl
        self.registered_resources = None
        
    def create(self, name: str, scopes: List[str], description: str, ownership_id: str, icon_uri: str):
        """
        Creates a new resource IF A RESOURCE WITH THAT ICON_URI DOESN'T EXIST YET.
        Will throw an exception if it exists
        """
        self.logger.debug("Creating resource through UMA Handler")
        if self.resource_exists(icon_uri):
            raise Exception("Resource already exists for URI "+icon_uri)

        resource_registration_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        pat = self.oidch.get_new_pat()
        new_resource_id = resource.create(pat, resource_registration_endpoint, name, scopes, description=description, icon_uri= icon_uri, secure = self.verify)
        self.logger.debug("Created resource '"+name+"' with ID :"+new_resource_id)
        # Register resources inside the dbs
        resp=self.mongo.insert_resource_in_mongo(new_resource_id, name, ownership_id, icon_uri)
        if resp: self.logger.debug('Resource saved in DB succesfully')
       
        return new_resource_id
        
    def update(self, resource_id: str, name: str, scopes: List[str], description: str, ownership_id: str, icon_uri: str):
        """
        Updates an existing resource.
        Can throw exceptions
        """
        
        resource_registration_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        pat = self.oidch.get_new_pat()
        new_resource_id = resource.update(pat, resource_registration_endpoint, resource_id, name, scopes, description=description, icon_uri= icon_uri, secure = self.verify)
        resp=self.mongo.insert_resource_in_mongo(resource_id, name, ownership_id, icon_uri)
        self.logger.debug("Updated resource '"+name+"' with ID :"+new_resource_id)
        
    def delete(self, resource_id: str):
        """
        Deletes an existing resource.
        Can throw exceptions
        """        
        
        id = self.get_resource(resource_id)["_id"]
        if id is None:
            raise Exception("Resource for ID "+resource_id+" does not exist")

        resource_registration_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        pat = self.oidch.get_new_pat()
        try:
            resource.delete(pat, resource_registration_endpoint, resource_id, secure = self.verify)
            resp = self.mongo.delete_in_mongo("resource_id", resource_id)
            self.logger.debug("Deleted resource with ID :"+resource_id)
        except Exception as e:
            self.logger.debug("Error while deleting resource: "+str(e))


    # Usage of Python library for query mongodb instance

    def validate_rpt(self, user_rpt: str, resources: List[dict], margin_time_rpt_valid: float, rpt_limit_uses: int, verify_signature: bool) -> bool:
        """
        Returns True/False, if the RPT is valid for the resource(s) they are trying to access
        """
        results = []

        rpt_splitted = user_rpt.split('.')

        introspection_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_INTROSPECTION_ENDPOINT)
        pat = self.oidch.get_new_pat()

        if len(rpt_splitted) == 3:
            if verify_signature == True:
                test = JWT_Verification()
                result = test.verify_signature_JWT(user_rpt)

                if result == False:
                    self.logger.debug("Verification of the signature for the JWT failed!")
                    return False
                else:
                    self.logger.debug("Signature verification is correct!")

            payload = str(user_rpt).split(".")[1]
            paddedPayload = payload + '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(paddedPayload)
            decoded = decoded.decode('utf-8')
            rpt_class = json.loads(decoded)
        else:
            rpt_class = rpt.introspect(rpt=user_rpt, pat=pat, introspection_endpoint=introspection_endpoint, secure=False)

        result = rpt.is_valid_now(user_rpt, pat, introspection_endpoint, resources, time_margin= margin_time_rpt_valid ,secure= self.verify )

        if result is False:
            return False

        resource_id_mongo = resources[0]['resource_id']

        #We see in the database if the rpt exists
        exists_rpt = self.mongo_rpt.mongo_exists("rpt", user_rpt)
        #If it exists -> decrease rpt usage and check if you have limit_uses
        if exists_rpt is True:
            rpt_mongo_obj = self.mongo_rpt.get_from_mongo("rpt", user_rpt)
            limits = rpt_mongo_obj['rpt_limit_uses']

            if limits > 0:
                rpt_mongo_obj['rpt_limit_uses'] = limits - 1
                self.mongo_rpt.update_in_mongo("rpt", rpt_mongo_obj)
        else:
            #If it does not exist -> it is inserted into the database with all the limit_uses obtained from the env var or config
            dateTimeObj = datetime.now()
            timestampStr = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S.%f)")

            self.mongo_rpt.insert_rpt_in_mongo(user_rpt, rpt_limit_uses - 1, timestampStr)
            limits = rpt_limit_uses

        if rpt_class['permissions'] is not None:
            result = self.validate_resources_ids(resource_id_mongo, rpt_class, limits)
            results.append(result)
        else:
            return False

        validator = True
        for i in range(0, len(results)):
            if results[i] is False:
                validator = False
    
        return validator

    
    def resource_exists(self, icon_uri: str):
        """
        Checks if the resources managed already contain a resource with that URI.
        Returns the matching (resource_id, scopes) or None if not found
        """
        pat = self.oidch.get_new_pat()
        resource_reg_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        r=self.mongo.get_id_from_uri(icon_uri)
        if not r: return False
        data = resource.read(pat, resource_reg_endpoint, r, self.verify)
        if "icon_uri" in data and data["icon_uri"] == icon_uri:
            return True
        
        return False
        
    def get_resource_scopes(self, resource_id: str):
        """
        Returns the matching scopes for resource_id or None if not found
        """
        pat = self.oidch.get_new_pat()
        resource_reg_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        data = resource.read(pat, resource_reg_endpoint, resource_id, self.verify)
        if "_id" in data and data["_id"] == resource_id:
            return data["resource_scopes"]
        return None
        
    def get_resource(self, resource_id: str):
        """
        Returns the matching resource for resource_id or None if not found
        """
        pat = self.oidch.get_new_pat()
        resource_reg_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        data = resource.read(pat, resource_reg_endpoint, resource_id, self.verify)
        if "_id" in data and data["_id"] == resource_id:
            return data
        return None


    def request_access_ticket(self, resources):
        permission_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_PERMISSION_ENDPOINT)
        pat = self.oidch.get_new_pat()
        return resource.request_access_ticket(pat, permission_endpoint, resources, secure = self.verify)

    def status(self):
        """
        Demo/debug-oriented function, to display the information of all controlled resources
        """
        pat = self.oidch.get_new_pat()
        resource_reg_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        actual_resources = resource.list(pat, resource_reg_endpoint, self.verify)

        self.logger.debug("-----------STATUS-----------")
        self.logger.debug(str(len(actual_resources))+ " Actual Resources registered in the AS, with IDS: "+str(actual_resources))
        self.logger.debug("-----------LIVE INFORMATION FROM AS------")
        for r in actual_resources:
            info = resource.read(pat, resource_reg_endpoint, r, secure= self.verify)
            self.logger.debug(info)
            self.logger.debug("++++++++++++++++")
        self.logger.debug("-----------STATUS END-------")


    def update_resources_from_as(self):
        """
        Updates the cache of resources
        """
        # Get a list of the controlled resources
        pat = self.oidch.get_new_pat()
        resource_reg_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        return resource.list(pat, resource_reg_endpoint, self.verify)
            
    def get_all_resources(self):
        """
        Updates and returns all the registed resources
        """
        return self.update_resources_from_as()

    def validate_resources_ids(self, resource_id_mongo: str, resource_id_rpt_list: List[dict], limits: int):
        first_validation = False

        for i in range(0, len(resource_id_rpt_list['permissions'])):
            resource_id_rpt = resource_id_rpt_list['permissions'][i]['resource_id']

            if (resource_id_mongo == resource_id_rpt) and limits > 0:
                first_validation = True

        return first_validation
