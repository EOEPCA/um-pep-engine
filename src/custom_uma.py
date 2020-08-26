#!/usr/bin/env python3
from eoepca_uma import rpt, resource
from custom_mongo import Mongo_Handler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT
from typing import List
import pymongo

class UMA_Handler:

    def __init__(self, wkhandler, oidc_handler, verify_ssl: bool = False ):
        self.wkh = wkhandler
        self.mongo= Mongo_Handler()
        self.oidch = oidc_handler
        self.verify = verify_ssl
        
    def create(self, name: str, scopes: List[str], description: str, ownership_id: str, icon_uri: str):
        """
        Creates a new resource IF A RESOURCE WITH THAT ICON_URI DOESN'T EXIST YET.
        Will throw an exception if it exists
        """

        if self.resource_exists(icon_uri):
            raise Exception("Resource already exists for URI "+icon_uri)

        resource_registration_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        pat = self.oidch.get_new_pat()
        new_resource_id = resource.create(pat, resource_registration_endpoint, name, scopes, description=description, icon_uri= icon_uri, secure = self.verify)
        print("Created resource '"+name+"' with ID :"+new_resource_id)
        # Register resources inside the dbs
        resp=self.mongo.insert_in_mongo(new_resource_id, name, ownership_id, icon_uri)
        if resp: print('Resource saved in DB succesfully')
       
        return new_resource_id
        
    def update(self, resource_id: str, name: str, scopes: List[str], description: str, ownership_id: str, icon_uri: str):
        """
        Updates an existing resource.
        Can throw exceptions
        """
        
        resource_registration_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT)
        pat = self.oidch.get_new_pat()
        new_resource_id = resource.update(pat, resource_registration_endpoint, resource_id, name, scopes, description=description, icon_uri= icon_uri, secure = self.verify)
        resp=self.mongo.insert_in_mongo(resource_id, name, ownership_id, icon_uri)
        print("Updated resource '"+name+"' with ID :"+new_resource_id)
        
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
            resp = self.mongo.delete_resource(resource_id)
            print("Deleted resource with ID :"+resource_id)
        except Exception as e:
            print("Error while deleting resource: "+str(e))


    # Usage of Python library for query mongodb instance

    def validate_rpt(self, user_rpt: str, resources: List[dict], margin_time_rpt_valid: float, ) -> bool:
        """
        Returns True/False, if the RPT is valid for the resource(s) they are trying to access
        """
        introspection_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_INTROSPECTION_ENDPOINT)
        pat = self.oidch.get_new_pat()
        return rpt.is_valid_now(user_rpt, pat, introspection_endpoint, resources, time_margin= margin_time_rpt_valid ,secure= self.verify )

    
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

        print("-----------STATUS-----------")
        print(str(len(actual_resources))+ " Actual Resources registered in the AS, with IDS: "+str(actual_resources))
        print("-----------LIVE INFORMATION FROM AS------")
        for r in actual_resources:
            info = resource.read(pat, resource_reg_endpoint, r, secure= self.verify)
            print(info)
            print("++++++++++++++++")
        print("-----------STATUS END-------")
