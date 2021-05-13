import unittest
import subprocess
import os
import requests
import json
import sys
import base64
import time
import traceback
import urllib
import logging
import datetime
from jwkest.jws import JWS
from jwkest.jwk import RSAKey, import_rsa_key_from_file, load_jwks_from_url, import_rsa_key
from jwkest.jwk import load_jwks
from Crypto.PublicKey import RSA
from WellKnownHandler import WellKnownHandler, TYPE_SCIM, TYPE_OIDC, KEY_SCIM_USER_ENDPOINT, KEY_OIDC_TOKEN_ENDPOINT, KEY_OIDC_REGISTRATION_ENDPOINT, KEY_OIDC_SUPPORTED_AUTH_METHODS_TOKEN_ENDPOINT, TYPE_UMA_V2, KEY_UMA_V2_PERMISSION_ENDPOINT
from eoepca_uma import rpt, resource

class PEPResourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g_config = {}
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path+"/../src/config/config.json") as j:
            cls.g_config = json.load(j)

        wkh = WellKnownHandler(cls.g_config["auth_server_url"], secure=False)
        cls.__TOKEN_ENDPOINT = wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)

        _rsajwk = RSAKey(kid="RSA1", key=import_rsa_key_from_file(dir_path+"/../src/config/private.pem"))
        _payload = { 
                    "iss": cls.g_config["client_id"],
                    "sub": cls.g_config["client_id"],
                    "aud": cls.__TOKEN_ENDPOINT,
                    "user_name": "admin",
                    "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
                    "exp": int(time.time())+3600,
                    "isOperator": False
                }
        _jws = JWS(_payload, alg="RS256")

        _payload_ownership = { 
                    "iss": cls.g_config["client_id"],
                    "sub": "54d10251-6cb5-4aee-8e1f-f492f1105c94",
                    "aud": cls.__TOKEN_ENDPOINT,
                    "user_name": "admin",
                    "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
                    "exp": int(time.time())+3600,
                    "isOperator": False
                }
        _jws_ownership = JWS(_payload_ownership, alg="RS256")

        cls.jwt = _jws.sign_compact(keys=[_rsajwk])
        cls.jwt_rotest = _jws_ownership.sign_compact(keys=[_rsajwk])
        #cls.scopes = 'public_access'
        cls.scopes = 'protected_access'
        cls.resourceName = "TestResourcePEP"
        cls.PEP_HOST = "http://localhost:5566"
        cls.PEP_RES_HOST = "http://localhost:5576"
       
    def getJWT(self):
        return self.jwt

    def getJWT_RO(self):
        return self.jwt_rotest

    def getResourceList(self, id_token="filler"):
        headers = { 'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache", "Authorization": "Bearer "+str(id_token)}
        res = requests.get(self.PEP_RES_HOST+"/resources", headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 404:
            return 404, res.headers["Error"]
        if res.status_code == 200:
            return 200, res.json()
        return 500, None

    def createTestResource(self, id_token="filler"):
        payload = { "resource_scopes":[ self.scopes ], "icon_uri":"/"+self.resourceName, "name": self.resourceName }
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+str(id_token) }
        res = requests.post(self.PEP_RES_HOST+"/resources", headers=headers, json=payload, verify=False)
        print(res)
        print(res.text)
        print(self.PEP_RES_HOST+"/resources")
        if res.status_code == 200:
            return 200, res.text
        return 500, None

    def getResource(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        res = requests.get(self.PEP_RES_HOST+"/resources/"+self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 200:
            return 200, res.json()
        if res.status_code == 404:
            return 404, res.headers["Error"]
        return 500, None

    def deleteResource(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        res = requests.delete(self.PEP_RES_HOST+"/resources/"+self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 204:
            return 204, None
        return 500, None

    def updateResource(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        payload = { "resource_scopes":[ self.scopes], "icon_uri":"/"+self.resourceName, "name":self.resourceName+"Mod" }
        res = requests.put(self.PEP_RES_HOST+"/resources/"+self.resourceID, headers=headers, json=payload, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 200:
            return 200, None
        return 500, None

    def updateResourceRO(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        payload = {"resource_scopes":[ self.scopes], "icon_uri":"/"+self.resourceName, "name":self.resourceName+"Mod", "ownership_id": "54d10251-6cb5-4aee-8e1f-f492f1105c94"}
        res = requests.put(self.PEP_RES_HOST+"/resources/"+self.resourceID, headers=headers, json=payload, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 403:
            return 403, res.headers["Error"]
        if res.status_code == 200:
            return 200, None
        return 500, None

    def swaggerUI(self):
        reply = requests.get(self.PEP_HOST+"/swagger-ui")
        self.assertEqual(200, reply.status_code)
        print("=================")
        print("Get Web Page: 200 OK!")
        print("=================")
        page = reply.text
        page_title = page[page.find("<title>")+7: page.find('</title>')]
        print("Get Page Title found: " + page_title)
        self.assertEqual("Policy Enforcement Point Interfaces", page_title)
        print("Get Page: OK!")

    def access_enforcement(self, id_token="filler"):
        #Create a new resource
        payload = { "resource_scopes":[ self.scopes ], "icon_uri":"/"+self.resourceName+"_access_enforcement", "name": self.resourceName+"_access_enforcement" }
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+str(id_token) }
        res = requests.post(self.PEP_RES_HOST+"/resources", headers=headers, json=payload, verify=False)
        resource_id = res.text

        #Access to the resource without token
        headers2 = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer filler" }
        res2 = requests.get(self.PEP_RES_HOST+"/resources/"+resource_id, headers=headers2, verify=False)
        print("Tried to access to the resource without token, return 500")
        self.assertEqual(500, res2.status_code)
        print("=======================")
        print("")

        #Access to the resource with token
        headers3 = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+str(id_token) }
        res3 = requests.get(self.PEP_RES_HOST+"/resources/"+resource_id, headers=headers3, verify=False)
        print("Tried to access to the resource with token, return 200")
        self.assertEqual(200, res3.status_code)

        #Delete resource
        headers4 = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        res4 = requests.delete(self.PEP_RES_HOST+"/resources/"+resource_id, headers=headers4, verify=False)

    #Monolithic test to avoid jumping through hoops to implement ordered tests
    #This test case assumes v0.3 of the PEP engine
    def test_resource(self):
        #Use a JWT token as id_token
        id_token = self.getJWT()
        id_token_ro = self.getJWT_RO()

        #Create resource
        status, self.resourceID = self.createTestResource(id_token)
        self.assertEqual(status, 200)
        print("Create resource: Resource created with id: "+self.resourceID)
        del status
        print("=======================")
        print("")

        #Get created resource
        status, reply = self.getResource(id_token)
        self.assertEqual(status, 200)
        #And we check if the returned id matches the id we got on creation
        #The reply message is in JSON format
        self.assertEqual(reply["_id"], self.resourceID)
        print("Get resource: Resource found.")
        print(reply)
        del status, reply
        print("=======================")
        print("")

        #Get resource list
        status, reply = self.getResourceList(id_token)
        self.assertEqual(status, 200)
        #And we finally check if the returned list contains our created resource
        #The reply message is a list of resources in JSON format
        found = False
        for r in reply:
            if r["_id"] == self.resourceID: found = True
        self.assertTrue(found)
        print("Get resource list: Resource found on Internal List.")
        print(reply)
        del status, reply
        print("=======================")
        print("")
        
        #Modify created resource
        #This will simply test if we can modify the pre-determined resource name with "Mod" at the end
        status, _ = self.updateResource(id_token)
        self.assertEqual(status, 200)
        #Get resource to check if modification actually was successfull
        status, reply = self.getResource(id_token)
        self.assertEqual(reply["_id"], self.resourceID)
        self.assertEqual(reply["_name"], self.resourceName+"Mod")
        print("Update resource: Resource properly modified.")
        print(reply)
        del status, reply
        print("=======================")
        print("")

        # Change ownership with user ROTEST but using admin jwt - should fail
        status, _ = self.updateResourceRO(id_token_ro)
        self.assertEqual(status, 403)
        del status
        print("Invalid Ownership Change request successfully denied")
        print("=======================")
        print("")

        # Test ownership with user ROTEST with ROTEST jwt - should succeed
        status, _ = self.updateResourceRO(id_token)
        self.assertEqual(status, 200)
        del status
        print("Valid Ownership Change request successfull")
        print("=======================")
        print("")

        # Delete created resource
        status, reply = self.deleteResource(id_token_ro)
        self.assertEqual(status, 204)
        print("Delete resource: Resource deleted.")
        del status, reply
        print("=======================")
        print("")

        #Get resource to make sure it was deleted
        status, _ = self.getResource(id_token)
        self.assertEqual(status, 404)
        print("Get resource: Resource correctly not found.")
        del status
        print("=======================")
        print("")

        #Get resource list to make sure the resource was removed from internal cache
        status, reply = self.getResourceList(id_token)
        self.assertEqual(status, 404)
        print("Get resource list: Resource correctly removed from Internal List.")
        print("=======================")
        print("")

        #Swagger UI Endpoint
        print("Swagger UI Endpoint ")
        self.swaggerUI()
        print("=======================")
        print("")

        #Access Enforcement
        print("Access Enforcement")
        self.access_enforcement(id_token)
        print("=======================")
        del status, reply, id_token
        print("")

if __name__ == '__main__':
    unittest.main()