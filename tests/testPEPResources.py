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
        with open("../src/config/config.json") as j:
            cls.g_config = json.load(j)

        wkh = WellKnownHandler(cls.g_config["auth_server_url"], secure=False)
        cls.__TOKEN_ENDPOINT = wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)

        #Generate ID Token
        _rsakey = RSA.generate(2048)
        _private_key = _rsakey.exportKey()
        _public_key = _rsakey.publickey().exportKey()

        file_out = open("private.pem", "wb")
        file_out.write(_private_key)
        file_out.close()

        file_out = open("public.pem", "wb")
        file_out.write(_public_key)
        file_out.close()

        _rsajwk = RSAKey(kid='RSA1', key=import_rsa_key(_private_key))
        _payload = { 
                    "iss": cls.g_config["client_id"],
                    "sub": cls.g_config["client_secret"],
                    "aud": cls.__TOKEN_ENDPOINT,
                    "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
                    "exp": int(time.time())+3600
                }
        _jws = JWS(_payload, alg="RS256")
        cls.jwt = _jws.sign_compact(keys=[_rsajwk])
        cls.scopes = 'public_access'
        cls.resourceName = "TestResourcePEP"
        cls.PEP_HOST = "http://localhost:5566"
    
    @classmethod
    def tearDownClass(cls):
        os.remove("private.pem")
        os.remove("public.pem")

    def getRPTFromAS(self, ticket):
        headers = { 'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache"}
        payload = { "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken", "claim_token": self.jwt, "ticket": ticket, "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket", "client_id": self.g_config["client_id"], "client_secret": self.g_config["client_secret"], "scope": self.scopes}
        res = requests.post(self.__TOKEN_ENDPOINT, headers=headers, data=payload, verify=False)
        if res.status_code == 200:
            return 200, res.json()["access_token"]
        return 500, None

    def getResourceList(self, rpt="filler"):
        headers = { 'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache", "Authorization": "Bearer "+str(rpt)}
        res = requests.get(self.PEP_HOST+"/resources", headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["WWW-Authenticate"].split("ticket=")[1]
        if res.status_code == 200:
            return 200, res.json()
        return 500, None

    def createTestResource(self):
        payload = { "resource_scopes":[ self.scopes ], "icon_uri":"/"+self.resourceName, "name": self.resourceName }
        headers = { 'content-type': "application/json", "cache-control": "no-cache" }
        res = requests.post(self.PEP_HOST+"/resources/"+self.resourceName, headers=headers, json=payload, verify=False)
        if res.status_code == 200:
            return 200, res.text
        return 500, None

    def getResource(self, rpt="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+rpt }
        res = requests.get(self.PEP_HOST+"/resources/"+self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["WWW-Authenticate"].split("ticket=")[1]
        if res.status_code == 200:
            return 200, res.json()
        return 500, None

    def deleteResource(self, rpt="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+rpt }
        res = requests.delete(self.PEP_HOST+"/resources/"+self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["WWW-Authenticate"].split("ticket=")[1]
        if res.status_code == 204:
            return 204, None
        return 500, None

    def updateResource(self, rpt="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+rpt }
        payload = { "resource_scopes":[ self.scopes], "icon_uri":"/"+self.resourceName, "name":self.resourceName+"Mod" }
        res = requests.put(self.PEP_HOST+"/resources/"+self.resourceID, headers=headers, json=payload, verify=False)
        if res.status_code == 401:
            return 401, res.headers["WWW-Authenticate"].split("ticket=")[1]
        if res.status_code == 200:
            return 200, None
        return 500, None

    #Monolithic test to avoid jumping through hoops to implement ordered tests
    #This test case assumes UMA is in place
    def test_resource_UMA(self):
        #Create resource
        status, self.resourceID = self.createTestResource()
        self.assertEqual(status, 200)
        print("Create resource: Resource created with id: "+self.resourceID)
        del status
        print("=======================")
        print("")

        #Get created resource
        #First attempt should return a 401 with a ticket
        status, reply = self.getResource()
        self.assertNotEqual(status, 500)
        #Now we get a valid RPT from the Authorization Server
        status, rpt = self.getRPTFromAS(reply)
        self.assertEqual(status, 200)
        #Now we retry the first call with the valid RPT
        status, reply = self.getResource(rpt)
        self.assertEqual(status, 200)
        #And we finally check if the returned id matches the id we got on creation
        #The reply message is in JSON format
        self.assertEqual(reply["_id"], self.resourceID)
        print("Get resource: Resource found.")
        print(reply)
        del status, reply, rpt
        print("=======================")
        print("")

        #Get resource list
        #Same MO as above
        #First attempt should return a 401 with a ticket
        status, reply = self.getResourceList()
        self.assertNotEqual(status, 500)
        #Now we get a valid RPT from the Authorization Server
        status, rpt = self.getRPTFromAS(reply)
        self.assertEqual(status, 200)
        #Now we retry the first call with the valid RPT
        status, reply = self.getResourceList(rpt)
        self.assertEqual(status, 200)
        #And we finally check if the returned list contains our created resource
        #The reply message is a list of resources in JSON format
        found = False
        for r in reply:
            if r["_id"] == self.resourceID: found = True
        self.assertTrue(found)
        print("Get resource list: Resource found on Internal List.")
        print(reply)
        del status, reply, rpt
        print("=======================")
        print("")
        
        #Modify created resource
        #This will simply test if we can modify the pre-determined resource name with "Mod" at the end
        #The MO is the same as above tests, so no further comment
        status, reply = self.updateResource()
        self.assertNotEqual(status, 500)
        status, rpt = self.getRPTFromAS(reply)
        self.assertEqual(status, 200)
        status, _ = self.updateResource(rpt)
        self.assertEqual(status, 200)
        #Get resource to check if modification actually was successfull
        status, reply = self.getResource()
        status, rpt = self.getRPTFromAS(reply)
        status, reply = self.getResource(rpt)
        self.assertEqual(reply["_id"], self.resourceID)
        self.assertEqual(reply["name"], self.resourceName+"Mod")
        print("Update resource: Resource properly modified.")
        print(reply)
        del status, reply, rpt
        print("=======================")
        print("")

        #Delete created resource
        status, reply = self.deleteResource()
        self.assertNotEqual(status, 500)
        status, rpt = self.getRPTFromAS(reply)
        self.assertEqual(status, 200)
        status, reply = self.deleteResource(rpt)
        self.assertEqual(status, 204)
        print("Delete resource: Resource deleted.")
        del status, reply, rpt
        print("=======================")
        print("")

        #Get resource to make sure it was deleted
        status, _ = self.getResource()
        self.assertEqual(status, 500)
        print("Get resource: Resource correctly not found.")
        del status
        print("=======================")
        print("")

        #Get resource list to make sure the resource was removed from internal cache
        status, reply = self.getResourceList()
        status, rpt = self.getRPTFromAS(reply)
        status, reply = self.getResourceList(rpt)

        found = False
        for r in reply:
            if r["_id"] == self.resourceID: found = True
        self.assertFalse(found)
        print("Get resource list: Resource correctly removed from Internal List.")
        print(reply)
        del status, reply, rpt, found
        print("=======================")
        print("")

if __name__ == '__main__':
    unittest.main()