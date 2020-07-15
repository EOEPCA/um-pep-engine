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
        self.g_config = {}
        with open("../src/config/config.json") as j:
            self.g_config = json.load(j)

        wkh = WellKnownHandler(self.g_config["auth_server_url"], secure=False)
        self.__TOKEN_ENDPOINT = wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)

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
                    "iss": self.g_config["client_id"],
                    "sub": self.g_config["client_secret"],
                    "aud": self.__TOKEN_ENDPOINT,
                    "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
                    "exp": int(time.time())+3600
                }
        _jws = JWS(_payload, alg="RS256")
        self.jwt = _jws.sign_compact(keys=[_rsajwk])
        self.scopes = 'public_access'
        self.resourceName = "TestResourcePEP"
        self.PEP_HOST = "http://localhost:5566"
    
    @classmethod
    def tearDownClass(cls):
        os.remove(private.pem)
        os.remove(public.pem)

    def getRPTFromAS(self, ticket):
        headers = { 'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache"}
        payload = { "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken", "claim_token": self.jwt, "ticket": ticket, "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket", "client_id": self.g_config["client_id"], "client_secret": self.g_config["client_secret"], "scope": self.scopes}
        res = requests.post(self.__TOKEN_ENDPOINT, headers=headers, data=payload, verify=False)
        if res.status_code == 200:
            return 200, res.json()["access_token"]
        return 500, None

    def getResourceList(rpt="filler"):
        headers = { 'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache", "Authorization": "Bearer "+rpt}
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
        ticket = res.headers["WWW-Authenticate"].split("ticket=")[1]
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
        status, self.resourceID = createTestResource()
        assertEqual(status, 200)
        print("Resource created.")

        #Get created resource
        #First attempt should return a 401 with a ticket
        status, reply = getResource()
        assertNotEqual(status, 500)
        #Now we get a valid RPT from the Authorization Server
        status, rpt = getRPTFromAS(reply)
        assertEqual(status, 200)
        #Now we retry the first call with the valid RPT
        status, reply = getResource(rpt)
        assertEqual(status, 200)
        #And we finally check if the returned id matches the id we got on creation
        #The reply message is in JSON format
        assertEqual(reply["_id"], self.resourceID)
        print("Resource found.")

        #Get resource list
        #Same MO as above
        #First attempt should return a 401 with a ticket
        status, reply = getResourceList()
        assertNotEqual(status, 500)
        #Now we get a valid RPT from the Authorization Server
        status, rpt = getRPTFromAS(reply)
        assertEqual(status, 200)
        #Now we retry the first call with the valid RPT
        status, reply = getResourceList(rpt)
        assertEqual(status, 200)
        #And we finally check if the returned list contains our created resource
        #The reply message is a list of resources in JSON format
        found = False
        for r in reply:
            if r["_id"] == self.resourceID: found = True
        assertTrue(found)
        print("Resource found on List.")
        
        #Modify created resource
        #This will simply test if we can modify the pre-determined resource name with "Mod" at the end
        #The MO is the same as above tests, so no further comment
        status, reply = updateResource()
        assertNotEqual(status, 500)
        status, rpt = getRPTFromAS(reply)
        assertEqual(status, 200)
        status, reply = updateResource(rpt)
        assertEqual(status, 200)
        assertEqual(reply["name"], self.resourceName+"Mod")
        print("Resource properly modified.")

        #Delete created resource
        status, reply = deleteResource()
        assertNotEqual(status, 500)
        status, rpt = getRPTFromAS(reply)
        assertEqual(status, 200)
        status, reply = deleteResource(rpt)
        assertEqual(status, 204)
        print("Resource deleted.")

        #Get resource to make sure it was deleted
        status, _ = getResource()
        assertEqual(status, 500)
        print("Resource correctly not found.")

        #Get resource list to make sure the resource was removed from internal cache
        status, reply = getResourceList()
        status, rpt = getRPTFromAS(reply)
        status, reply = getResourceList(rpt)

        found = False
        for r in reply:
            if r["_id"] == self.resourceID: found = True
        assertFalse(found)
        print("Resource removed from List.")