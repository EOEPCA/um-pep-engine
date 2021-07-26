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

        _rsajwk = RSAKey(kid="RSA1", key=import_rsa_key_from_file("../src/config/private.pem"))
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

        cls.jwt = _jws.sign_compact(keys=[_rsajwk])
        cls.scopes = ''
        cls.resourceName = "TestAuthorizePEP001"
        cls.PEP_HOST = "http://localhost:5566"
        cls.PEP_RES_HOST = "http://localhost:5576"
       
    def getJWT(self):
        return self.jwt

    def getJWT_RO(self):
        return self.jwt_rotest

    def createTestResource(self, id_token="filler"):
        payload = { "resource_scopes":[ self.scopes ], "icon_uri":"/test/"+self.resourceName, "name": self.resourceName }
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+str(id_token), "X-Original-Method": "POST" }
        res = requests.post(self.PEP_HOST+"/authorize", headers=headers, json=payload, verify=False)
        if res.status_code == 200:
            return 200, res.text
        return 500, None

    def getResource(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token, "X-Original-Method": "GET", "X-Original-Uri": "/test/"+self.resourceName }
        res = requests.get(self.PEP_HOST+"/authorize", headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 200:
            return 200, res.json()
        if res.status_code == 404:
            return 404, res.headers["Error"]
        return 500, None

    def deleteResource(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token, "X-Original-Method": "DELETE", "X-Original-Uri": "/test/"+self.resourceName }
        res = requests.delete(self.PEP_HOST+"/authorize", headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 204:
            return 204, None
        return 500, None

    #Monolithic test to avoid jumping through hoops to implement ordered tests
    #This test case assumes v0.9.1 of the PEP engine
    def test_resource(self):
        #Use a JWT token as id_token
        id_token = self.getJWT()

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

if __name__ == '__main__':
    unittest.main()