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
        # sub is inum for a user, in this case admin
        _payload = { 
                    "iss": "25611146-fee4-4454-b84b-b4b5010f516b",
                    "sub": "25611146-fee4-4454-b84b-b4b5010f516b",
                    "aud": cls.__TOKEN_ENDPOINT,
                    "user_name": "admin",
                    "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
                    "exp": int(time.time())+3600,
                    "isOperator": True
                }
        _jws = JWS(_payload, alg="RS256")

        cls.jwt = _jws.sign_compact(keys=[_rsajwk])
        cls.scopes = ''
        cls.resourceName = "TestAuthorizePEP101"
        cls.PEP_HOST = "http://localhost:5566"
        cls.PEP_RES_HOST = "http://localhost:5576"
       
    def getJWT(self):
        return self.jwt

    def getJWT_RO(self):
        return self.jwt_rotest

    def createTestResource(self, id_token="filler"):
        payload = { "resource_scopes":[ self.scopes ], "icon_uri":"/test/"+self.resourceName, "name": self.resourceName }
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+str(id_token)}
        res = requests.post(self.PEP_RES_HOST+"/resources", headers=headers, json=payload, verify=False)
        if res.status_code == 200:
            return 200, res.json()["id"]
        return 500, None

    def getResourceAuthorize(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token, "X-Original-Method": "GET", "X-Original-Uri": "/test/"+self.resourceName }
        res = requests.get(self.PEP_HOST+"/authorize", headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers
        if res.status_code == 200:
            return 200, None
        if res.status_code == 404:
            return 404, res.headers["Error"]
        return 500, None

    def getResource(self, token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+token }
        res = requests.get(self.PEP_RES_HOST+"/resources/"+self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 200:
            return 200, res.json()
        if res.status_code == 404:
            return 404, res.headers["Error"]
        return 500, None

    def deleteResourceAuthorize(self, token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+token, "X-Original-Method": "DELETE", "X-Original-Uri": "/test/"+self.resourceName }
        res = requests.delete(self.PEP_HOST+"/authorize", headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 204:
            return 204, None
        return 500, None

    def deleteResource(self, token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+token }
        res = requests.delete(self.PEP_RES_HOST+"/resources/"+self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 204:
            return 204, None
        return 500, None

    def getRPT(self, id_token, ticket):
        headers = { 'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache"}
        payload = { "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken", "claim_token": id_token, "ticket": ticket, "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket", "client_id": self.g_config["client_id"], "client_secret": self.g_config["client_secret"], "scope": 'Authenticated'}
        res = requests.post(self.__TOKEN_ENDPOINT, headers=headers, data=payload, verify=False)
        return res.json()["access_token"]

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

        #self.resourceID = "ec46567e-f0de-4216-9a19-066ec5eaf650"

        #Get created resource authorization
        status, reply = self.getResourceAuthorize(id_token)
        #First attempt should return a ticket, so we test for a 401 containing it
        print("Reply status: " + str(status))
        self.assertTrue("WWW-Authenticate" in reply)
        print("Ticket correctly detected!")
        ticket = reply["WWW-Authenticate"].split("ticket=")[1]
        #Get RPT from id_token and ticket
        rpt = self.getRPT(id_token, ticket)
        #Repeat request, but now with the rpt
        status, reply = self.getResourceAuthorize(rpt)
        
        self.assertEqual(status, 200)
        # This means we have authorization
        print("Get resource authorization: Success.")
        del status
        print("=======================")
        print("")

        # Delete created resource
        status, reply = self.deleteResource(id_token)
        self.assertEqual(status, 204)
        print("Delete resource: Resource deleted.")
        del status, reply
        print("=======================")
        print("")

if __name__ == '__main__':
    unittest.main()