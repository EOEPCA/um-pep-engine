import datetime
import json
import os
import time
import unittest

import requests
from Crypto.PublicKey import RSA
from WellKnownHandler import WellKnownHandler, TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT
from jwkest.jwk import RSAKey, import_rsa_key
from jwkest.jws import JWS


class ROChangeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g_config = {}
        with open("../keycloak_setup/logging/config.json") as j:
            cls.g_config = json.load(j)

        wkh = WellKnownHandler(cls.g_config["auth_server_url"], secure=False)
        cls.__TOKEN_ENDPOINT = wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)

        # Generate ID Token
        _rsakey = RSA.generate(2048)
        _private_key = _rsakey.exportKey()
        _public_key = _rsakey.publickey().exportKey()

        file_out = open("private.pem", "wb")
        file_out.write(_private_key)
        file_out.close()

        file_out = open("public.pem", "wb")
        file_out.write(_public_key)
        file_out.close()

        # Admin JWT
        _rsajwk = RSAKey(kid='RSA1', key=import_rsa_key(_private_key))
        _payload = {
            "iss": cls.g_config["client_id"],
            "sub": cls.g_config["client_id"],
            "aud": cls.__TOKEN_ENDPOINT,
            "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
            "exp": int(time.time()) + 3600,
            "isOperator": False
        }
        _jws = JWS(_payload, alg="RS256")
        cls.jwt_admin = _jws.sign_compact(keys=[_rsajwk])

        # ROTest user JWT
        _payload = {
            "iss": cls.g_config["client_id"],
            "sub": "54d10251-6cb5-4aee-8e1f-f492f1105c94",
            "aud": cls.__TOKEN_ENDPOINT,
            "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
            "exp": int(time.time()) + 3600,
            "isOperator": False
        }
        _jws = JWS(_payload, alg="RS256")
        cls.jwt_rotest = _jws.sign_compact(keys=[_rsajwk])

        cls.scopes = 'public_access'
        cls.resourceName = "TestROChangePEP"
        cls.PEP_HOST = "http://localhost:5566"

    @classmethod
    def tearDownClass(cls):
        os.remove("private.pem")
        os.remove("public.pem")

    def getJWTAdmin(self):
        return self.jwt_admin

    def getJWTROTest(self):
        return self.jwt_rotest

    def createTestResource(self, id_token="filler"):
        payload = {"resource_scopes": [self.scopes], "icon_uri": "/" + self.resourceName, "name": self.resourceName}
        headers = {'content-type': "application/json", "cache-control": "no-cache",
                   "Authorization": "Bearer " + str(id_token)}
        res = requests.post(self.PEP_HOST + "/resources/" + self.resourceName, headers=headers, json=payload,
                            verify=False)
        if res.status_code == 200:
            return 200, res.text
        return 500, None

    def getResource(self, id_token="filler"):
        headers = {'content-type': "application/json", "cache-control": "no-cache",
                   "Authorization": "Bearer " + id_token}
        res = requests.get(self.PEP_HOST + "/resources/" + self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 200:
            return 200, res.json()
        if res.status_code == 404:
            return 404, res.headers["Error"]
        return 500, None

    def deleteResource(self, id_token="filler"):
        headers = {'content-type': "application/json", "cache-control": "no-cache",
                   "Authorization": "Bearer " + id_token}
        res = requests.delete(self.PEP_HOST + "/resources/" + self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 403:
            return 403, res.headers["Error"]
        if res.status_code == 204:
            return 204, None
        return 500, None

    def updateResource(self, id_token="filler"):
        headers = {'content-type': "application/json", "cache-control": "no-cache",
                   "Authorization": "Bearer " + id_token}
        payload = {"resource_scopes": [self.scopes], "icon_uri": "/" + self.resourceName, "name": self.resourceName,
                   "ownership_id": "54d10251-6cb5-4aee-8e1f-f492f1105c94"}
        res = requests.put(self.PEP_HOST + "/resources/" + self.resourceID, headers=headers, json=payload, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 403:
            return 403, res.headers["Error"]
        if res.status_code == 200:
            return 200, None
        return 500, None

    # Monolithic test to avoid jumping through hoops to implement ordered tests
    # This test case assumes v0.3 of the PEP engine
    def test_resource(self):
        # Use a JWT token as id_token
        id_token_admin = self.getJWTAdmin()
        id_token_rotest = self.getJWTROTest()

        # Create resource with owner ADMIN
        status, self.resourceID = self.createTestResource(id_token_admin)
        self.assertEqual(status, 200)
        print("Create resource: Resource created with id: " + self.resourceID)
        del status
        print("=======================")
        print("")

        # self.resourceID = "7dec4bd4-e6c2-4b4e-9425-3d720cc8b33d"

        # Change ownership with user ROTEST - should fail
        status, _ = self.updateResource(id_token_rotest)
        self.assertEqual(status, 403)
        del status
        print("Invalid Ownership Change request successfully denied")
        print("=======================")
        print("")

        # Change ownership with user ADMIN - should succeed
        status, _ = self.updateResource(id_token_admin)
        self.assertEqual(status, 200)
        del status
        print("Valid Ownership Change request successfull")
        print("=======================")
        print("")

        # Delete created resource
        status, reply = self.deleteResource(id_token_rotest)
        self.assertEqual(status, 204)
        print("Delete resource: Resource deleted.")
        del status, reply
        print("=======================")
        print("")


if __name__ == '__main__':
    unittest.main()
