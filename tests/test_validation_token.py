import requests
import datetime
import json
import time

import requests
from Crypto.PublicKey import RSA
from WellKnownHandler import WellKnownHandler, TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT
from jwkest.jwk import RSAKey, import_rsa_key
from jwkest.jws import JWS


class PEPResourceTest:
    def __init__(self):
        self.g_config = {}
        with open("../keycloak_setup/logging/config.json") as j:
            self.g_config = json.load(j)
        wkh = WellKnownHandler(self.g_config["auth_server_url"], secure=False)
        self.__TOKEN_ENDPOINT = wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)
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
        _rsajwk = RSAKey(kid='RSA1', key=import_rsa_key(_private_key))
        _payload = {
            "iss": self.g_config["client_id"],
            "sub": self.g_config["client_secret"],
            "aud": self.__TOKEN_ENDPOINT,
            "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
            "exp": int(time.time()) + 3600
        }
        _jws = JWS(_payload, alg="RS256")
        self.jwt = _jws.sign_compact(keys=[_rsajwk])
        self.scopes = 'public_access'
        self.resourceName = "TestResourcePEP10"
        self.PEP_HOST = "http://localhost:5566"
        status, self.resourceID = self.createTestResource()
        print(self.jwt)
        print(self.resourceID)

    def getRPTFromAS(self, ticket):
        headers = {'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache"}
        payload = {"claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
                   "claim_token": self.jwt, "ticket": ticket,
                   "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket", "client_id": self.g_config["client_id"],
                   "client_secret": self.g_config["client_secret"], "scope": self.scopes}
        res = requests.post(self.__TOKEN_ENDPOINT, headers=headers, data=payload, verify=False)
        if res.status_code == 200:
            return 200, res.json()["access_token"]
        return 500, None

    def getResourceList(self, rpt="filler"):
        headers = {'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache",
                   "Authorization": "Bearer " + str(rpt)}
        res = requests.get(self.PEP_HOST + "/resources", headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["WWW-Authenticate"].split("ticket=")[1]
        if res.status_code == 200:
            return 200, res.json()
        return 500, None

    def createTestResource(self):
        payload = {"resource_scopes": [self.scopes], "icon_uri": "/" + self.resourceName, "name": self.resourceName}
        headers = {'content-type': "application/json", "cache-control": "no-cache",
                   "Authorization": "Bearer " + self.jwt}
        res = requests.post(self.PEP_HOST + "/resources/" + self.resourceName, headers=headers, json=payload,
                            verify=False)
        if res.status_code == 200:
            return 200, res.text
        return 500, None

    def getResource(self, rpt="filler"):
        headers = {'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer " + rpt}
        res = requests.get(self.PEP_HOST + "/resources/" + self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["WWW-Authenticate"].split("ticket=")[1]
        if res.status_code == 200:
            return 200, res.json()
        return 500, None

    def deleteResource(self, rpt="filler"):
        headers = {'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer " + rpt}
        res = requests.delete(self.PEP_HOST + "/resources/" + self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["WWW-Authenticate"].split("ticket=")[1]
        if res.status_code == 204:
            return 204, None
        return 500, None

    def updateResource(self, rpt="filler"):
        headers = {'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer " + rpt}
        payload = {"resource_scopes": [self.scopes], "icon_uri": "/" + self.resourceName,
                   "name": self.resourceName + "Mod"}
        res = requests.put(self.PEP_HOST + "/resources/" + self.resourceID, headers=headers, json=payload, verify=False)
        if res.status_code == 401:
            return 401, res.headers["WWW-Authenticate"].split("ticket=")[1]
        if res.status_code == 200:
            return 200, None
        return 500, None

    # Monolithic test to avoid jumping through hoops to implement ordered tests
    # This test case assumes UMA is in place
    def test_resource_UMA(self):
        # Create resource
        status, self.resourceID = self.createTestResource()
        self.assertEqual(status, 200)
        print("Create resource: Resource created with id: " + self.resourceID)
        del status
        print("=======================")
        print("")
        # Get created resource
        # First attempt should return a 401 with a ticket
        status, reply = self.getResource()
        self.assertNotEqual(status, 500)
        # Now we get a valid RPT from the Authorization Server
        status, rpt = self.getRPTFromAS(reply)
        self.assertEqual(status, 200)
        # Now we retry the first call with the valid RPT
        status, reply = self.getResource(rpt)
        self.assertEqual(status, 200)
        # And we finally check if the returned id matches the id we got on creation
        # The reply message is in JSON format
        self.assertEqual(reply["_id"], self.resourceID)
        print("Get resource: Resource found.")
        print(reply)
        del status, reply, rpt
        print("=======================")
        print("")


if __name__ == '__main__':
    test = PEPResourceTest()

    status, reply = test.getResource(test.jwt)
    print(reply)
    if reply["_id"] == test.resourceID: print("Get resource found")
    print("=======================")
    status, reply = test.getResourceList(test.jwt)
    print("\n")
    print(reply)
    for r in reply:
        if r["_id"] == test.resourceID: print("Get resource list: Resource found on Internal List.")
    print("=======================")
    status, _ = test.updateResource(test.jwt)
    # Get resource to check if modification actually was successfull
    status, reply = test.getResource(test.jwt)
    if reply["_id"] == test.resourceID and reply["name"] == test.resourceName + "Mod": print(
        "Update resource: Resource properly modified.")
    print("\n")
    print(reply)
    print("=======================")
    print("")
