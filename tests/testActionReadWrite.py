import unittest
import subprocess
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
import os
sys.path.append('../src/')
from handlers.policy_handler import policy_handler

class PEPProtectedAction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open("../src/config/config.json") as j:
            cls.g_config = json.load(j)

        headers = { 'cache-control': "no-cache" }
        data = {
            "scope": "openid user_name eoepca is_operator",
            "grant_type": "password",
            "username": "admin",
            "password": "admin_Abcd1234#",
            "client_id": cls.g_config["client_id"],
            "client_secret": cls.g_config["client_secret"]
        }
        session = requests.Session()
        r = session.post("https://test.10.0.2.15.nip.io/oxauth/restv1/token", headers=headers, data=data, verify=False)
        #print(r.json())
        id_token = r.json()["id_token"]
        oauth_token = r.json()["access_token"]
        cls.jwt_id = id_token

        headers2 = { 'cache-control': "no-cache" }
        data2 = {
            "scope": "openid user_name eoepca is_operator",
            "grant_type": "password",
            "username": "UserAction",
            "password": "useractionpass",
            "client_id": cls.g_config["client_id"],
            "client_secret": cls.g_config["client_secret"]
        }
        session2 = requests.Session()
        r2 = session2.post("https://test.10.0.2.15.nip.io/oxauth/restv1/token", headers=headers2, data=data2, verify=False)
        id_token2 = r2.json()["id_token"]
        oauth_token2 = r2.json()["access_token"]
        cls.jwt_id2 = id_token2

        cls.PEP_HOST = "http://localhost:5566"
        cls.PEP_RES_HOST = "http://localhost:5576"
        cls.icon_uri_var = "Resource1"
       
    def getJWT(self):
        return self.jwt_id

    def getJWT2(self):
        return self.jwt_id2

    def createTestResource(self, id_token):
        payload = { "resource_scopes":[], "icon_uri":"/"+self.icon_uri_var, "name":"TestResourcePEP" }
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        res = requests.post(self.PEP_RES_HOST+"/resources", headers=headers, json=payload, verify=False)
        if res.status_code == 200:
            return 200, res.text
        return 500, None

    def generateTicket(self, id_token, action_type):
        print("\nGenerating the ticket for protected_" + action_type)
        payload = { "resource_scopes":[], "icon_uri":"/"+self.icon_uri_var, "name":"TestResourcePEP" }
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token  }

        if action_type == "read":
            res = requests.get(self.PEP_HOST+"/"+self.icon_uri_var, headers=headers, data=payload, verify=False)
        elif action_type == "write":
            res = requests.post(self.PEP_HOST+"/"+self.icon_uri_var, headers=headers, data=payload, verify=False)

        ticket = res.headers["WWW-Authenticate"].split("ticket=")[1]

        if res.status_code == 401:
            return 401, ticket
        return 500, None
    
    def getRPT(self, ticket, jwt_id, action_type):
        print("Trying with RPT Token for protected_"+action_type)

        #Generate RPT
        os.system('bash rpt.sh -t '+ticket+' -c '+jwt_id+' -e '+self.g_config["client_id"]+' -k '+self.g_config["client_secret"]+' >/dev/null 2>&1')

        with open("rpt.txt") as rpt:
            rpt_json = json.load(rpt)

        if "error" in rpt_json.keys():
            if rpt_json["error"] ==  "forbidden_by_policy":
                return 403, rpt_json["error_description"]


        rpt_token = rpt_json["access_token"]

        payload = {"icon_uri":"/"+self.icon_uri_var, "name":"TestResourcePEP" }
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+rpt_token}
        
        if action_type == "read":
            res = requests.get(self.PEP_HOST+"/"+self.icon_uri_var, headers=headers, data=payload, verify=False)
        elif action_type == "write":
            res = requests.post(self.PEP_HOST+"/"+self.icon_uri_var, headers=headers, data=payload, verify=False)

        if res.status_code == 401:
            return 401, res.text
        if res.status_code == 200:
            return 200, None
        return 500, None

    def updatePolicy(self, resource_id, uid, action, jwt_id):
        print("\nModifying the policy "+action)
        name = "Default Ownership Policy of " + str(resource_id) + " with action " + action
        description = "This is the default ownership policy for created resources through PEP"
    
        if action == "read":
            scopes = ["protected_read"]
            policy_cfg =  { "resource_id": resource_id, "action": action, "rules": [] }
        else:
            scopes = ["protected_access"]

        body_policy = {"name": name, "description": description, "config": policy_cfg, "scopes": scopes}

        pdp_policy_handler = policy_handler(pdp_url=self.g_config["pdp_url"], pdp_port=self.g_config["pdp_port"], pdp_policy_endpoint=self.g_config["pdp_policy_endpoint"])
        headers_policy = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+jwt_id}
        policy_reply = pdp_policy_handler.create_policy(policy_body=body_policy, input_headers=headers_policy)

        if policy_reply.status_code == 401:
            return 401, res.headers["Error"]
        if policy_reply.status_code == 200:
            return 200, None
        return 500, None

    def get_uid_from_jwt(self, jwt_id):
        payload = str(jwt_id).split(".")[1]
        paddedPayload = payload + '=' * (4 - len(payload) % 4)
        decoded = base64.b64decode(paddedPayload)
        ownership = json.loads(decoded)["sub"]

        return ownership

    def deleteResource(self, id_token="filler"):
        print("\nDeleting the resource...")
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token}
        res = requests.delete(self.PEP_RES_HOST+"/resources/"+self.resourceID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 204:
            return 204, None
        return 500, None

    #Monolithic test to avoid jumping through hoops to implement ordered tests
    def test_action(self):
        #Use a JWT token as id_token
        id_token = self.getJWT()

        print("")
        #Create resource
        status, self.resourceID = self.createTestResource(id_token)
        self.assertEqual(status, 200)
        print("Create resource: Resource created with id: "+self.resourceID)
        del status
        print("=======================")
        print("")

        #-----------------------------------------------------------------------

        #Generate Ticket for GET
        print("Creating ticket for user: admin")
        status, ticket_read = self.generateTicket(id_token, "read")
        self.assertEqual(status, 401)
        del status
        print("")

        #Generate RPT for GET
        status, reply = self.getRPT(ticket_read, id_token, "read")
        self.assertEqual(status, 200)
        print("Access granted to user: admin")
        del status
        print("=======================")
        print("")

        #------------------------------------------------------------------------

        #Generate Ticket for POST
        print("Creating ticket for user: admin")
        status, ticket_write = self.generateTicket(id_token, "write")
        self.assertEqual(status, 401)
        del status
        print("")

        #Generate RPT for POST
        status, reply = self.getRPT(ticket_write, id_token, "write")
        self.assertEqual(status, 200)
        print("")
        print("Access granted to user: admin")
        del status
        print("=======================")
        print("")

        #-----------------------------------------------------------------------

        #Use a JWT token as id_token
        id_token2 = self.getJWT2()

        #Generate Ticket for GET
        print("Creating ticket for user and trying to access to the read policy: UserAction")
        status, ticket_read = self.generateTicket(id_token2, "read")
        self.assertEqual(status, 401)
        del status
        print("")

        #Generate RPT for GET
        status, reply = self.getRPT(ticket_read, id_token2, "read")
        print("")
        print("Access denied to user: UserAction")
        print("Error code: "+str(status)+" "+reply)
        self.assertEqual(status, 403)
        del status
        print("=======================")
        print("")

        #-----------------------------------------------------------------------

        #Update read policy
        ow_id = self.get_uid_from_jwt(id_token)
        status, reply = self.updatePolicy(self.resourceID, ow_id, "read", id_token)
        self.assertEqual(status, 200)
        del status
        print("")
        print("")
        print("=======================")

        #-----------------------------------------------------------------------

        #Generate Ticket for GET
        print("Creating ticket for user and trying to access to the read policy again after modified the policy read: UserAction")
        status, ticket_read2 = self.generateTicket(id_token2, "read")
        self.assertEqual(status, 401)
        del status
        print("")

        #Generate RPT for GET
        status, reply = self.getRPT(ticket_read2, id_token2, "read")
        self.assertEqual(status, 200)
        print("")
        print("Access granted to user: UserAction to the policy read modified")
        del status
        print("=======================")
        print("")

        #-----------------------------------------------------------------------

        #Generate Ticket for GET
        print("Creating ticket for user and trying to access to the write policy again: UserAction")
        status, ticket_read2 = self.generateTicket(id_token2, "write")
        self.assertEqual(status, 401)
        del status
        print("")

        #Generate RPT for GET
        status, reply = self.getRPT(ticket_read2, id_token2, "write")
        self.assertEqual(status, 403)
        print("")
        print("Access denied to user: UserAction")
        print("Error code: "+str(status)+" "+reply)
        del status
        print("=======================")
        print("")

        #-----------------------------------------------------------------------

        # Delete created resource
        status, reply = self.deleteResource(id_token)
        self.assertEqual(status, 204)
        print("Delete resource: Resource deleted.")
        del status, reply
        print("=======================")
        print("")

        # Remove rpt.txt file
        os.remove("rpt.txt")

if __name__ == '__main__':
    unittest.main()

