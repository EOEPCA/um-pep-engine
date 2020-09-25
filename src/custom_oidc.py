#!/usr/bin/env python3

from base64 import b64encode
from WellKnownHandler import TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT, KEY_OIDC_USERINFO_ENDPOINT
from base64 import b64encode
import logging
import base64
import json

from requests import post

class OIDCHandler:

    def __init__(self, wkh, client_id: str, client_secret: str, redirect_uri: str, scopes, verify_ssl: bool = False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.wkh = wkh

    def get_new_pat(self):
        """
        Returns a new PAT
        """
        token_endpoint = self.wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)
        headers = {"content-type": "application/x-www-form-urlencoded", 'cache-control': "no-cache"}
        payload = "grant_type=client_credentials&client_id="+self.client_id+"&client_secret="+self.client_secret+"&scope="+" ".join(self.scopes).replace(" ","%20")+"&redirect_uri="+self.redirect_uri
        response = post(token_endpoint, data=payload, headers=headers, verify = self.verify_ssl)
        
        try:
            access_token = response.json()["access_token"]
        except Exception as e:
            print("Error while getting access_token: "+str(response.text))
            exit(-1)
        
        return access_token

    def verify_JWT_token(self, token, key):
        try:
            payload = str(token).split(".")[1]
            paddedPayload = payload + '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(paddedPayload)
            #to remove byte-code
            decoded = decoded.decode('utf-8')
            user_value = json.loads(decoded)[key]
            return user_value
        except Exception as e:
            print("Authenticated RPT Resource. No Valid JWT id token passed! " +str(e))
            return None

    def verify_OAuth_token(self, token, key):
        headers = { 'content-type': "application/json", 'Authorization' : 'Bearer '+token}
        url = self.wkh.get(TYPE_OIDC, KEY_OIDC_USERINFO_ENDPOINT )
        try:
            res = get(url, headers=headers, verify=False)
            user = (res.json())
            return user[key]
        except:
            print("OIDC Handler: Get User "+key+": Exception occured!")
            return None

    def verify_uid_headers(self, headers_protected, key):
        value = None
        #Retrieve the token from the headers
        for i in headers_protected:
            if 'Bearer' in str(i):
                aux_protected=headers_protected.index('Bearer')
                inputToken_protected = headers_protected[aux_protected+1]           
        token_protected = inputToken_protected
        if token_protected:
            #Compares between JWT id_token and OAuth access token to retrieve the requested key-value
            if len(str(token_protected))>40:
                value=self.verify_JWT_token(token_protected, key)
            else:
                value=self.verify_OAuth_token(token_protected, key)

            return value
        else:
            return 'NO TOKEN FOUND'

            
