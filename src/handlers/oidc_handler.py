#!/usr/bin/env python3

from base64 import b64encode
from WellKnownHandler import TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT, KEY_OIDC_USERINFO_ENDPOINT
from handlers.uma_handler import rpt as class_rpt
from config import load_config
import logging
import base64
import json
from jwkest.jws import JWS
from jwkest.jwk import RSAKey, import_rsa_key_from_file
from jwt_verification.signature_verification import JWT_Verification

from requests import post, get


class OIDCHandler:

    def __init__(self, wkh, client_id: str, client_secret: str, redirect_uri: str, scopes, verify_ssl: bool = False):
        self.logger = logging.getLogger("PEP_ENGINE")
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
        payload = "grant_type=client_credentials&client_id=" + self.client_id + "&client_secret=" + self.client_secret + "&scope=" + " ".join(
            self.scopes).replace(" ", "%20") + "&redirect_uri=" + self.redirect_uri
        response = post(token_endpoint, data=payload, headers=headers, verify=self.verify_ssl)

        try:
            access_token = response.json()["access_token"]
        except Exception as e:
            self.logger.debug("Error while getting access_token: " + str(response.text))
            exit(-1)

        return access_token

    def verify_JWT_token(self, token, key):
        try:
            header = str(token).split(".")[0]
            paddedHeader = header + '=' * (4 - len(header) % 4)
            decodedHeader = base64.b64decode(paddedHeader)
            # to remove byte-code
            decodedHeader_format = decodedHeader.decode('utf-8')
            decoded_str_header = json.loads(decodedHeader_format)

            payload = str(token).split(".")[1]
            paddedPayload = payload + '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(paddedPayload)
            # to remove byte-code
            decoded = decoded.decode('utf-8')
            decoded_str = json.loads(decoded)

            if self.getVerificationConfig() == True:
                if decoded_str_header['kid'] != "RSA1":
                    verificator = JWT_Verification()
                    result = verificator.verify_signature_JWT(token)
                else:
                    # validate signature for rpt
                    rsajwk = RSAKey(kid="RSA1", key=import_rsa_key_from_file("config/public.pem"))
                    dict_rpt_values = JWS().verify_compact(token, keys=[rsajwk], sigalg="RS256")

                    if dict_rpt_values == decoded_str:
                        result = True
                    else:
                        result = False

                if result == False:
                    self.logger.debug("Verification of the signature for the JWT failed!")
                    raise Exception
                else:
                    self.logger.debug("Signature verification is correct!")

            user_value = None
            if decoded_str.get(key):
                user_value = decoded_str[key]
            elif decoded_str.get("pct_claims"):
                if decoded_str.get("pct_claims").get(key):
                    user_value = decoded_str['pct_claims'][key]
            if isinstance(user_value, list) and len(user_value) != 0 and user_value[0]:
                user_value = user_value[0]
            if user_value is None:
                raise Exception

            return user_value
        except Exception as e:
            self.logger.debug("Authenticated RPT Resource. No Valid JWT id token passed! " + str(e))
            return None

    def verify_OAuth_token(self, token, key):
        headers = {'content-type': "application/json", 'Authorization': 'Bearer ' + token}
        url = self.wkh.get(TYPE_OIDC, KEY_OIDC_USERINFO_ENDPOINT)
        try:
            res = get(url, headers=headers, verify=False)
            user = (res.json())
            return user[key]
        except:
            self.logger.debug("OIDC Handler: Get User " + key + ": Exception occured!")
            return None

    def verify_uid_headers(self, headers_protected, key):
        value = None
        token_protected = None
        # Retrieve the token from the headers
        for i in headers_protected:
            if 'Bearer' in str(i):
                aux_protected = headers_protected.index('Bearer')
                token_protected = headers_protected[aux_protected + 1]
        if token_protected:
            # Compares between JWT id_token and OAuth access token to retrieve the requested key-value
            if len(str(token_protected)) > 40:
                value = self.verify_JWT_token(token_protected, key)
            else:
                value = self.verify_OAuth_token(token_protected, key)

            return value
        else:
            return 'NO TOKEN FOUND'

    def getVerificationConfig(self):
        g_config = load_config("config/config.json")

        return g_config['verify_signature']
