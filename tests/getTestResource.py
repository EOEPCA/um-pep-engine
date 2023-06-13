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

config = {}
with open("../auth_proxy_server/logging/config.json") as j:
    g_config = json.load(j)

wkh = WellKnownHandler(g_config["auth_server_url"], secure=False)
__TOKEN_ENDPOINT = wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)

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
            "iss": g_config["client_id"],
            "sub": g_config["client_secret"],
            "aud": __TOKEN_ENDPOINT,
            "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
            "exp": int(time.time())+3600
        }
_jws = JWS(_payload, alg="RS256")
jwt = _jws.sign_compact(keys=[_rsajwk])

#payload = { "resource_scopes":[ "Authenticated"], "icon_uri":"/testResourcePEP", "name":"TestResourcePEP" }
headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer filler"  }
res = requests.get("http://localhost:5566/resources/1b107ef3-36f3-44d1-adb4-fe6a073d5db", headers=headers, verify=False)
print(res.status_code)
print(res.text)
print(res.headers)
ticket = res.headers["WWW-Authenticate"].split("ticket=")[1]

#Get RPT
headers = { 'content-type': "application/x-www-form-urlencoded", "cache-control": "no-cache"}
payload = { "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken", "claim_token": jwt, "ticket": ticket, "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket", "client_id": g_config["client_id"], "client_secret": g_config["client_secret"], "scope": 'Authenticated'}
res = requests.post(__TOKEN_ENDPOINT, headers=headers, data=payload, verify=False)
print(res.status_code)
rpt = res.json()["access_token"]

headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+rpt }
res = requests.get("http://localhost:5566/resources/1b107ef3-36f3-44d1-adb4-fe6a073d5db", headers=headers, verify=False)
print(res.status_code)
print(res.text)
print(res.headers)
print("JSON")
print(res.json())
