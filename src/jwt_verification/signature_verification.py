import base64
import json

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from jwkest.jwk import KEYS
from jwkest.jws import JWS
from config import load_config


class JWT_Verification():

    def __init__(self):
        self.SIGKEYS = KEYS()
        keys_json = self.getKeys_JWT()
        self.SIGKEYS.load_dict(keys_json)

    def verify_signature_JWT(self, jwt):
        symkeys = [k for k in self.SIGKEYS if k.alg == "RS256"]

        _rj = JWS()
        info = _rj.verify_compact(jwt, symkeys)
        decoded_json = self.decode_JWT(jwt)

        if info == decoded_json:
            return True
        else:
            return False

    def getKeys_JWT(self):
        g_config = load_config("./config/config.json")

        headers = {'content-type': "application/json", "cache-control": "no-cache"}
        res = requests.get(g_config["auth_server_url"] + "/oxauth/restv1/jwks", headers=headers, verify=False)

        json_dict = json.loads(res.text)
        return json_dict

    def decode_JWT(self, jwt):
        payload = str(jwt).split(".")[1]
        paddedPayload = payload + '=' * (4 - len(payload) % 4)
        decoded = base64.b64decode(paddedPayload)
        decoded_json = json.loads(decoded)

        return decoded_json
