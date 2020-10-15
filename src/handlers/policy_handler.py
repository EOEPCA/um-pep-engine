#!/usr/bin/env python3
from requests import post

class policy_handler:

    def __init__(self, pdp_url: str, pdp_port: int, pdp_policy_endpoint: str):
        self.url = pdp_url
        self.port = pdp_port
        self.endpoint = pdp_policy_endpoint

    def create_policy(self, policy_body, jwt, ownership_id):
        headers = { 'content-type': "application/json", 'Authorization': 'Bearer '+str(jwt)}
        data = policy_body
        return post(self.url+':'+self.port+"/"+self.endpoint, headers=headers, data=data)