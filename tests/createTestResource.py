import subprocess
import requests

payload = { "resource_scopes":[ "Authenticated"], "icon_uri":"/testResourcePEP", "name":"TestResourcePEP" }
headers = { 'content-type': "application/json", "cache-control": "no-cache" }
res = requests.post("http://localhost:5566/resources/TestResourcePEP", headers=headers, json=payload, verify=False)
print(res.status_code)
print(res.text)
print(res.headers)
resource_id = res.text