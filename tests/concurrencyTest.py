from multiprocessing import Process

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

n_threads = 60
token_ep = "https://demoexample.gluu.org/oxauth/restv1/token"
pep = '10.104.167.58'
resources_ep = 'http://' + pep + ':5576/resources'
proxy_ep = 'http://' + pep + ':5566'
client_id = "99466173-3148-4278-821b-54b3f38b0c2e"
client_secret = "908183bc-c07c-4f9f-ab4e-0ed0a8f025b5"


# Returns JWT Token for specific user and client
def get_jwt(client_id, client_secret):
    headers = {'cache-control': "no-cache"}
    data = {
        "scope": "openid user_name is_operator profile permission clientinfo",
        "grant_type": "password",
        "username": "admin",
        "password": "admin_Abcd1234#",
        "client_id": client_id,
        "client_secret": client_secret
    }
    r = requests.post(token_ep, headers=headers, data=data, verify=False)
    id_token = r.json()["id_token"]
    return id_token


def uma_flow_single_resource():
    # Requesting ticket (Expected code: 401)
    ticket_response = requests.get(proxy_ep + "/res", verify=False)
    ticket = ticket_response.headers["WWW-Authenticate"].split("ticket=")[1]
    assert ticket_response.status_code == 401
    # Requesting RPT (Expected code: 200)
    data = "claim_token_format=http://openid.net/specs/openid-connect-core-1_0.html#IDToken&claim_token=" + jwt + "&ticket=" + ticket + "&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket&client_id=" + client_id + "&client_secret=" + client_secret + "&scope=openid"
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'cache-control': 'no-cache'}
    rpts_response = requests.post(token_ep, data=data, headers=headers, verify=False)
    rpt = rpts_response.json()["access_token"]
    assert rpts_response.status_code == 200
    # Accessing resource (Expected code: 500)
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + str(rpt)}
    resource_response = requests.get(proxy_ep + "/res", headers=headers, verify=False)
    assert resource_response.status_code == 500


def uma_flow(u):
    # Inserting resource (Expected code: 200/422)
    data = {"icon_uri": "/res" + str(u), "name": "resource" + str(u), "scopes": ["protected_access"]}
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + str(jwt)}
    insertion_response = requests.post(resources_ep, json=data, headers=headers, verify=False)
    assert insertion_response.status_code in [200, 422]
    # Requesting ticket (Expected code: 401)
    ticket_response = requests.get(proxy_ep + "/res" + str(u), verify=False)
    ticket = ticket_response.headers["WWW-Authenticate"].split("ticket=")[1]
    assert ticket_response.status_code == 401
    # Requesting RPT (Expected code: 200)
    data = "claim_token_format=http://openid.net/specs/openid-connect-core-1_0.html#IDToken&claim_token=" + jwt + "&ticket=" + ticket + "&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket&client_id=" + client_id + "&client_secret=" + client_secret + "&scope=openid"
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'cache-control': 'no-cache'}
    rpts_response = requests.post(token_ep, data=data, headers=headers, verify=False)
    rpt = rpts_response.json()["access_token"]
    assert rpts_response.status_code == 200
    # Accessing resource (Expected code: 500)
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + str(rpt)}
    resource_response = requests.get(proxy_ep + "/res" + str(u), headers=headers, verify=False)
    assert resource_response.status_code == 500


jwt = get_jwt(client_id, client_secret)
n = []
single_res = []
# Inserting resource (Expected code: 200/422)
data = {"icon_uri": "/res", "name": "resource", "scopes": ["protected_access"]}
headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + str(jwt)}
insertion_response = requests.post(resources_ep, json=data, headers=headers, verify=False)
assert insertion_response.status_code in [200, 422]
print("Setting up " + str(n_threads) + " concurrent requests")
for i in range(n_threads):
    # n.append(Process(target=uma_flow,args=(i,)))
    single_res.append(Process(target=uma_flow_single_resource))
# print("Starting all threads...")
# for i in n:
#     i.start()
# for i in n:
#     i.join()
print("All processes have been succesfully completed")
print("Starting " + str(n_threads) + ' different rpts for same resource')
for i in single_res:
    i.start()
for i in single_res:
    i.join()
print("Finished")
