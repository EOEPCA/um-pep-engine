import json

from flask import jsonify
from keycloak import KeycloakOpenID, KeycloakOpenIDConnection, KeycloakAdmin, KeycloakUMA, ConnectionManager, \
    urls_patterns
from keycloak.exceptions import raise_error_from_response, KeycloakGetError, KeycloakPostError, KeycloakPutError


class KeycloakClient:

    def __init__(self, server_url, realm, resource_server, username, password, init=False):
        self.server_url = server_url
        self.realm = realm
        self.resource_server = resource_server
        openid_connection = KeycloakOpenIDConnection(
            server_url=server_url,
            username=username,
            password=password,
            verify=True)
        self.keycloak_admin = KeycloakAdmin(connection=openid_connection)
        self.admin_client = None
        self.resources_client = None
        self.keycloak_uma = None
        self.keycloak_uma_openid = None
        if init:
            self.init()

    def init(self):
        if self.realm != "master":
            self.keycloak_admin.create_realm(payload={"realm": self.realm, "enabled": True}, skip_exists=True)
            self.keycloak_admin.realm_name = self.realm
        admin_client_id = self.keycloak_admin.get_client_id('admin-cli')
        self.admin_client = self.keycloak_admin.get_client(admin_client_id)
        self.resources_client = self.register_resources_client("resources")
        # we have one admin client to do admin REST API calls
        openid_connection = KeycloakOpenIDConnection(
            server_url=self.server_url,
            user_realm_name="master",
            realm_name=self.realm,
            username=self.keycloak_admin.username,
            password=self.keycloak_admin.password,
            client_id=self.admin_client.get('clientId'),
            verify=True)
        self.keycloak_admin = KeycloakAdmin(connection=openid_connection)
        # we have one resources client to do resource REST API calls
        self.keycloak_uma = KeycloakUMA(connection=KeycloakOpenIDConnection(
            server_url=self.server_url,
            realm_name=self.realm,
            client_id=self.resources_client.get('clientId'),
            client_secret_key=self.resources_client.get('secret'),
            verify=True))
        self.keycloak_uma_openid = KeycloakOpenID(server_url=self.server_url,
                                                  realm_name=self.realm,
                                                  client_id=self.resources_client.get('clientId'),
                                                  client_secret_key=self.resources_client.get('secret'))


    def register_resources(self, resources):
        for resource in resources:
            self.register_resource(resource)


    def register_resource(self, resource):
        client_id = self.resources_client.get('id')
        response = self.keycloak_admin.create_client_authz_resource(client_id=client_id, payload=resource,
                                                                    skip_exists=True)
        print('Created resource:\n' + json.dumps(resource, indent=2))
        print('Response: ' + str(response))
        return response


    def update_resource(self, resource_id, resource):
        client_id = self.resources_client.get('id')
        if "_id" not in resource:
            resource["_id"] = resource_id
        elif resource["_id"] != resource_id:
            return jsonify(error="Resource ids on path and body don't match"), 400
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/resource/" + resource_id
        data_raw = self.keycloak_uma_openid.connection.raw_put(url.format(**params_path), data=json.dumps(resource))
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[200])


    def delete_resource(self, resource_id):
        return self.keycloak_uma.resource_set_delete(resource_id)


    def __register_policy(self, policy, register_f):
        client_id = self.resources_client.get('id')
        print("Creating policy:\n" + json.dumps(policy, indent=2))
        response = register_f(client_id=client_id, payload=policy, skip_exists=True)
        print("Response: " + str(response))


    def __register_policy_send_post(self, policy_type, client_id, payload, skip_exists):
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_uma_openid.connection.raw_post(url.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )


    def __register_aggregated_policy(self, client_id, payload, skip_exists):
        self.__register_policy_send_post("aggregate", client_id, payload, skip_exists)


    def register_aggregated_policy(self, name, policies, strategy):
        # strategy: UNANIMOUS | AFFIRMATIVE | CONSENSUS
        if not isinstance(policies, list):
            policies = [policies]
        policy = {
            "type": "aggregate",
            "logic": "POSITIVE",
            "decisionStrategy": strategy,
            "name": name,
            "policies": policies,
            "description": ""
        }
        self.__register_policy(policy, self.__register_aggregated_policy)


    def register_client_policy(self, policy):
        self.__register_policy(policy, self.keycloak_admin.create_client_authz_client_policy)


    def __register_client_scope_policy(self, client_id, payload, skip_exists):
        self.__register_policy_send_post("client-scope", client_id, payload, skip_exists)


    def register_client_scope_policy(self, policy):
        self.__register_policy(policy, self.__register_client_scope_policy)


    def __register_group_policy(self, client_id, payload, skip_exists):
        self.__register_policy_send_post("group", client_id, payload, skip_exists)


    def register_group_policy(self, name, groups, groups_claim):
        # groups: [{"id": str, "path": str}]
        policy = {
            "type": "group",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": name,
            "groups": groups,
            "groupsClaim": groups_claim,
            "description": ""
        }
        self.__register_policy(policy, self.__register_group_policy)


    def __register_regex_policy(self, client_id, payload, skip_exists):
        self.__register_policy_send_post("regex", client_id, payload, skip_exists)


    def register_regex_policy(self, name, regex, target_claim):
        policy = {
            "type": "regex",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": name,
            "pattern": regex,
            "targetClaim": target_claim,
            "description": ""
        }
        self.__register_policy(policy, self.__register_regex_policy)


    def register_role_policy(self, name, roles):
        if not isinstance(roles, list):
            roles = [roles]
        policy = {
            "type": "role",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": name,
            "roles": [
                {
                    "id": role,
                    "required": False
                } for role in roles
            ]
        }
        self.__register_policy(policy, self.keycloak_admin.create_client_authz_role_based_policy)


    def __register_time_policy(self, client_id, payload, skip_exists):
        self.__register_policy_send_post("time", client_id, payload, skip_exists)


    def register_time_policy(self, name, time):
        # time can be one of:
        # "notAfter":"1970-01-01 00:00:00"
        # "notBefore":"1970-01-01 00:00:00"
        # "dayMonth":<day-of-month>
        # "dayMonthEnd":<day-of-month>
        # "month":<month>
        # "monthEnd":<month>
        # "year":<year>
        # "yearEnd":<year>
        # "hour":<hour>
        # "hourEnd":<hour>
        # "minute":<minute>
        # "minuteEnd":<minute>
        policy = {
            "type": "time",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": name,
            "description": ""
        }
        policy.update(time)
        self.__register_policy(policy, self.__register_time_policy)


    def __register_user_policy(self, client_id, payload, skip_exists):
        self.__register_policy_send_post("user", client_id, payload, skip_exists)


    def register_user_policy(self, name, users):
        if not isinstance(users, list):
            users = [users]
        policy = {
            "type": "user",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": name,
            "users": users,
            "description": ""
        }
        self.__register_policy(policy, self.__register_user_policy)


    def assign_resources_permissions(self, permissions):
        if not isinstance(permissions, list):
            permissions = [permissions]
        client_id = self.resources_client.get('id')
        for permission in permissions:
            response = self.keycloak_admin.create_client_authz_resource_based_permission(client_id=client_id,
                                                                                         payload=permission,
                                                                                         skip_exists=True)
            print("Creating resource permission: " + json.dumps(permission, indent=2))
            print("Response: " + str(response))


    def create_user(self, username, password, realm_roles=None) -> str:
        if realm_roles is None:
            realm_roles = []
        payload = {
            "username": username,
            "realmRoles": realm_roles,
            "enabled": True
        }
        user_id = self.keycloak_admin.create_user(payload, exist_ok=True)
        print('Created user: ' + str(user_id))
        self.keycloak_admin.set_user_password(user_id, password, temporary=False)
        return user_id


    def get_user_token(self, username, password, openid):
        """Gets a user token using username/password authentication.
        """
        return openid.token(username, password, scope="openid profile")


    def generate_protection_pat(self):
        """Generate a personal access token
        """
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.resources_client.get('clientId'),
            "client_secret": self.resources_client.get('secret'),
        }
        connection = ConnectionManager(self.keycloak_uma.connection.base_url)
        connection.add_param_headers("Content-Type", "application/x-www-form-urlencoded")
        data_raw = connection.raw_post(self.keycloak_uma.uma_well_known["token_endpoint"], data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)


    def get_resources(self,
                      name: str = "",
                      exact_name: bool = False,
                      uri: str = "",
                      owner: str = "",
                      resource_type: str = "",
                      scope: str = "",
                      first: int = 0,
                      maximum: int = -1) -> [str]:
        if not name and not uri and not owner and not resource_type and not scope and first == 0 and maximum == -1:
            return list(self.keycloak_uma.resource_set_list())

        return self.__query_resources(name=name, exact_name=exact_name, uri=uri, owner=owner,
                                      resource_type=resource_type, scope=scope, first=first,
                                      maximum=maximum)


    def __query_resources(self, name: str = "",
                          exact_name: bool = False,
                          uri: str = "",
                          owner: str = "",
                          resource_type: str = "",
                          scope: str = "",
                          first: int = 0,
                          maximum: int = -1) -> [str]:
        """Query for list of resource set ids.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#list-resource-sets

        :param name: query resource name
        :type name: str
        :param exact_name: query exact match for resource name
        :type exact_name: bool
        :param uri: query resource uri
        :type uri: str
        :param owner: query resource owner
        :type owner: str
        :param resource_type: query resource type
        :type resource_type: str
        :param scope: query resource scope
        :type scope: str
        :param first: index of first matching resource to return
        :type first: int
        :param maximum: maximum number of resources to return (-1 for all)
        :type maximum: int
        :return: List of ids
        :rtype: List[str]
        """
        query = dict()
        if name:
            query["name"] = name
            if exact_name:
                query["exactName"] = "true"
        if uri:
            query["uri"] = uri
        if owner:
            query["owner"] = owner
        if resource_type:
            query["type"] = resource_type
        if scope:
            query["scope"] = scope
        if first > 0:
            query["first"] = first
        if maximum >= 0:
            query["max"] = maximum
        query["deep"] = True

        data_raw = self.keycloak_uma.connection.raw_get(
            self.keycloak_uma.uma_well_known["resource_registration_endpoint"], **query
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])


    def get_resource(self, resource_id: str):
        return self.keycloak_uma.resource_set_read(resource_id)


    def get_permission_ticket(self, resources: [str]):
        if not isinstance(resources, list):
            resources = [resources]
        payload = [
            {"resource_id": resource} for resource in resources
        ]
        data = self.keycloak_uma.connection.raw_post(
            f"${self.keycloak_uma.connection.base_url}/realms/{self.realm}/authz/protection/permission",
            data=json.dumps(payload)
        )
        return raise_error_from_response(data, KeycloakPostError)


    def get_rpt(self, access_token, ticket, limits):
        payload = {
            "claim_token_format": "urn:ietf:params:oauth:token-type:jwt",
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "claim_token": access_token,
            "ticket": ticket,
            "client_id": self.resources_client.get('clientId'),
            "client_secret": self.resources_client.get('secret'),
            "response_permissions_limit": limits
        }
        params_path = {
            "realm-name": self.realm
        }
        connection = ConnectionManager(self.keycloak_uma.connection.base_url)
        connection.add_param_headers("Content-Type", "application/x-www-form-urlencoded")
        data = connection.raw_post(urls_patterns.URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data, KeycloakPostError)


    def get_user_id(self, username) -> str:
        return self.keycloak_admin.get_user_id(username)


    def create_realm_role(self, role: str) -> str:
        payload = {
            "name": role,
            "clientRole": False
        }
        return self.keycloak_admin.create_realm_role(payload=payload, skip_exists=True)


    def assign_realm_roles_to_user(self, user_id: str, roles: [str]):
        if not isinstance(roles, list):
            roles = [roles]
        all_roles = self.keycloak_admin.get_realm_roles(brief_representation=False)
        realm_roles = list(filter(lambda role: role.get('name') in roles, all_roles))
        if not realm_roles:
            print("Warning: roles " + str(roles) + " do not exist on realm " + self.realm)
            return
        print('Assigning roles to user ' + user_id + ':\n' + json.dumps(realm_roles, indent=2))
        print('realm_roles ' + str(realm_roles))
        self.keycloak_admin.assign_realm_roles(user_id=user_id, roles=[realm_roles])


    def create_client_role(self, client_id: str, role: str) -> str:
        payload = {
            "name": role,
            "clientRole": True
        }
        return self.keycloak_admin.create_client_role(client_role_id=client_id, payload=payload, skip_exists=True)


    def register_client(self, options: dict, roles=None):
        if roles:
            options['serviceAccountsEnabled'] = True
        client_id = self.keycloak_admin.create_client(payload=options, skip_exists=True)
        client = self.keycloak_admin.get_client(client_id)
        print('Created client:\n' + json.dumps(client, indent=2))
        if options.get('serviceAccountsEnabled'):
            user = self.__get_service_account_user(client.get('id'))
            user_id = user.get('id')
            print('Created service account user:\n' + json.dumps(user, indent=2))
            if roles:
                for role in roles:
                    r = self.create_realm_role(role)
                    print('Created realm role: ' + json.dumps(r, indent=2))
                self.assign_realm_roles_to_user(user_id, roles)
        return client


    def register_admin_client(self, client_id: str):
        options = {
            'clientId': client_id,
            'serviceAccountsEnabled': True,
            'directAccessGrantsEnabled': True,
            'authorizationServicesEnabled': True
        }
        return self.register_client(options=options, roles=['admin'])


    def register_resources_client(self, client_id: str):
        options = {
            'clientId': client_id,
            'secret': 'secret',
            'serviceAccountsEnabled': True,
            'directAccessGrantsEnabled': True,
            'authorizationServicesEnabled': True,
            'authorizationSettings': {
                'allowRemoteResourceManagement': True,
                'policyEnforcementMode': 'ENFORCING'
            },
            "bearerOnly": False,
            'adminUrl': self.resource_server,
            'baseUrl': self.resource_server,
            'redirectUris': [
                self.resource_server + '/*'
            ]
        }
        return self.register_client(options=options)


    def __get_service_account_user(self, client_id: str):
        data_raw = self.keycloak_admin.connection.raw_get(
            self.server_url + '/admin/realms/' + self.realm + '/clients/' + client_id + '/service-account-user')
        return raise_error_from_response(data_raw, KeycloakGetError)
