import logging

import requests
from flask import Blueprint, request, Response, abort


def construct_blueprint(config, keycloak_client):
    proxy = Blueprint('proxy', __name__)

    @proxy.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"])
    @proxy.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"])
    def resource_request(path):
        print('path ' + path)

        # start UMA flow

        # validate Authorization token
        token = request.headers.get('Authorization')
        invalid_token = False
        if not token:
            invalid_token = True
        token_split = token.split(' ')
        if len(token_split) < 2:
            invalid_token = True
        if token_split[0].lower() != 'basic' and token_split[0].lower() != 'bearer':
            invalid_token = True
        if invalid_token:
            # send ticket
            resources = keycloak_client.get_resources(uri=path)
            print("resources " + str(resources))
            if not resources:
                return abort(404)
            resource_id = resources[0]
            print("resource_id " + str(resource_id))
            ticket = keycloak_client.get_permission_ticket(resource_id)
            response = Response()
            response.headers["WWW-Authenticate"] = "UMA realm=" + config["realm"] \
                                                   + ", as_uri=" + config["auth_server_url"] \
                                                   + ", ticket=" + ticket
            response.status_code = 401

        return __foward_request(path)

    def __foward_request(path):
        res = requests.request(
            method=request.method,
            url=config.get('resource_server_endpoint') + path,
            headers={k: v for k, v in request.headers if k.lower() == 'host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
        )
        # Exclude all "hop-by-hop headers" defined by RFC 2616 section 13.5.1 ref. https://www.rfc-editor.org/rfc/rfc2616#section-13.5.1
        excluded_headers = [
            'content-encoding',
            'content-length',
            'transfer-encoding',
            'connection'
        ]
        headers = [
            (k, v) for k, v in res.raw.headers.items()
            if k.lower() not in excluded_headers
        ]
        response = Response(res.iter_content(chunk_size=10 * 1024), res.status_code, headers,
                            content_type=res.headers['Content-Type'])
        return response

    return proxy
