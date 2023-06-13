import json

from flask import Blueprint, request


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    resources = Blueprint('resources', __name__)

    @resources.route("/resources", methods=["GET"])
    def get_resources():
        name = request.args.get('name', "")
        exact_name = request.args.get('exact_name', False)
        uri = request.args.get('uri', "")
        owner = request.args.get('owner', "")
        resource_type = request.args.get('resource_type', "")
        scope = request.args.get('scope', "")
        first = int(request.args.get('first', 0))
        maximum = int(request.args.get('maximum', -1))
        return keycloak_client.get_resources(name, exact_name, uri, owner, resource_type, scope, first, maximum)

    @resources.route("/resources/<resource_id>", methods=["GET"])
    def get_resource(resource_id: str):
        return keycloak_client.get_resource(resource_id)

    @resources.route("/resources", methods=["POST"])
    def register_resource():
        resource = request.get_json()
        return keycloak_client.register_resource(resource)

    @resources.route("/resources/<resource_id>", methods=["PUT"])
    def update_resource(resource_id: str):
        resource = request.get_json()
        return keycloak_client.update_resource(resource_id, resource)

    @resources.route("/resources/<resource_id>", methods=["DELETE"])
    def delete_resource(resource_id: str):
        return keycloak_client.delete_resource(resource_id)

    return resources
