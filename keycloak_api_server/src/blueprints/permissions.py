from flask import Blueprint


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    permissions = Blueprint('permissions', __name__)

    return permissions
