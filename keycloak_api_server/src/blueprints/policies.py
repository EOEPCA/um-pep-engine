from flask import Blueprint


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    policies = Blueprint('policies', __name__)

    return policies
