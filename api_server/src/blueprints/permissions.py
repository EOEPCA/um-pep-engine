import json

from flask import Blueprint, request


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    permissions = Blueprint('permissions', __name__)

    return permissions
