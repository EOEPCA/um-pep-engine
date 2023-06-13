import json

from flask import Blueprint, request


def construct_blueprint(keycloak_client):
    keycloak_client = keycloak_client
    policies = Blueprint('policies', __name__)

    return policies
