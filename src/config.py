#!/usr/bin/env python3

import os
import sys
import traceback
from json import load, dump
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from WellKnownHandler import WellKnownHandler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT
import logging

def load_config(config_path: str) -> dict:
    """
    Parses and returns the config file

    Returns: dict
    """
    config = {}
    with open(config_path) as j:
        config = load(j)

    return config


def save_config(config_path: str, data: dict):
    """
    Saves updated config file
    """
    with open(config_path, 'w') as j:
        dump(data,j)

def get_verb_config(config_path: str, g_config):
    """
    Loads HTTP verb-to-action-id mapping onto existing dictionary, if provided
    """
    if g_config:
        verbs_config = load_config(config_path)
        g_config.update(verbs_config)
        return g_config
    else:
        return load_config(config_path)
    


def get_config(config_path: str):
    """
    Loads entire configuration onto memory
    """
    env_vars = [
    "PEP_REALM",
    "PEP_AUTH_SERVER_URL",
    "PEP_SERVICE_HOST",
    "PEP_PROXY_SERVICE_PORT",
    "PEP_RESOURCES_SERVICE_PORT",
    "PEP_S_MARGIN_RPT_VALID",
    "PEP_CHECK_SSL_CERTS",
    "PEP_USE_THREADS",
    "PEP_DEBUG_MODE",
    "PEP_RESOURCE_SERVER_ENDPOINT",
    "PEP_API_RPT_UMA_VALIDATION",
    "PEP_RPT_LIMIT_USES",
    "PEP_PDP_URL",
    "PEP_PDP_PORT",
    "PEP_PDP_POLICY_ENDPOINT",
    "PEP_VERIFY_SIGNATURE",
    "PEP_DEFAULT_RESOURCE_PATH",
    "PEP_DEFAULT_TERMS_PATH",
    "PEP_WORKING_MODE"]

    #Sets logger
    logger = logging.getLogger("PEP_ENGINE")

    use_env_var = True

    for env_var in env_vars:
        if env_var not in os.environ:
            use_env_var = False

    g_config = {}
    # Global config objects
    if use_env_var is False:
        g_config = load_config(config_path)
    else:
        for env_var in env_vars:
            env_var_config = env_var.replace('PEP_', '')

            if "true" in os.environ[env_var].replace('"', ''):
                g_config[env_var_config.lower()] = True
            elif "false" in os.environ[env_var].replace('"', ''):
                g_config[env_var_config.lower()] = False
            else:
                g_config[env_var_config.lower()] = os.environ[env_var].replace('"', '')

    # Sanitize PDP "policy" endpoint config value, VERY IMPORTANT to ensure proper function of the endpoint
    if g_config["pdp_policy_endpoint"][0] is not "/":
        g_config["pdp_policy_endpoint"] = "/" + g_config["pdp_policy_endpoint"]
    if g_config["pdp_policy_endpoint"][-1] is not "/":
        g_config["pdp_policy_endpoint"] = g_config["pdp_policy_endpoint"] + "/"

    # Global handlers
    g_wkh = WellKnownHandler(g_config["auth_server_url"], secure=False)
    
    # Global setting to validate RPTs received at endpoints
    api_rpt_uma_validation = g_config["api_rpt_uma_validation"]
    if api_rpt_uma_validation:
        logger.debug("UMA RPT validation is ON.")
    else:
        logger.debug("UMA RPT validation is OFF.")

    # Generate client dynamically if one is not configured.
    if "client_id" not in g_config or "client_secret" not in g_config:
        print ("NOTICE: Client not found, generating one... ")
        scim_client = EOEPCA_Scim(g_config["auth_server_url"])
        new_client = scim_client.registerClient("PEP Dynamic Client",
                                    grantTypes = ["client_credentials", "password"],
                                    redirectURIs = [""],
                                    logoutURI = "", 
                                    responseTypes = ["code","token","id_token"],
                                    scopes = ['openid', 'uma_protection', 'permission', 'profile', 'is_operator'],
                                    token_endpoint_auth_method = ENDPOINT_AUTH_CLIENT_POST)
        logger.debug("NEW CLIENT created with ID '"+new_client["client_id"]+"', since no client config was found on config.json or environment")

        g_config["client_id"] = new_client["client_id"]
        g_config["client_secret"] = new_client["client_secret"]
        if use_env_var is False:
            save_config("config/config.json", g_config)
        else:
            os.environ["PEP_CLIENT_ID"] = new_client["client_id"]
            os.environ["PEP_CLIENT_SECRET"] = new_client["client_secret"]
        logger.debug("New client saved to config!")
    else:
        logger.debug("Client found in config, using: "+g_config["client_id"])

    save_config(config_path, g_config)

    return g_config, g_wkh


def get_default_resources(path: str):
    """
    Loads Charts configuration file in addition with the alredy existent on the source path
    """
    #Sets logger
    logger = logging.getLogger("PEP_ENGINE")
    g_config = {}    
    # Global config objects
    # If path is the same as default one, return default values
    if path == "./config/default-resources.json":
        return load_config(path)
    # If paths are different, merge both files and return dict
    g_config = load_config(path)
    l_config = load_config("./config/default-resources.json")
    for k in l_config['default_resources']:
        if not any(d['resource_uri'] == k['resource_uri'] for d in g_config['default_resources']):
            g_config['default_resources'].append(k)
        else:
            logger.debug("The default resource "+str(k)+" is already on the k8s definition")
    return g_config

def get_terms(path: str):
    """
    Gets the default terms and conditions to associate to each resource policy
    """
    #Sets logger
    logger = logging.getLogger("PEP_ENGINE")
    g_config = {}    
    # Global config objects
    # If path is the same as default one, return default values
    if path == "./config/default-terms.json":
        return load_config(path)
    # If paths are different, merge both files and return dict
    g_config = load_config(path)
    l_config = load_config("./config/default-terms.json")
    for k in l_config:
        if not any(d == k for d in g_config):
            g_config.append(k)
        else:
            logger.debug("The default T&C "+str(k)+" is already on the k8s definition")
    logger.info("CONFIG HECHA?")
    return g_config