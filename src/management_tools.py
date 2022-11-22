#!/usr/local/bin/python3
import argparse
import sys
from handlers.mongo_handler import Mongo_Handler
from bson.json_util import dumps

custom_mongo = Mongo_Handler("resource_db", "resources")

def list_resources(user,resource):
    if resource is not None:
        return custom_mongo.get_from_mongo("resource_id", resource)
    if user is not None:
        resources=custom_mongo.get_all_resources()
        return list(filter(lambda x: x["ownership_id"] == user,resources))
    return custom_mongo.get_all_resources()
    
def remove_resources(user,resource,all):
    if resource is not None:
        return custom_mongo.delete_in_mongo("resource_id", resource)
    if user is not None and all:
        return custom_mongo.remove_resources("ownership_id",user)
    if user is None and all:
        return custom_mongo.remove_resources()
    return "No action taken (missing --all flag?)"

def import_database(res_path, rpt_path):
    print("importing database....")
    return custom_mongo.import_database(res_path, rpt_path)

def export_database(res_path, rpt_path):
    print("Exporting database....")
    return custom_mongo.export_database(res_path, rpt_path)


parser = argparse.ArgumentParser(description='Operational management of resources.')
parser.add_argument('action', metavar='action', type=str,
                    help='Operation to perform: list/remove import/export')
parser.add_argument('-u',
                       '--user',
                       help='Filter action by user ID')
parser.add_argument('-r',
                       '--resource',
                       help='Filter action by resource ID')

parser.add_argument('-p',
                       '--path',
                       help='Select directory from where to save/read the resources collection')

parser.add_argument('-t',
                       '--token',
                       help='Select directory from where to save/read the token collection')

parser.add_argument('-a',
                       '--all',
                       action='store_true',
                       help='Apply action to all resources.')


args = vars(parser.parse_args())

if args["action"] == "list":
    result = dumps(list_resources(args['user'],args['resource']))
elif args["action"] == "remove": 
    if args["resource"] is not None:
        args["all"] = False
    result = remove_resources(args['user'],args['resource'],args['all'])
elif args["action"] == "import": 
    result = import_database(args['path'], args['token'])
elif args["action"] == "export": 
    result = export_database(args['path'], args['token'])
else:
    print("Allowed actions are 'remove' or 'list'")
    sys.exit(-1)
    
print(result)
