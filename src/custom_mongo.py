#!/usr/bin/env python3
import pymongo

class Mongo_Handler:

    def __init__(self, **kwargs):
        self.modified = []
        self.__dict__.update(kwargs)
        self.myclient = pymongo.MongoClient('localhost', 27017)
        self.db = self.myclient["resource_db"]

    def get_id_from_uri(self,uri):
        '''
            Finds the most similar match with the uri given
            Generates a list of the possible matches
            Returns resource_id of the best match
        '''
        total= '/'
        col= self.db['resources']
        k=[]
        uri_split=uri.split('/')
        count=0
        for n in uri_split:
            if count >= 2:
                total = total + '/' + n
            else:
                total = total + n
            count+=1
            myquery = { "reverse_match_url": total }
            found=col.find_one(myquery)
            if found:
                k.append(found['resource_id'])
        if len(k)>0:
            return k[-1]
        else: 
            return None

    def resource_exists(self, resource_id):
        '''
            Check the existence of the resource inside the database
            Return boolean result
        '''
        col = self.db['resources']  
        myquery = { "resource_id": resource_id }
        if col.find_one(myquery):
            return True
        else:
            return False

    def insert_in_mongo(self, resource_id: str, name: str, ownership_id: str, reverse_match_url: str):   
        '''
            Generates a document with:
                -RESOURCE_ID: Unique id for each resource
                -RESOURCE_NAME: Custom name for the resource (NO restrictions)
                -OWNERSHIP_ID: Resource owner
                -RESOURCE_URL: Stored endpoint for each resource
            Check the existence of the resource to be registered on the database
            If alredy registered will return None
            If not registered will add it and return the query result
        '''
        dblist = self.myclient.list_database_names()
        # Check if the database alredy exists
        if "resource_db" in dblist:
            col = self.db['resources']
            myres = { "resource_id": resource_id, "name": name, "ownership_id": ownership_id, "reverse_match_url": reverse_match_url }
            # Check if the resource is alredy registered in the collection
            x=None
            if self.resource_exists(resource_id):
                x= self.update_resource(myres)
            # Add the resource since it doesn't exist on the database 
            else:
                x = col.insert_one(myres)
            return x
        else:
            col = self.db['resources']
            myres = { "resource_id": resource_id, "name": name, "ownership_id": ownership_id, "reverse_match_url": reverse_match_url }
            x = col.insert_one(myres)
            return x

    def get_resource(self, resource_id):
        '''
            Gets an existing resource from the database, or None if not found
        '''
        col = self.db['resources']
        myquery = { "resource_id": resource_id }
        return col.find_one(myquery)

    def get_all_resources(self):
        '''
            Gets all existing resources in database
        '''
        col = self.db['resources']
        return col.find()

    def delete_resource(self, resource_id):
        '''
            Check the existence of the resource inside the database
            And deletes the document
        '''
        if self.resource_exists(resource_id):
            col = self.db['resources']  
            myquery = { "resource_id": resource_id }
            a= col.delete_one(myquery)
    
    def update_resource(self, dict_data):
        '''
        Find the resource in the database by id, add or modify the changed values for the resource
        '''
        id=dict_data['resource_id']
        col = self.db['resources']
        myquery= {'resource_id': id}
        new_val= {"$set": dict_data}
        x = col.update_many(myquery, new_val)
        return
    
    def verify_uid(self, resource_id, uid):
        col = self.db['resources']
        try:
            myquery = {"resource_id": resource_id, "ownership_id": uid }
            a= col.find_one(myquery)
            if a:                
                return True
            else:
                return False
        except:
            print('no resource with that UID associated')
            return False
