#!/usr/bin/env python3
import pymongo

class Mongo_Handler:

    def __init__(self, database, database_obj, **kwargs):
        self.modified = []
        self.__dict__.update(kwargs)
        self.myclient = pymongo.MongoClient('localhost', 27017)
        self.db = self.myclient[database]
        self.db_obj = database_obj

    def mongo_exists(self, mongo_key, mongo_value):
        '''
            Check the existence of the value inside the database
            Return boolean result
        '''
        col = self.db[self.db_obj]  
        myquery = { mongo_key: mongo_value }
        if col.find_one(myquery):
            return True
        else:
            return False

    def get_from_mongo(self, mongo_key, mongo_value):
        '''
            Gets an existing object from the database, or None if not found
        '''
        col = self.db[self.db_obj]
        myquery = { mongo_key: mongo_value }
        return col.find_one(myquery)

    def delete_in_mongo(self, mongo_key, mongo_value):
        '''
            Check the existence of the key inside the database
            And deletes the document with that value
        '''
        if self.mongo_exists(mongo_key, mongo_value):
            col = self.db[self.db_obj]  
            myquery = { mongo_key: mongo_value }
            a= col.delete_one(myquery)
    
    def update_in_mongo(self, key_mongo, dict_data):
        '''
        Find the object in the database by id, add or modify the changed values for the object
        '''
        id=dict_data[key_mongo]
        col = self.db[self.db_obj]
        myquery= {key_mongo: id}
        new_val= {"$set": dict_data}
        x = col.update_many(myquery, new_val)
        return
    
    #Functions only for resources db
    def insert_resource_in_mongo(self, resource_id: str, name: str, ownership_id: str, reverse_match_url: str):   
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
            if self.mongo_exists("resource_id", resource_id):
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

    def get_id_from_uri(self,uri):
        '''
            Finds the most similar match with the uri given
            Generates a list of the possible matches
            Returns resource_id of the best match
        '''
        total= '/'
        col= self.db[self.db_obj]
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

    def get_all_resources(self):
        '''
            Gets all existing resources in database
        '''
        col = self.db['resources']
        return col.find()
        
    def remove_resources(self, filter_key=None, filter_value=None):
        col = self.db['resources']
        query = {}
        if filter_key is not None and filter_value is not None:
            query = { filter_key: filter_value }
        col.delete_many(query)

    #Functions for rpt db
    def insert_rpt_in_mongo(self, rpt: str, rpt_limit_uses: int, timestamp: str):   
        '''
            Generates a document with:
                -RPT: Unique id for each rpt
                -RPT_LIMIT_USES: Limit of uses
                -TIMESTAMP: RPT time when it is inserted
            Check the existence of the rpt to be registered on the database
            If alredy registered will return None
            If not registered will add it and return the query result
        '''
        dblist = self.myclient.list_database_names()
        # Check if the database alredy exists
        if "rpt_db" in dblist:
            col = self.db['rpts']
            myres = { "rpt": rpt, "rpt_limit_uses": rpt_limit_uses, "timestamp": timestamp }
            # Check if the resource is alredy registered in the collection
            x=None
            if self.mongo_exists("rpt", rpt):
                x= self.update_rpt(myres)
            # Add the resource since it doesn't exist on the database 
            else:
                x = col.insert_one(myres)
            return x
        else:
            col = self.db['rpts']
            myres = { "rpt": rpt, "rpt_limit_uses": rpt_limit_uses, "timestamp": timestamp }
            x = col.insert_one(myres)
            return x
