#!/usr/bin/env python3

import logging

from elasticsearch import Elasticsearch

logger = logging.getLogger("PEP")


class ElasticSearch:

    def __init__(self, database, hosts, username, password, **kwargs):
        self.modified = []
        self.__dict__.update(kwargs)
        self.elastic_search = Elasticsearch(
            hosts=hosts,
            http_auth=(username, password),
            timeout=20
        )
        self.db = database
        if not self.elastic_search.indices.exists(index=database):
            logger.debug("Creating index in Elasticsearch: " + str(self.db))
            self.elastic_search.indices.create(index=database, ignore=400)
            logger.debug("Created index in Elasticsearch: " + str(self.db))

    def exists(self, key, value):
        """
            Check the existence of the value inside the database
            Return boolean result
        """
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "match": {
                            key: value
                        }
                    }
                }
            }
        }
        res = self.elastic_search.search(index=self.db, body=query_body)
        if str(key) == "rpt":
            if len(res["hits"]["hits"]) > 0:
                for i in res["hits"]["hits"]:
                    if str(i["_source"]["rpt"]) == value:
                        return True
            else:
                return False
        else:
            if len(res["hits"]["hits"]) > 0:
                return True
            else:
                return False
        return False

    def get(self, key, value):
        """
            Gets an existing object from the database, or None if not found
        """
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "match": {
                            key: value
                        }
                    }
                }
            }
        }
        res = self.elastic_search.search(index=self.db, body=query_body)
        if not self.exists(key, value):
            return {}
        return res["hits"]["hits"][0]["_source"]

    def delete(self, key, value):
        """
            Check the existence of the key inside the database
            And deletes the document with that value
        """
        if self.exists(key, value):
            query_body = {
                "query": {
                    "bool": {
                        "must": {
                            "match": {
                                key: value
                            }
                        }
                    }
                }
            }
            res = self.elastic_search.search(index=self.db, body=query_body)
            self.elastic_search.delete(index=self.db, doc_type=self.db_obj, id=res["hits"]["hits"][0]["_id"],
                                       refresh="true")

    def insert(self, value):
        """
            Generates a document with:
                -msg: dict formatted message to be inserted in elastic
            Works as a generic message document for elastic logging
        """
        self.elastic_search.index(index=self.db, doc_type=self.db_obj, body=value, refresh="true")

    def update(self, key, value):
        """
        Find the object in the database by id, add or modify the changed values for the object
        """
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "match": {
                            key: value[key]
                        }
                    }
                }
            }
        }
        res = self.elastic_search.search(index=self.db, body=query_body)
        _id = res['hits']['hits'][0]['_id']
        update_body = {
            "doc": value
        }
        self.elastic_search.update(index=self.db, id=_id, body=update_body, refresh="true")
        return
