#!/usr/bin/env python3
import unittest

import mock
from src.utils.mongo_handler import Mongo_Handler


def mocked_mongo(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            a = dict(resources='')
            self.response = dict(resource_db=a)

        def response(self):
            return self.response

    return MockResponse().response


def mocked_list_dbs(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            self.response = ['resource_db', 'other_db']

    return MockResponse().response


def mocked_exists_mongo(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            if 'reverse_match_url' in args[0]:
                a = ['/pep/no', '/mongo/', '/', '/uma/ades']
                self.response = {'resource_id': 'a', 'name': 'b', 'reverse_match_url': a[0]}
                a.pop(0)
                self.boo = True
            else:
                self.boo = False

    resp = MockResponse()
    if resp.boo:
        return resp.response
    else:
        return False


def mocked_insert_mongo(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            self.response = {'resource_id': args[0], 'name': args[1], 'reverse_match_url': args[2]}

        def response(self):
            return self.response

    return MockResponse().response


class Mongo_Unit_Test(unittest.TestCase):
    # First, mock has to simulate http response, therefore a patch of get and post methods from requests library will be needed.

    @mock.patch('pymongo.MongoClient', side_effect=mocked_mongo)
    def test_mongo(self, mock_test, raise_for_status=None):
        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        mongo = Mongo_Handler("resource_db", "resources")
        self.assertEqual(str(mongo)[:-16], '<src.handlers.mongo_handler.Mongo_Handler object at')

    @mock.patch('pymongo.collection.Collection.find_one', side_effect=mocked_exists_mongo)
    def test_find_mongo(self, mock_find_test, raise_for_status=None):
        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        mongo = Mongo_Handler("resource_db", "resources")
        a = mongo.get_id_from_uri('c')

    # @mock.patch('pymongo.collection.Collection.find_one', side_effect=mocked_exists_mongo)
    @mock.patch('src.handlers.mongo_handler.Mongo_Handler.insert_resource_in_mongo', side_effect=mocked_insert_mongo)
    @mock.patch('pymongo.collection.Collection.find_one', side_effect=mocked_exists_mongo)
    def test_insert_mongo(self, mock_insert_test, raise_for_status=None):
        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        mongo = Mongo_Handler("resource_db", "resources")
        j = mongo.insert_resource_in_mongo('a', 'b', 'c')
        a = mongo.get_id_from_uri('c')


if __name__ == '__main__':
    unittest.main()
