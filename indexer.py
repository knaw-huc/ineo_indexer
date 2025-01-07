from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Indexer:
    def __init__(self, config):
        self.config = config
        self.es = Elasticsearch([config])

    # Insert single document to index
    def add_to_index(self, data):
        result = self.es.index(index=self.config["index"], id=data['id'], document=data)

    def add_to_index_bulk(self, data_gen):
        def bulk_func():
            for data in data_gen:
                doc = {
                    "_index": self.config["index"],
                    "_id": data['id'],
                }
                doc.update(data)

                yield doc

        bulk(self.es, bulk_func())

    def add_to_index_bulk(self, data_gen):
        def bulk_func():
            for data in data_gen:
                doc = {
                    "_index": self.config["index"],
                    "_id": data['id'],
                }
                doc.update(data)

                yield doc

        bulk(self.es, bulk_func())

    # Insert set of documents to index
    def bulk_to_index(self, data):
        result = self.es.bulk(index = self.config["index"], body=data, refresh='wait_for');

    def add_to_index_with_id(self, data, data_id):
        result = self.es.index(index = self.config["index"], body = data, id=data_id)
