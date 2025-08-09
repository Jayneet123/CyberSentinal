from elasticsearch import Elasticsearch, helpers

def make_es(url: str = "http://localhost:9200"):
    return Elasticsearch(url, request_timeout=60, retry_on_timeout=True)

def push_doc(es, index: str, doc: dict):
    helpers.bulk(es, [{"_index": index, "_source": doc}], chunk_size=1, max_retries=3)
