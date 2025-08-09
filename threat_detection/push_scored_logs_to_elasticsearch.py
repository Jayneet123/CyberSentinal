import json
from elasticsearch import Elasticsearch, helpers

# Connect to Elasticsearch
es = Elasticsearch(
    "http://localhost:9200",
    request_timeout=60,
    retry_on_timeout=True
)

# Load scored logs
with open("scored_logs.json", "r") as f:
    logs = json.load(f)

index_name = "scored-log-events"

# Prepare documents
actions = [
    {
        "_index": index_name,
        "_source": log
    }
    for log in logs
]

# Bulk insert
try:
    helpers.bulk(es, actions, chunk_size=100, max_retries=3)
    print(f"✅ Inserted {len(logs)} documents into '{index_name}'")
except Exception as e:
    print(f"❌ Bulk insert failed: {e}")
