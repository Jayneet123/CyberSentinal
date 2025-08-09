import json
from elasticsearch import Elasticsearch, helpers

# Connect with extended timeout
es = Elasticsearch(
    "http://localhost:9200",
    request_timeout=60,
    retry_on_timeout=True
)

# Load logs
with open("output/summarized_logs.json", "r") as f:
    summaries = json.load(f)

index_name = "llm-log-summaries"

# Prepare actions
actions = [
    {
        "_index": index_name,
        "_source": summary
    }
    for summary in summaries
]

# Bulk insert with chunking
try:
    helpers.bulk(es, actions, chunk_size=100, max_retries=3)
    print(f"Successfully inserted {len(summaries)} documents into '{index_name}'")
except Exception as e:
    print(f"Bulk insert failed: {e}")
