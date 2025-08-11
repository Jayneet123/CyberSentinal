import os, time, threading, queue
from pathlib import Path
import json
import pandas as pd
from dotenv import load_dotenv

from llm_log_parser.summarizer import make_groq_client, summarize_log_line
from threat_detection.model import load_or_new_model, save_model
from threat_detection.features import FeatureEncoder
from threat_detection.scorer import fit_if_needed, score_event
from integrations.elastic import make_es, push_doc

# ---- Config ----
LOG_SOURCE = os.getenv("CS_LOG_SOURCE")
MODEL_PATH = os.getenv("CS_MODEL_PATH", r"./threat_detection/threat_model.pkl")
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_INDEX = os.getenv("ES_INDEX", "scored-log-events")
THRESHOLD = float(os.getenv("CS_THREAT_THRESHOLD", "0.60"))
HIST_JSON = os.getenv("CS_HIST_JSON", r"./llm_log_parser/output/summarized_logs.json")

load_dotenv()

# ---- Init clients ----
groq_client = make_groq_client()
es = make_es(ES_URL)

# ---- Model + encoder ----
model = load_or_new_model(MODEL_PATH)
encoder = FeatureEncoder()

# Optional: warm-up on historical LLM summaries
if Path(HIST_JSON).exists():
    with open(HIST_JSON, "r") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = [data]
    if data:
        df_hist = pd.DataFrame(data)
        model = fit_if_needed(model, encoder, df_hist)
        save_model(model, MODEL_PATH)

# ---- Tail + process ----
q = queue.Queue()

def tail_file(path: str, q: queue.Queue):
    p = Path(path)
    if not p.exists():
        print(f"Log source not found: {path}")
        return
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            line = line.strip()
            if line:
                q.put(line)

def worker():
    while True:
        line = q.get()
        try:
            summary = summarize_log_line(groq_client, line)
            scored, s, is_bad = score_event(model, encoder, summary, threshold=THRESHOLD)
            push_doc(es, ES_INDEX, scored)
            if is_bad:
                print(f"ALERT | score={s:.2f} | user={scored['username']} | ip={scored['ip_address']} | action={scored['action']}")
            else:
                print(f"OK | score={s:.2f} | {scored['message_summary']}")
        except Exception as e:
            print(f"Pipeline error: {e}")
        finally:
            q.task_done()

if __name__ == "__main__":
    print("CyberSentinel agent starting…")
    print(f"Tailing: {LOG_SOURCE} | ES index: {ES_INDEX}")
    print(f"GROQ key present: {'yes' if os.getenv('GROQ_API_KEY') else 'no'}")
    t1 = threading.Thread(target=tail_file, args=(LOG_SOURCE, q), daemon=True)
    t2 = threading.Thread(target=worker, daemon=True)
    t1.start(); t2.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n Shutting down…")
