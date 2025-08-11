import os, json, re
from typing import Dict
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
_JSON_BLOCK = re.compile(r"\{[\s\S]*\}")

SYSTEM_PROMPT = (
    "You are a cybersecurity log parser. You must respond with valid JSON only. No explanations. No text outside the JSON. "
    "Return ONLY a valid JSON object with keys: timestamp, source, action, username, ip_address, message_summary."
)

def make_groq_client() -> Groq:
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY not set")
    return Groq(api_key=key)

def summarize_log_line(client: Groq, log_line: str) -> Dict:
    prompt = (
        "You are a cybersecurity log parser.\n"
        "Given a raw syslog line, return ONLY JSON with keys: "
        "timestamp, source, action, username, ip_address, message_summary.\n\n"
        f"{log_line.strip()}"
    )
    resp = client.chat.completions.create(
        model="llama3-8b-8192",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    text = resp.choices[0].message.content.strip()
    m = _JSON_BLOCK.search(text)
    payload = json.loads(m.group() if m else text)

    return {
        "timestamp": payload.get("timestamp"),
        "source": payload.get("source") or "",
        "action": payload.get("action") or "",
        "username": payload.get("username") or "unknown",
        "ip_address": payload.get("ip_address") or "0.0.0.0",
        "message_summary": payload.get("message_summary") or "",
        "original_log": log_line.strip(),
    }
