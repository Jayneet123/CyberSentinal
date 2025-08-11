import os
import re
import json
import ast
from typing import Dict, Optional
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# ---------- Regex helpers ----------
RE_CODEFENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
RE_JSON_BLOCK = re.compile(r"\{")  # we'll do manual brace matching
RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_USER_FOR = re.compile(r"\bfor\s+([A-Za-z0-9._-]+)")
RE_USER_QUOTED = re.compile(r"user\s*['\"]([A-Za-z0-9._-]+)['\"]", re.IGNORECASE)
RE_SRC = re.compile(r"\s([a-zA-Z0-9_-]+)\[\d+\]:")
RE_TS = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
ACTIONS = [
    "Failed password",
    "Accepted password",
    "Unauthorized database access attempt",
    "Multiple failed sudo attempts",
    "Unauthorized",
    "Denied",
    "Login failure",
]

SYSTEM_PROMPT = (
    "You are a cybersecurity log parser. "
    "Return ONLY a valid JSON object with keys: "
    "timestamp, source, action, username, ip_address, message_summary."
)

def make_groq_client() -> Groq:
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY not set")
    return Groq(api_key=key)

# ---------- JSON repair utilities ----------
def _strip_fences(text: str) -> str:
    return RE_CODEFENCE.sub("", text).strip()

def _extract_balanced_json(text: str) -> Optional[str]:
    """
    Find the first balanced {...} block using a simple brace counter.
    Returns the substring or None if not found.
    """
    s = text
    start = None
    depth = 0
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    return s[start:i+1]
    return None

def _sanitize_json_like(s: str) -> str:
    """
    Heuristics to convert almost-JSON to JSON:
    - strip fences
    - replace Python bool/None with JSON lower-case
    - quote unquoted keys
    - fix trailing commas
    - prefer double quotes
    """
    s = _strip_fences(s)

    # Ensure we only work on the balanced block if present
    block = _extract_balanced_json(s)
    if block:
        s = block

    # Replace Python literals with JSON
    s = re.sub(r"\bTrue\b", "true", s)
    s = re.sub(r"\bFalse\b", "false", s)
    s = re.sub(r"\bNone\b", "null", s)

    # Quote unquoted keys: key: value -> "key": value
    # Avoid touching already quoted keys
    s = re.sub(r'(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:', r'"\1":', s)

    # Replace single quotes with double quotes (rough but helpful)
    # Do this after quoting keys
    s = s.replace("'", '"')

    # Remove trailing commas before } or ]
    s = re.sub(r",\s*([}\]])", r"\1", s)

    return s.strip()

def _safe_parse_json(text: str) -> Optional[Dict]:
    """
    Try strict JSON, then Python literal, else None.
    """
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        obj = ast.literal_eval(text)
        if isinstance(obj, dict):
            # Convert Python booleans/None to JSON-like
            return json.loads(json.dumps(obj))
    except Exception:
        pass
    return None

# ---------- Fallback field extraction ----------
def _fallback_parse(line: str) -> Dict:
    ts = RE_TS.search(line)
    src = RE_SRC.search(line)
    ip = RE_IP.search(line)
    user = RE_USER_FOR.search(line) or RE_USER_QUOTED.search(line)
    action = next((a for a in ACTIONS if a.lower() in line.lower()), "")
    return {
        "timestamp": ts.group(0) if ts else None,
        "source": src.group(1) if src else "",
        "action": action,
        "username": (user.group(1) if user else "unknown"),
        "ip_address": ip.group(0) if ip else "0.0.0.0",
        "message_summary": line.strip(),
    }

# ---------- Public API ----------
def summarize_log_line(client: Groq, log_line: str) -> Dict:
    """
    Never raises. Always returns a dict with required keys.
    """
    prompt = (
        "You are a cybersecurity log parser.\n"
        "Given a raw syslog line, return ONLY JSON with keys: "
        "timestamp, source, action, username, ip_address, message_summary.\n\n"
        f"{log_line.strip()}"
    )

    try:
        resp = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        text = (resp.choices[0].message.content or "").strip()
    except Exception as e:
        # If the LLM call fails, still return structured data from fallback
        out = _fallback_parse(log_line)
        out["original_log"] = log_line.strip()
        out["raw_summary_error"] = f"llm_error: {e}"
        return out

    # Try to clean and parse JSON-ish output
    cleaned = _sanitize_json_like(text)
    payload = _safe_parse_json(cleaned)

    if not payload:
        # As a last resort, parse fields from the raw log line
        out = _fallback_parse(log_line)
    else:
        # Normalize fields and fill gaps via fallback if missing
        out = {
            "timestamp": payload.get("timestamp"),
            "source": payload.get("source") or "",
            "action": payload.get("action") or "",
            "username": payload.get("username") or "unknown",
            "ip_address": payload.get("ip_address") or "0.0.0.0",
            "message_summary": payload.get("message_summary") or log_line.strip(),
        }

        # Fill missing from raw line heuristics
        if not out["ip_address"] or out["ip_address"] == "0.0.0.0":
            ip = RE_IP.search(log_line)
            if ip:
                out["ip_address"] = ip.group(0)
        if not out["username"] or out["username"] == "unknown":
            u = RE_USER_FOR.search(log_line) or RE_USER_QUOTED.search(log_line)
            if u:
                out["username"] = u.group(1)
        if not out["source"]:
            s = RE_SRC.search(log_line)
            if s:
                out["source"] = s.group(1)
        if not out["timestamp"]:
            t = RE_TS.search(log_line)
            if t:
                out["timestamp"] = t.group(0)
        if not out["action"]:
            a = next((a for a in ACTIONS if a.lower() in log_line.lower()), "")
            out["action"] = a

    out["original_log"] = log_line.strip()
    return out
