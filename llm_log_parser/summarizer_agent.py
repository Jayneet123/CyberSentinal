import os
import json
import re
from dotenv import load_dotenv
from groq import Groq

# Load environment
load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# File paths
LOG_FILE = "sample_logs/syslog_sample.log"  
OUTPUT_FILE = "output/summarized_logs.json"

# Base Prompt
base_prompt = """
You are a cybersecurity log parser.

You will be given a raw syslog line. Extract and return only a valid JSON object with these fields:
- timestamp
- source (e.g., sshd, sudo)
- action (e.g., failed login, accepted login)
- username
- ip_address
- message_summary

Rules:
- Do NOT include any commentary or markdown.
- Use exact field names and format valid JSON.
- The message_summary should describe the event meaningfully.

Now process this log line:
"""

# Ensure output directory exists 
os.makedirs("output", exist_ok=True)

# Load logs
with open(LOG_FILE, "r") as f:
    log_lines = [line.strip() for line in f if line.strip()]

print(f"📄 Loaded {len(log_lines)} log lines from {LOG_FILE}")
summarized_logs = []

# Process each log line 
for i, log_line in enumerate(log_lines):
    print(f"\n🪵 Processing line {i + 1}: {log_line}")

    user_prompt = base_prompt.strip() + f"\n\nLog:\n{log_line}"

    try:
        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": "You are a helpful assistant for log analysis."},
                {"role": "user", "content": user_prompt}
            ]
        )

        summary_text = response.choices[0].message.content.strip()
        print("🧠 Raw GPT Response:\n", summary_text)

        # Try extracting JSON block using regex
        match = re.search(r'\{[\s\S]*?\}', summary_text)
        if match:
            summary_json = json.loads(match.group())
            print("✅ JSON parsed successfully.")
        else:
            print("⚠️ No valid JSON found. Wrapping raw response.")
            summary_json = {"raw_summary": summary_text}

        summary_json["original_log"] = log_line
        summarized_logs.append(summary_json)

    except Exception as e:
        print("❌ GPT API Error:", e)

# Save output 
with open(OUTPUT_FILE, "w") as f:
    json.dump(summarized_logs, f, indent=2)

print(f"\n📁 Done! {len(summarized_logs)} summaries saved to {OUTPUT_FILE}")
