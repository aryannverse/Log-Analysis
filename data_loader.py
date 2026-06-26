import os
import re
import json
import requests
import time
from functools import lru_cache
import pandas as pd
import pypdf
from config import DEFAULT_REGEXES, DEFAULT_ANOMALIES

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def extract_and_parse_json(text):
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    if '<think>' in text:
        text = text.split('<think>')[0]
    text = text.strip()
    
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        json_str = text[start_idx:end_idx+1]
        try:
            return json.loads(json_str, strict=False)
        except Exception:
            pass
            
    meaning_match = re.search(r'"meaning"\s*:\s*"(.*?)"', text, re.DOTALL)
    fix_match = re.search(r'"fix"\s*:\s*"(.*?)"', text, re.DOTALL)
    if meaning_match and fix_match:
        meaning_str = meaning_match.group(1).replace('\\"', '"').replace('\\n', '\n')
        fix_str = fix_match.group(1).replace('\\"', '"').replace('\\n', '\n')
        return {
            "meaning": meaning_str,
            "fix": fix_str
        }
        
    try:
        return json.loads(text, strict=False)
    except Exception as e:
        return {
            "meaning": f"JSON Parse Error: {e}. Raw Response content: {text}",
            "fix": "Try refreshing or reloading this log entry to generate a new analysis."
        }

API_KEY = os.environ.get("GROQ_API_KEY")

@lru_cache(maxsize=1024)
def get_groq_explanation(raw_log):
    if not API_KEY:
        return {
            "meaning": "GROQ_API_KEY is not set in the environment.",
            "fix": "Please create a .env file and set GROQ_API_KEY=your_groq_api_key_here."
        }
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    
    prompt = f"""You are an expert security engineer and system reliability expert.
Analyze the following raw log line and explain its meaning and fix.
You must output a JSON object with exactly two keys:
1. "meaning": A clear, human-readable explanation of the stack trace, warning, error, or vulnerability.
2. "fix": Actionable, step-by-step remediation or patch instructions.

Return ONLY the raw JSON object. Do not wrap the output in markdown code blocks (such as ```json or ```). Do not include any text outside the JSON object.

Raw Log:
{raw_log}
"""
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "qwen/qwen3.6-27b",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": 3000
    }
    
    for attempt in range(1, 5):
        timeout_sec = 60
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=timeout_sec)
            if r.status_code == 200:
                res_data = r.json()
                choices = res_data.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "").strip()
                    parsed = extract_and_parse_json(content)
                    meaning = parsed.get("meaning")
                    fix = parsed.get("fix")
                    if meaning and fix and "JSON Parse Error" not in meaning:
                        return {
                            "meaning": meaning,
                            "fix": fix
                        }
                    return {
                        "meaning": f"JSON Parse Error. Content was: '{content}'. Parsed object: {parsed}",
                        "fix": "Please check the debug content above."
                    }
                return {
                    "meaning": "Invalid response format from Groq API.",
                    "fix": "Please check the log format and try again."
                }
            elif r.status_code == 429:
                retry_after = r.headers.get("retry-after") or r.headers.get("Retry-After")
                try:
                    sleep_time = float(retry_after) if retry_after else (2 ** attempt)
                except ValueError:
                    sleep_time = 2 ** attempt
                sleep_time = min(sleep_time, 15.0)
                time.sleep(sleep_time)
                continue
            elif r.status_code in [401, 403]:
                return {
                    "meaning": "Authentication/Permission error with Groq API.",
                    "fix": "Please verify your GROQ_API_KEY is correct and active."
                }
            else:
                try:
                    err_msg = r.json().get("error", {}).get("message", r.text)
                except Exception:
                    err_msg = r.text
                return {
                    "meaning": f"Groq API returned error code {r.status_code}: {err_msg}",
                    "fix": "Verify network status and API key configuration."
                }
        except requests.exceptions.Timeout:
            if attempt == 4:
                return {
                    "meaning": "Groq API read timed out after multiple attempts.",
                    "fix": "The connection timed out. Please check your internet connection and verify Groq service status."
                }
            time.sleep(1.0)
            continue
        except Exception as e:
            return {
                "meaning": f"Error communicating with Groq API: {e}",
                "fix": "Ensure your internet connection is working and GROQ_API_KEY is configured."
            }
 
    return {
        "meaning": "Unable to extract response from Groq model due to rate limit/timeout.",
        "fix": "Check model availability, tokens per minute (TPM) limit, or wait a few seconds and try again."
    }

def analyze_dataset_format(sample_text):
    if not API_KEY:
        return None
    url = "https://api.groq.com/openai/v1/chat/completions"
    prompt = f"""You are an expert log parser and system reliability engineer.
Analyze the following sample content from an uploaded dataset file and generate a parsing configuration.
You must output a JSON object with exactly the following keys:
1. "file_type": Either "csv", "json", "pdf", or "text".
2. "regex": A python regular expression pattern to parse log lines (if file_type is "text" or "pdf" or "csv"), or null. It must capture named groups: 'timestamp' (if available), 'level' (if available), 'component' (if available), and 'message'. E.g. r"^(\\d{{4}}-\\d{{2}}-\\d{{2}})\\s+(\\S+)\\s+(?P<level>\\w+)\\s+(?P<message>.*)$"
3. "columns": List of column names to parse (if file_type is "csv"), or null.
4. "anomaly_keywords": List of lowercase strings indicating a system bug/anomaly.
5. "security_keywords": List of lowercase strings indicating a security vulnerability/risk.
6. "timestamp_format": A python datetime format string (e.g. "%Y-%m-%d %H:%M:%S") or null.

Sample Content:
{sample_text}
"""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "qwen/qwen3.6-27b",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": 3000
    }
    for attempt in range(1, 5):
        timeout_sec = 60
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=timeout_sec)
            if r.status_code == 200:
                res_data = r.json()
                choices = res_data.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "").strip()
                    parsed = extract_and_parse_json(content)
                    if parsed and isinstance(parsed, dict) and "meaning" not in parsed:
                        return parsed
            elif r.status_code == 429:
                retry_after = r.headers.get("retry-after") or r.headers.get("Retry-After")
                try:
                    sleep_time = float(retry_after) if retry_after else (2 ** attempt)
                except ValueError:
                    sleep_time = 2 ** attempt
                sleep_time = min(sleep_time, 15.0)
                time.sleep(sleep_time)
                continue
            elif r.status_code in [401, 403]:
                import sys
                sys.stderr.write(f"Authentication/Permission error with Groq API: {r.status_code}\n")
                return None
            else:
                import sys
                sys.stderr.write(f"Groq API returned status code {r.status_code}\n")
        except requests.exceptions.Timeout:
            if attempt == 4:
                import sys
                sys.stderr.write("Groq API read timed out after multiple attempts.\n")
                return None
            time.sleep(1.0)
            continue
        except Exception as e:
            import sys
            sys.stderr.write(f"Error communicating with Groq API: {e}\n")
            time.sleep(1.0)
            continue
    return None

def parse_dynamic_log_line(line, line_num, config):
    if not line.strip():
        return None
    pattern_str = config.get("regex")
    if not pattern_str:
        is_anomaly = False
        anomaly_type = "System Bug"
        msg_lower = line.strip().lower()
        sec_kw = config.get("security_keywords") or []
        bug_kw = config.get("anomaly_keywords") or []
        if any(k in msg_lower for k in sec_kw):
            is_anomaly = True
            anomaly_type = "Security Anomaly"
        elif any(k in msg_lower for k in bug_kw):
            is_anomaly = True
            anomaly_type = "System Bug"
        return {
            "index": line_num,
            "timestamp": "",
            "level": "INFO",
            "component": "",
            "message": line.strip(),
            "raw": line.strip(),
            "is_anomaly": is_anomaly,
            "anomaly_type": anomaly_type
        }
    try:
        pattern = re.compile(pattern_str)
        match = pattern.match(line)
    except Exception:
        match = None
    if not match:
        is_anomaly = False
        anomaly_type = "System Bug"
        msg_lower = line.strip().lower()
        sec_kw = config.get("security_keywords") or []
        bug_kw = config.get("anomaly_keywords") or []
        if any(k in msg_lower for k in sec_kw):
            is_anomaly = True
            anomaly_type = "Security Anomaly"
        elif any(k in msg_lower for k in bug_kw):
            is_anomaly = True
            anomaly_type = "System Bug"
        return {
            "index": line_num,
            "timestamp": "",
            "level": "INFO",
            "component": "",
            "message": line.strip(),
            "raw": line.strip(),
            "is_anomaly": is_anomaly,
            "anomaly_type": anomaly_type
        }
    groups = match.groupdict()
    timestamp = groups.get("timestamp") or ""
    level = (groups.get("level") or "INFO").upper()
    component = groups.get("component") or ""
    message = groups.get("message") or ""
    if not message and not component and not level:
        message = line.strip()
    is_anomaly = False
    anomaly_type = "System Bug"
    msg_lower = message.lower()
    sec_kw = config.get("security_keywords") or []
    bug_kw = config.get("anomaly_keywords") or []
    if any(k in msg_lower for k in sec_kw):
        is_anomaly = True
        anomaly_type = "Security Anomaly"
    elif any(k in msg_lower for k in bug_kw) or level in ["ERROR", "CRITICAL", "FATAL"]:
        is_anomaly = True
        anomaly_type = "System Bug"
    return {
        "index": line_num,
        "timestamp": timestamp,
        "level": level,
        "component": component,
        "message": message,
        "raw": line.strip(),
        "is_anomaly": is_anomaly,
        "anomaly_type": anomaly_type
    }

def load_uploaded_file(uploaded_file, config):
    filename = uploaded_file.name.lower()
    records = []
    
    if filename.endswith(".pdf"):
        try:
            reader = pypdf.PdfReader(uploaded_file)
            text = ""
            for page in reader.pages:
                text += page.extract_text() or ""
            lines = text.splitlines()
            line_num = 1
            for line in lines:
                if len(records) >= 50000:
                    break
                parsed = parse_dynamic_log_line(line, line_num, config)
                if parsed:
                    records.append(parsed)
                    line_num += 1
        except Exception as e:
            import sys
            sys.stderr.write(f"Error parsing PDF: {e}\n")
            
    elif filename.endswith(".csv"):
        try:
            df = pd.read_csv(uploaded_file)
            for idx, row in df.iterrows():
                if idx >= 50000:
                    break
                message = str(row.get("message", row.get("Message", "")))
                level = str(row.get("level", row.get("Level", "INFO"))).upper()
                timestamp = str(row.get("timestamp", row.get("Timestamp", "")))
                component = str(row.get("component", row.get("Component", "")))
                
                is_anomaly = False
                anomaly_type = "System Bug"
                msg_lower = message.lower()
                
                sec_kw = config.get("security_keywords") or []
                bug_kw = config.get("anomaly_keywords") or []
                
                if any(k in msg_lower for k in sec_kw):
                    is_anomaly = True
                    anomaly_type = "Security Anomaly"
                elif any(k in msg_lower for k in bug_kw) or level in ["ERROR", "CRITICAL", "FATAL"]:
                    is_anomaly = True
                    anomaly_type = "System Bug"
                    
                records.append({
                    "index": idx + 1,
                    "timestamp": timestamp,
                    "level": level,
                    "component": component,
                    "message": message,
                    "raw": ", ".join(f"{col}: {val}" for col, val in row.items()),
                    "is_anomaly": is_anomaly,
                    "anomaly_type": anomaly_type
                })
        except Exception as e:
            import sys
            sys.stderr.write(f"Error parsing CSV: {e}\n")
            
    else:
        try:
            content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
            lines = content.splitlines()
            line_num = 1
            for line in lines:
                if len(records) >= 50000:
                    break
                parsed = parse_dynamic_log_line(line, line_num, config)
                if parsed:
                    records.append(parsed)
                    line_num += 1
        except Exception as e:
            import sys
            sys.stderr.write(f"Error parsing text file: {e}\n")
            
    return records
