import os
import re
import json
import requests
import httpx
from dotenv import load_dotenv
from functools import lru_cache
from datetime import datetime, timedelta
import pandas as pd

load_dotenv()
HF_TOKEN = os.getenv("HF_TOKEN", "")

BASE_DIR = "/Users/vermaryan1/Desktop/CODING/Log Analysis/Dataset"
APACHE_PATH = os.path.join(BASE_DIR, "Apache/Apache.log")
HDFS_PATH = os.path.join(BASE_DIR, "HDFS/HDFS_v1/HDFS.log")
OPENSTACK_PATH = os.path.join(BASE_DIR, "OpenStack/openstack_abnormal.log")
OPENSTACK_ANOMALY_LABELS_PATH = os.path.join(BASE_DIR, "OpenStack/anomaly_labels.txt")

HDFS_REGEX = re.compile(r"^(\d{6})\s+(\d{6})\s+(\d+)\s+(\w+)\s+([^:]+):\s*(.*)$")
APACHE_REGEX = re.compile(r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)$")
OPENSTACK_REGEX = re.compile(r"^(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\d+)\s+(\w+)\s+(\S+)\s+\[([^\]]*)\]\s+(.*)$")

def get_openstack_anomalies():
    anomalies = set()
    if os.path.exists(OPENSTACK_ANOMALY_LABELS_PATH):
        try:
            with open(OPENSTACK_ANOMALY_LABELS_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("The following"):
                        anomalies.add(line)
        except Exception:
            pass
    if not anomalies:
        anomalies = {
            "544fd51c-4edc-4780-baae-ba1d80a0acfc",
            "ae651dff-c7ad-43d6-ac96-bbcd820ccca8",
            "a445709b-6ad0-40ec-8860-bec60b6ca0c2",
            "1643649d-2f42-4303-bfcd-7798baec19f9"
        }
    return anomalies

OPENSTACK_ANOMALIES = get_openstack_anomalies()

def parse_hdfs_line(line, line_num):
    match = HDFS_REGEX.match(line)
    if not match:
        return None
    
    date_str, time_str, thread_id, level, component, message = match.groups()
    
    try:
        dt = datetime.strptime(f"{date_str} {time_str}", "%y%m%d %H%M%S")
        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        timestamp = f"2008-11-09 {time_str[:2]}:{time_str[2:4]}:{time_str[4:6]}"

    level = level.upper()
    if level not in ["INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"]:
        level = "INFO"
    if level == "WARNING":
        level = "WARN"
    elif level == "FATAL":
        level = "CRITICAL"

    is_anomaly = False
    anomaly_type = "System Bug"
    
    msg_lower = message.lower()
    if any(k in msg_lower for k in ["accesscontrolexception", "unauthorized", "permission denied", "verification failed"]):
        is_anomaly = True
        anomaly_type = "Security Anomaly"
    elif "missing" in msg_lower and "block" in msg_lower:
        is_anomaly = True
        anomaly_type = "Security Anomaly"
    elif level in ["ERROR", "CRITICAL"]:
        is_anomaly = True
        anomaly_type = "System Bug"

    return {
        "index": line_num,
        "timestamp": timestamp,
        "level": level,
        "component": component.strip(),
        "message": message.strip(),
        "raw": line.strip(),
        "is_anomaly": is_anomaly,
        "anomaly_type": anomaly_type
    }

def parse_apache_line(line, line_num):
    match = APACHE_REGEX.match(line)
    if not match:
        return None
    
    time_str, level, rest = match.groups()
    
    try:
        dt = datetime.strptime(time_str, "%a %b %d %H:%M:%S %Y")
        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        timestamp = time_str

    level = level.lower()
    if "error" in level:
        level_mapped = "ERROR"
    elif "notice" in level:
        level_mapped = "INFO"
    elif "warn" in level:
        level_mapped = "WARN"
    elif "crit" in level or "emerg" in level or "alert" in level:
        level_mapped = "CRITICAL"
    else:
        level_mapped = "INFO"

    component = "core"
    message = rest
    
    client_match = re.match(r"^\[client\s+([^\]]+)\]\s+(.*)$", rest)
    if client_match:
        client_ip, message = client_match.groups()
        component = f"client:{client_ip}"
    else:
        comp_match = re.match(r"^([^:\s]+(?:\(\))?):?\s+(.*)$", rest)
        if comp_match:
            comp_candidate, msg_candidate = comp_match.groups()
            if len(comp_candidate) < 30 and "/" not in comp_candidate:
                component = comp_candidate
                message = msg_candidate

    is_anomaly = False
    anomaly_type = "System Bug"
    msg_lower = message.lower()
    
    if any(k in msg_lower for k in ["../", "uri too long", "mod_security", "script not found", "authentication failed", "invalid user", "forbidden", "union select", "nmap"]):
        is_anomaly = True
        anomaly_type = "Security Anomaly"
    elif level_mapped in ["ERROR", "CRITICAL"]:
        is_anomaly = True
        anomaly_type = "System Bug"

    return {
        "index": line_num,
        "timestamp": timestamp,
        "level": level_mapped,
        "component": component.strip(),
        "message": message.strip(),
        "raw": line.strip(),
        "is_anomaly": is_anomaly,
        "anomaly_type": anomaly_type
    }

def parse_openstack_line(line, line_num):
    match = OPENSTACK_REGEX.match(line)
    if not match:
        return None
    
    log_src, time_str, pid, level, component, req_context, message = match.groups()
    
    try:
        if "." in time_str:
            dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S.%f")
        else:
            dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        timestamp = time_str

    level = level.upper()
    if level not in ["INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"]:
        level = "INFO"
    if level == "WARNING":
        level = "WARN"
    elif level == "FATAL":
        level = "CRITICAL"

    is_anomaly = False
    anomaly_type = "System Bug"
    
    has_anomaly_vm = False
    for vm_id in OPENSTACK_ANOMALIES:
        if vm_id in line:
            has_anomaly_vm = True
            break
            
    msg_lower = message.lower()
    if has_anomaly_vm:
        is_anomaly = True
        anomaly_type = "Security Anomaly"
    elif any(k in msg_lower for k in ["unauthorized", "forbidden", "policy check failed", "access denied"]):
        is_anomaly = True
        anomaly_type = "Security Anomaly"
    elif level in ["ERROR", "CRITICAL"]:
        is_anomaly = True
        anomaly_type = "System Bug"

    return {
        "index": line_num,
        "timestamp": timestamp,
        "level": level,
        "component": component.strip(),
        "message": message.strip(),
        "raw": line.strip(),
        "is_anomaly": is_anomaly,
        "anomaly_type": anomaly_type
    }

def load_logs(dataset_name, chunk_index=0, chunk_size=30000):
    records = []
    
    if dataset_name == "HDFS":
        file_path = HDFS_PATH
        parse_func = parse_hdfs_line
    elif dataset_name == "Apache":
        file_path = APACHE_PATH
        parse_func = parse_apache_line
    elif dataset_name == "OpenStack":
        file_path = OPENSTACK_PATH
        parse_func = parse_openstack_line
    else:
        raise ValueError(f"Unknown dataset name: {dataset_name}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found at: {file_path}")

    start_line_idx = chunk_index * chunk_size

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            line_num = 1
            parsed_count = 0
            for line in f:
                if line_num <= start_line_idx:
                    line_num += 1
                    continue
                
                parsed = parse_func(line, line_num)
                if parsed:
                    records.append(parsed)
                    parsed_count += 1
                line_num += 1
                if parsed_count >= chunk_size:
                    break
    except Exception as e:
        raise e

    return records

_hf_explanation_cache = {}

def clean_json_string(s):
    s = s.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    return s

async def get_hf_explanation(raw_log):
    if raw_log in _hf_explanation_cache:
        return _hf_explanation_cache[raw_log]

    if not HF_TOKEN or HF_TOKEN == "your_hugging_face_token_here":
        return {
            "meaning": "Hugging Face API token is missing or not configured.",
            "fix": "Please create a `.env` file in the project root and set `HF_TOKEN=your_huggingface_token`."
        }

    prompt = f"""<|im_start|>system
You are an expert security engineer and system reliability expert.
Analyze the following raw log line and explain its meaning and fix.
You must output a JSON object with exactly two keys:
1. "meaning": A clear, human-readable explanation of the stack trace, warning, error, or vulnerability.
2. "fix": Actionable, step-by-step remediation or patch instructions.

Format:
{{
  "meaning": "...",
  "fix": "..."
}}
<|im_end|>
<|im_start|>user
Raw Log:
{raw_log}
<|im_end|>
<|im_start|>assistant
"""

    url = "https://api-inference.huggingface.co/models/Qwen/Qwen2.5-Coder-7B-Instruct"
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    
    for attempt, timeout_sec in enumerate([30, 60], start=1):
        try:
            payload = {
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": 800,
                    "temperature": 0.1,
                    "return_full_text": False
                }
            }
            async with httpx.AsyncClient() as client:
                r = await client.post(url, json=payload, headers=headers, timeout=timeout_sec)
                
            if r.status_code == 200:
                res_data = r.json()
                if isinstance(res_data, list) and len(res_data) > 0:
                    response_text = res_data[0].get("generated_text", "").strip()
                elif isinstance(res_data, dict):
                    response_text = res_data.get("generated_text", "").strip()
                else:
                    response_text = ""
                
                try:
                    cleaned_text = clean_json_string(response_text)
                    parsed = json.loads(cleaned_text)
                    meaning = parsed.get("meaning")
                    fix = parsed.get("fix")
                    if meaning and fix:
                        result = {"meaning": meaning, "fix": fix}
                        _hf_explanation_cache[raw_log] = result
                        return result
                except Exception:
                    result = {
                        "meaning": response_text,
                        "fix": "Could not parse structured JSON from Hugging Face response. Please inspect the raw output above."
                    }
                    _hf_explanation_cache[raw_log] = result
                    return result
            elif r.status_code == 503:
                if attempt == 1:
                    import asyncio
                    await asyncio.sleep(5)
                    continue
                else:
                    return {
                        "meaning": "Hugging Face model is currently loading on the server.",
                        "fix": "The Serverless Inference API is starting up the model. Please wait a few seconds and try again."
                    }
            else:
                return {
                    "meaning": f"Hugging Face API returned error status {r.status_code}: {r.text}",
                    "fix": "Check your HF_TOKEN permissions and ensure the Serverless Inference API is available."
                }
        except httpx.TimeoutException:
            if attempt == 2:
                return {
                    "meaning": "Hugging Face API read timed out after multiple attempts.",
                    "fix": "The Hugging Face server took too long to respond. Please check your internet connection or try again."
                }
            continue
        except Exception as e:
            return {
                "meaning": f"Error communicating with Hugging Face API: {e}",
                "fix": "Verify that your internet connection is active and that your HF_TOKEN is valid."
            }

    return {
        "meaning": "Unable to extract response from Hugging Face model.",
        "fix": "Check model availability and token configuration."
    }
