import os
import re
import json
import requests
from functools import lru_cache
from datetime import datetime, timedelta
import pandas as pd

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

@lru_cache(maxsize=1024)
def get_qwen_explanation(raw_log):
    prompt = f"""You are an expert security engineer and system reliability expert.
Analyze the following raw log line and explain its meaning and fix.
You must output a JSON object with exactly two keys:
1. "meaning": A clear, human-readable explanation of the stack trace, warning, error, or vulnerability.
2. "fix": Actionable, step-by-step remediation or patch instructions.

Raw Log:
{raw_log}

JSON output:
"""
    try:
        payload = {
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "format": "json",
            "stream": False
        }
        r = requests.post("http://localhost:11434/api/generate", json=payload, timeout=15)
        if r.status_code == 200:
            res_data = r.json()
            response_text = res_data.get("response", "").strip()
            parsed = json.loads(response_text)
            meaning = parsed.get("meaning")
            fix = parsed.get("fix")
            if meaning and fix:
                return {
                    "meaning": meaning,
                    "fix": fix
                }
    except Exception as e:
        return {
            "meaning": f"Error communicating with local Qwen model: {e}",
            "fix": "Ensure Ollama is running locally with the qwen2.5-coder:7b model loaded."
        }

    return {
        "meaning": "Unable to extract response from Qwen model.",
        "fix": "Check model availability and parameters."
    }
