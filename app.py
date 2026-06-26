import streamlit as st
import pandas as pd
import pypdf
import data_loader
from components.dashboard import render_dashboard
from components.triage import render_triage_stream

st.set_page_config(
    page_title="Log Analysis",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    code, pre, [class*="stCode"] {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stApp {
        background-color: #0b0f19;
        color: #f1f5f9;
    }
    
    section[data-testid="stSidebar"] {
        background-color: #020617;
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    h1, h2, h3 {
        font-family: 'Outfit', sans-serif;
        font-weight: 600 !important;
        letter-spacing: -0.5px;
    }
    
    hr {
        border-color: rgba(255, 255, 255, 0.08);
    }
    </style>
""", unsafe_allow_html=True)

st.markdown("""
<div style="margin-bottom: 25px;">
    <h1 style="margin: 0; font-size: 2.2rem; background: linear-gradient(to right, #60a5fa, #c084fc); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Log analysis</h1>
</div>
""", unsafe_allow_html=True)

def get_file_sample(uploaded_file):
    filename = uploaded_file.name.lower()
    sample_text = ""
    try:
        if filename.endswith(".pdf"):
            reader = pypdf.PdfReader(uploaded_file)
            if reader.pages:
                sample_text = reader.pages[0].extract_text() or ""
        elif filename.endswith(".csv"):
            df = pd.read_csv(uploaded_file, nrows=15)
            sample_text = df.to_string()
        else:
            sample_bytes = uploaded_file.read(3000)
            sample_text = sample_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        st.error(f"Error reading file sample: {e}")
    finally:
        uploaded_file.seek(0)
    return sample_text[:3000]

if "chunk_index" not in st.session_state:
    st.session_state["chunk_index"] = 0

st.sidebar.markdown("### Controller Panel")

uploaded_file = st.sidebar.file_uploader("Upload Log Dataset", type=["log", "txt", "csv", "pdf"])

if uploaded_file is not None:
    if "processed_data" not in st.session_state or st.session_state.get("uploaded_name") != uploaded_file.name or st.session_state.get("uploaded_size") != uploaded_file.size:
        st.session_state["uploaded_name"] = uploaded_file.name
        st.session_state["uploaded_size"] = uploaded_file.size
        st.session_state["triage_index"] = 0
        st.session_state["chunk_index"] = 0
        
        sample_text = get_file_sample(uploaded_file)
        
        fallback_config = {
            "file_type": "text",
            "regex": r"^(?P<timestamp>\S+)?\s*(?P<level>INFO|WARN|ERROR|CRITICAL|DEBUG|FATAL)?\s*(?P<component>\S+)?\s*(?P<message>.*)$",
            "columns": None,
            "anomaly_keywords": ["error", "fail", "exception", "critical", "fatal"],
            "security_keywords": ["unauthorized", "access denied", "forbidden", "login failed", "exploit", "vulnerability"],
            "timestamp_format": None
        }
        
        with st.spinner("Analyzing dataset format with Groq Qwen 3.6..."):
            config = data_loader.analyze_dataset_format(sample_text)
            
        if not config or not isinstance(config, dict):
            st.sidebar.warning("Could not analyze format with Groq (possibly due to API rate limits). Using default fallback settings. You can try re-uploading to retry.")
            config = fallback_config
        else:
            for key, val in fallback_config.items():
                if config.get(key) is None:
                    config[key] = val
                    
        with st.spinner("Loading and parsing logs..."):
            logs = data_loader.load_uploaded_file(uploaded_file, config)
            
        st.session_state["processed_data"] = {
            "logs": logs,
            "config": config
        }
    else:
        logs = st.session_state["processed_data"]["logs"]
        config = st.session_state["processed_data"]["config"]
        
    st.sidebar.markdown("### Config Metadata")
    st.sidebar.write(f"**Detected Type:** {config.get('file_type', 'unknown')}")
    st.sidebar.write(f"**Regex Pattern:** `{config.get('regex')}`")
    st.sidebar.write(f"**Security Keywords:** {len(config.get('security_keywords', []))}")
    st.sidebar.write(f"**Anomaly Keywords:** {len(config.get('anomaly_keywords', []))}")
    
    page_choice = st.sidebar.radio(
        "Navigation Mode:",
        ["Analytics Dashboard", "Live Triage Stream"],
        index=0
    )
    
    st.sidebar.markdown("---")
    
    st.sidebar.markdown("""
<div style="position: fixed; bottom: 20px; left: 20px; font-size: 0.8rem; color: #555577;">
    Engine Status: <span style="color: #10b981; font-weight: bold;">Active (Groq Qwen 3.6)</span>
</div>
""", unsafe_allow_html=True)

    try:
        if "Analytics Dashboard" in page_choice:
            st.markdown("## Dataset Analytics Dashboard")
            render_dashboard(logs)
        else:
            st.markdown("## Live Triage Stream")
            render_triage_stream(logs)
    except Exception as e:
        st.error(f"Failed to render application component: {e}")
        st.exception(e)
else:
    st.info("Please upload a log dataset (.log, .txt, .csv, .pdf) in the sidebar to begin analysis.")
    st.sidebar.markdown("---")
    st.sidebar.markdown("""
<div style="position: fixed; bottom: 20px; left: 20px; font-size: 0.8rem; color: #555577;">
    Engine Status: <span style="color: #10b981; font-weight: bold;">Active (Groq Qwen 3.6)</span>
</div>
""", unsafe_allow_html=True)
