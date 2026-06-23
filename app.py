import streamlit as st
from data_loader import load_logs
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

if "chunk_index" not in st.session_state:
    st.session_state["chunk_index"] = 0

st.sidebar.markdown("### Controller Panel")

dataset_choice = st.sidebar.selectbox(
    "Choose Target Log Source:",
    ["HDFS", "Apache", "OpenStack"],
    index=0
)

if "prev_dataset" not in st.session_state:
    st.session_state["prev_dataset"] = dataset_choice
elif st.session_state["prev_dataset"] != dataset_choice:
    st.session_state["chunk_index"] = 0
    st.session_state["prev_dataset"] = dataset_choice
    if "triage_index" in st.session_state:
        st.session_state["triage_index"] = 0

@st.cache_data(show_spinner="Parsing log streams...")
def get_cached_logs(source, chunk_idx):
    return load_logs(source, chunk_index=chunk_idx, chunk_size=30000)

try:
    with st.spinner("Processing source logs..."):
        logs = get_cached_logs(dataset_choice, st.session_state["chunk_index"])
except Exception as e:
    st.error(f"Failed to load logs: {e}")
    logs = []

if dataset_choice == "HDFS" and logs:
    st.sidebar.markdown("### HDFS Log Segment")
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("Previous 30K", disabled=(st.session_state["chunk_index"] == 0), use_container_width=True):
            st.session_state["chunk_index"] -= 1
            if "triage_index" in st.session_state:
                st.session_state["triage_index"] = 0
            st.rerun()
    with col2:
        if st.button("Next 30K", disabled=(len(logs) < 30000), use_container_width=True):
            st.session_state["chunk_index"] += 1
            if "triage_index" in st.session_state:
                st.session_state["triage_index"] = 0
            st.rerun()
    
    start_num = st.session_state["chunk_index"] * 30000 + 1
    end_num = start_num + len(logs) - 1
    st.sidebar.caption(f"Logs {start_num:,} to {end_num:,}")

page_choice = st.sidebar.radio(
    "Navigation Mode:",
    ["Analytics Dashboard", "Live Triage Stream"],
    index=0
)

st.sidebar.markdown("---")

show_critical_only = False
if "Live Triage Stream" in page_choice:
    st.sidebar.markdown("### Stream Filters")
    show_critical_only = st.sidebar.checkbox(
        "Show Critical Vulnerabilities Only",
        value=False,
        help="Filters the feed strictly to security risks (directory traversal, block loss exploit labels, etc.)"
    )

st.sidebar.markdown("""
<div style="position: fixed; bottom: 20px; left: 20px; font-size: 0.8rem; color: #555577;">
    Engine Status: <span style="color: #10b981; font-weight: bold;">Active (Qwen 7B)</span>
</div>
""", unsafe_allow_html=True)

try:
    if "Analytics Dashboard" in page_choice:
        st.markdown("## Dataset Analytics Dashboard")
        render_dashboard(logs)
    else:
        st.markdown("## Live Triage Stream")
        render_triage_stream(logs, show_critical_only)

except Exception as e:
    st.error(f"Failed to render application component: {e}")
    st.exception(e)
