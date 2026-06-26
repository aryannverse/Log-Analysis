import streamlit as st
from data_loader import get_groq_explanation

def render_triage_stream(records):
    if not records:
        st.warning("No logs loaded to triage.")
        return
    filtered_records = [r for r in records if r.get("is_anomaly") and r.get("anomaly_type") == "Security Anomaly"]
    total_filtered = len(filtered_records)
    if total_filtered == 0:
        st.info("No security anomalies found in this dataset.")
        return

    state_key = "triage_index"
    if state_key not in st.session_state:
        st.session_state[state_key] = 0
        
    if st.session_state[state_key] >= total_filtered:
        st.session_state[state_key] = total_filtered - 1
    if st.session_state[state_key] < 0:
        st.session_state[state_key] = 0

    current_idx = st.session_state[state_key]
    log_item = filtered_records[current_idx]




    col_nav_1, col_nav_2, col_nav_3 = st.columns([1, 2, 1])
    
    with col_nav_1:
        if st.button("Previous", disabled=(current_idx == 0), use_container_width=True):
            st.session_state[state_key] -= 1
            st.rerun()
            
    with col_nav_2:
        st.markdown(f"<h3 style='text-align: center; margin-top: 0;'>Log Entry {current_idx + 1} of {total_filtered}</h3>", unsafe_allow_html=True)
        
    with col_nav_3:
        if st.button("Next", disabled=(current_idx == total_filtered - 1), use_container_width=True):
            st.session_state[state_key] += 1
            st.rerun()

    st.markdown("### Live Triage Inspector")
    st.write(f"**Timestamp:** `{log_item['timestamp']}` | **Level:** `{log_item['level']}` | **Component:** `{log_item['component']}`")

    st.markdown("**Raw Log Payload:**")
    st.code(log_item['raw'], language="text")

    with st.spinner("Analyzing log with Groq Qwen 3.6..."):
        groq_output = get_groq_explanation(log_item['raw'])

    status_label = "Groq Qwen 3.6 Coprocessor Explanation"
    status_state = "running"
    if log_item['is_anomaly']:
        if log_item['anomaly_type'] == 'Security Anomaly':
            status_label = "CRITICAL VULNERABILITY EXPLAINED (Groq Qwen 3.6)"
            status_state = "error"
        else:
            status_label = "EXCEPTION STACK TRACE ANALYSIS (Groq Qwen 3.6)"
            status_state = "running"

    with st.status(status_label, state=status_state, expanded=True) as status:
        st.markdown("#### **Root Cause Meaning**")
        st.markdown(groq_output.get('meaning', 'No meaning extracted.'))
        st.markdown("#### **Remediation & Patch Instructions**")
        st.markdown(groq_output.get('fix', 'No remediation instructions provided.'))
        
        final_state = "error" if (log_item['is_anomaly'] and log_item['anomaly_type'] == 'Security Anomaly') else "complete"
        status.update(label=status_label, state=final_state, expanded=True)
