import streamlit as st
from data_loader import get_qwen_explanation

def render_triage_stream(records, show_critical_only):
    if not records:
        st.warning("No logs loaded to triage.")
        return

    if show_critical_only:
        filtered_records = [r for r in records if r['is_anomaly'] and r['anomaly_type'] == 'Security Anomaly']
    else:
        filtered_records = records

    total_filtered = len(filtered_records)
    if total_filtered == 0:
        st.info("No logs match the current filters.")
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

    qwen_output = get_qwen_explanation(log_item['raw'])

    status_label = "local ollama qwen2.5-coder:7b Coprocessor Explanation"
    status_state = "running"
    if log_item['is_anomaly']:
        if log_item['anomaly_type'] == 'Security Anomaly':
            status_label = "CRITICAL VULNERABILITY EXPLAINED (Qwen 2.5 Coding 7B)"
            status_state = "error"
        else:
            status_label = "EXCEPTION STACK TRACE ANALYSIS (Qwen 2.5 Coding 7B)"
            status_state = "running"

    with st.status(status_label, state=status_state, expanded=True) as status:
        st.markdown("#### **Root Cause Meaning**")
        st.markdown(qwen_output['meaning'])
        st.markdown("#### **Remediation & Patch Instructions**")
        st.markdown(qwen_output['fix'])
        
        final_state = "error" if (log_item['is_anomaly'] and log_item['anomaly_type'] == 'Security Anomaly') else "complete"
        status.update(label=status_label, state=final_state, expanded=True)
