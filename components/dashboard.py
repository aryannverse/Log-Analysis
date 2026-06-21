import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def render_dashboard(records):
    if not records:
        st.warning("No logs available for analysis.")
        return

    df = pd.DataFrame(records)
    df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
    total_logs = len(df)
    error_logs = len(df[df['level'].isin(['ERROR', 'CRITICAL'])])
    warn_logs = len(df[df['level'] == 'WARN'])
    
    sec_anom_df = df[df['is_anomaly'] == True]
    security_anom_count = len(sec_anom_df[sec_anom_df['anomaly_type'] == 'Security Anomaly'])
    system_bug_count = len(sec_anom_df[sec_anom_df['anomaly_type'] == 'System Bug'])
    
    st.markdown("""
        <style>
        .metric-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            text-align: center;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
        }
        .metric-value {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 5px;
            color: #ffffff;
        }
        .metric-label {
            font-size: 0.9rem;
            color: #8888aa;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        </style>
    """, unsafe_allow_html=True)
    
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #60a5fa;">{total_logs:,}</div><div class="metric-label">Total Logs Parsed</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #f87171;">{error_logs:,}</div><div class="metric-label">Errors / Critical</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #fbbf24;">{warn_logs:,}</div><div class="metric-label">Warnings</div></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #34d399;">{security_anom_count:,}</div><div class="metric-label">Security Anomalies</div></div>', unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("Log Intensity & Levels Over Time")
        if df['datetime'].notnull().sum() > 0:
            df_time = df.dropna(subset=['datetime']).copy()
            time_diff = df_time['datetime'].max() - df_time['datetime'].min()
            if time_diff.days > 7:
                freq = 'D'
            elif time_diff.days > 1:
                freq = 'h'
            else:
                freq = 'min'
                
            time_grouped = df_time.groupby([pd.Grouper(key='datetime', freq=freq), 'level']).size().reset_index(name='count')
            fig_time = px.line(
                time_grouped, 
                x='datetime', 
                y='count', 
                color='level',
                color_discrete_map={
                    'INFO': '#60a5fa', 
                    'WARN': '#fbbf24', 
                    'ERROR': '#f87171', 
                    'CRITICAL': '#ec4899'
                },
                labels={'datetime': 'Timestamp', 'count': 'Log Count', 'level': 'Level'},
                template='plotly_dark'
            )
            fig_time.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=20, r=20, t=10, b=20),
                height=300
            )
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("Time-series visualization not available due to missing or invalid timestamps.")

    with c2:
        st.subheader("Log Level Distribution")
        level_counts = df['level'].value_counts().reset_index(name='count')
        fig_pie = px.pie(
            level_counts, 
            values='count', 
            names='level', 
            hole=0.4,
            color='level',
            color_discrete_map={
                'INFO': '#60a5fa', 
                'WARN': '#fbbf24', 
                'ERROR': '#f87171', 
                'CRITICAL': '#ec4899'
            },
            template='plotly_dark'
        )
        fig_pie.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=20, r=20, t=10, b=20),
            height=300
        )
        st.plotly_chart(fig_pie, use_container_width=True)
        
    c3, c4 = st.columns(2)
    
    with c3:
        st.subheader("Anomalies vs bugs breakdown")
        anomaly_counts = pd.DataFrame([
            {"Type": "Security Anomaly", "Count": security_anom_count},
            {"Type": "System Bug", "Count": system_bug_count}
        ])
        fig_bar_anom = px.bar(
            anomaly_counts, 
            x='Type', 
            y='Count', 
            color='Type',
            color_discrete_map={
                'Security Anomaly': '#10b981', 
                'System Bug': '#ef4444'
            },
            template='plotly_dark'
        )
        fig_bar_anom.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            showlegend=False,
            margin=dict(l=20, r=20, t=10, b=20),
            height=300
        )
        st.plotly_chart(fig_bar_anom, use_container_width=True)
        
    with c4:
        st.subheader("Top 5 Most Frequent Components")
        comp_counts = df['component'].value_counts().head(5).reset_index(name='count')
        fig_comp = px.bar(
            comp_counts, 
            x='count', 
            y='component', 
            orientation='h',
            labels={'count': 'Occurrence Count', 'component': 'Component'},
            template='plotly_dark'
        )
        fig_comp.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            yaxis={'categoryorder': 'total ascending'},
            margin=dict(l=20, r=20, t=10, b=20),
            height=300
        )
        st.plotly_chart(fig_comp, use_container_width=True)
        
    st.markdown("### Detected Anomalies (Sample)")
    anom_df = df[df['is_anomaly'] == True].head(10)[['timestamp', 'level', 'anomaly_type', 'component', 'message']]
    if not anom_df.empty:
        st.dataframe(anom_df, hide_index=True)
    else:
        st.success("No anomalies detected in the parsed dataset range!")
