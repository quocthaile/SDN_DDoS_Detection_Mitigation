import streamlit as st
import pandas as pd
import psutil
import time
import os
import altair as alt
from datetime import datetime
import warnings

# --- TẮT CẢNH BÁO ---
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)

st.set_page_config(
    page_title="SDN AI-Guard Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CẤU HÌNH ĐƯỜNG DẪN ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR) if os.path.exists(os.path.join(os.path.dirname(BASE_DIR), 'attack_log')) else BASE_DIR

ATTACK_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'attack_logs.csv')
HISTORY_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'offender_history.csv')
MANUAL_BLOCK_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'manual_blocks.txt')
DDOS_DATASET_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'ddos_captured_dataset.csv')
TRAFFIC_MONITOR_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'traffic_monitor.csv')
AI_PREDICT_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'ai_predict.csv')
FIREWALL_STATUS_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'firewall_status.txt')

st.markdown("""<style>.stApp { background-color: #0E1117; color: #FAFAFA; } .metric-card { background-color: #262730; padding: 10px; border-radius: 5px; } .stButton>button { width: 100%; border-radius: 5px; }</style>""", unsafe_allow_html=True)

if 'traffic_history' not in st.session_state: st.session_state.traffic_history = pd.DataFrame(columns=['Time', 'Speed_MBps', 'Type'])
if 'last_time' not in st.session_state: st.session_state.last_time = time.time()

# --- HÀM HỖ TRỢ ---
def load_data(filepath):
    if not os.path.exists(filepath): return pd.DataFrame()
    try:
        if os.path.getsize(filepath) == 0: return pd.DataFrame()
        return pd.read_csv(filepath, on_bad_lines='skip', engine='python')
    except: return pd.DataFrame()

def save_manual_block(ip):
    try:
        with open(MANUAL_BLOCK_FILE, "a") as f: f.write(f"{ip}\n"); f.flush()
        return True
    except Exception as e: st.error(f"Lỗi: {e}"); return False

def clear_all_logs():
    try:
        files = [ATTACK_LOG_FILE, HISTORY_LOG_FILE, MANUAL_BLOCK_FILE, TRAFFIC_MONITOR_FILE, AI_PREDICT_LOG_FILE]
        for f in files:
            if os.path.exists(f): os.remove(f)
        return True
    except Exception as e: st.error(f"Lỗi xóa log: {e}"); return False

def delete_dataset():
    try:
        if os.path.exists(DDOS_DATASET_FILE): os.remove(DDOS_DATASET_FILE); return True
        return False
    except Exception as e: st.error(f"Lỗi xóa dataset: {e}"); return False

def get_firewall_state():
    if not os.path.exists(FIREWALL_STATUS_FILE): return True
    try:
        with open(FIREWALL_STATUS_FILE, "r") as f: return f.read().strip().upper() == "ON"
    except: return True

def set_firewall_state(state):
    try:
        with open(FIREWALL_STATUS_FILE, "w") as f: f.write("ON" if state else "OFF"); f.flush()
    except Exception as e: st.error(f"Lỗi ghi trạng thái FW: {e}")

# Hàm Format đơn vị thông minh
def format_speed(mbps):
    if mbps >= 1024:
        return f"{mbps/1024:.2f} Gbps"
    elif mbps < 1 and mbps > 0:
        return f"{mbps*1024:.2f} Kbps"
    elif mbps == 0:
        return "0 Kbps"
    else:
        return f"{mbps:.2f} Mbps"

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ Control Panel")
    st.subheader("⚙️ System Control")
    current_fw_state = get_firewall_state()
    new_fw_state = st.toggle("Firewall Active", value=current_fw_state)
    if new_fw_state != current_fw_state: set_firewall_state(new_fw_state); st.rerun()
    if new_fw_state: st.success("✅ Firewall is ON")
    else: st.error("⚠️ Firewall is OFF")
    st.divider()
    st.subheader("Manual Blocking")
    with st.form("block_form", clear_on_submit=True):
        ip_input = st.text_input("IP Address:", placeholder="e.g., 10.0.0.5", disabled=not new_fw_state)
        submitted = st.form_submit_button("🚫 Block IP Now", disabled=not new_fw_state)
        if submitted and ip_input:
            if save_manual_block(ip_input): st.success(f"Đã gửi lệnh chặn: {ip_input}"); time.sleep(0.5)
    st.divider()
    st.subheader("💾 Dataset Management")
    c1, c2 = st.columns(2)
    with c1:
        if os.path.exists(DDOS_DATASET_FILE):
            with open(DDOS_DATASET_FILE, "rb") as f: st.download_button("📥 Download", f, "ddos_captured_dataset.csv", "text/csv")
        else: st.button("📥 Download", disabled=True)
    with c2:
        if st.button("🗑️ Delete Data"):
            if delete_dataset(): st.success("Deleted!"); time.sleep(1); st.rerun()
            else: st.warning("File not found")
    st.divider()
    if st.button("🗑️ Clear All Logs & History"):
        if clear_all_logs(): st.success("System Cleaned!"); time.sleep(1); st.rerun()
    st.caption("✅ System Active | Refresh: 1s")

# --- MAIN PAGE ---
st.title("SDN AI-Guard Monitoring Center")
df_attacks = load_data(ATTACK_LOG_FILE)
df_history = load_data(HISTORY_LOG_FILE)
system_state = "SAFE"
if not df_attacks.empty and 'timestamp' in df_attacks.columns:
    try:
        last_row = df_attacks.iloc[-1]
        if time.time() - float(last_row['timestamp']) < 30:
            label = str(last_row['label'])
            if label == "Attack": system_state = "CRITICAL"
            elif label in ["Warning", "Suspicious"]: system_state = "WARNING"
    except: pass

def load_traffic_monitor():
    if not os.path.exists(TRAFFIC_MONITOR_FILE): return pd.DataFrame()
    try:
        df = pd.read_csv(TRAFFIC_MONITOR_FILE, on_bad_lines='skip')
        required_cols = ['Blocked_MBps', 'Allowed_Attack_MBps', 'Benign_MBps']
        if not all(col in df.columns for col in required_cols): return pd.DataFrame()
        df = df.tail(60).reset_index(drop=True)
        df['Sequence'] = df.index 
        return df
    except: return pd.DataFrame()

df_traffic = load_traffic_monitor()
curr_blocked = 0.0
curr_allowed_attack = 0.0
curr_benign = 0.0

if not df_traffic.empty:
    curr_blocked = df_traffic.iloc[-1]['Blocked_MBps']
    curr_allowed_attack = df_traffic.iloc[-1]['Allowed_Attack_MBps']
    curr_benign = df_traffic.iloc[-1]['Benign_MBps']

# [DYNAMIC METRICS]
c1, c2, c3, c4 = st.columns(4)
with c1:
    if not new_fw_state: st.metric("System Status", "DISABLED", delta="Off", delta_color="off")
    elif system_state == "CRITICAL": st.metric("System Status", "UNDER ATTACK", delta="- CRITICAL", delta_color="inverse")
    elif system_state == "WARNING": st.metric("System Status", "SUSPICIOUS", delta="! WARNING", delta_color="off")
    else: st.metric("System Status", "SECURE", delta="Active")
with c2: 
    if curr_allowed_attack > 0:
        st.metric("Allowed Attack", format_speed(curr_allowed_attack), delta="Risk!", delta_color="inverse")
    else:
        st.metric("Malicious IPs", df_attacks['ip_src'].nunique() if not df_attacks.empty else 0)
        
with c3: st.metric("Blocked Traffic", format_speed(curr_blocked), delta="Stopped", delta_color="normal")
with c4: st.metric("Benign Traffic", format_speed(curr_benign), delta="Clean")

# --- CHART (DYNAMIC SCALING & FIXED WIDTH) ---
st.divider()
if not df_traffic.empty:
    # Tính toán đơn vị phù hợp
    max_val = df_traffic[['Blocked_MBps', 'Allowed_Attack_MBps', 'Benign_MBps']].max().max()
    scale_factor = 1.0
    unit_label = "Mbps"
    if max_val >= 1024:
        scale_factor = 1024.0
        unit_label = "Gbps"
    elif max_val < 1: 
        scale_factor = 1/1024.0
        unit_label = "Kbps"
    
    df_melt = df_traffic.melt('Sequence', value_vars=['Blocked_MBps', 'Allowed_Attack_MBps', 'Benign_MBps'], var_name='Type', value_name='Original_MBps')
    df_melt['Value'] = df_melt['Original_MBps'] / scale_factor
    df_melt['Type'] = df_melt['Type'].replace({
        'Blocked_MBps': 'Blocked Attack (Red)',
        'Allowed_Attack_MBps': 'Allowed Attack (Orange)',
        'Benign_MBps': 'Benign Traffic (Green)'
    })
    
    base = alt.Chart(df_melt).encode(
        x=alt.X('Sequence', axis=alt.Axis(title='60 Seconds Window', labels=False, grid=True, tickCount=10), scale=alt.Scale(domain=[0, 60])),
        y=alt.Y('Value', title=f'Throughput ({unit_label})', stack=None, axis=alt.Axis(grid=True)),
        color=alt.Color('Type', 
            scale=alt.Scale(
                domain=['Blocked Attack (Red)', 'Allowed Attack (Orange)', 'Benign Traffic (Green)'], 
                range=['#d62728', '#ff7f0e', '#2ca02c']
            ), 
            legend=alt.Legend(title="Traffic Status", orient="top-left")
        ),
        tooltip=[
            alt.Tooltip('Type', title='Type'),
            alt.Tooltip('Value', title=f'Speed ({unit_label})', format='.2f')
        ]
    )
    
    area = base.mark_area(opacity=0.3, interpolate='monotone')
    line = base.mark_line(opacity=1.0, strokeWidth=2, interpolate='monotone')
    chart = (area + line).properties(height=350)

    # [FIX] Sử dụng width="stretch" để sửa lỗi
    try: 
        st.altair_chart(chart, width="stretch")
    except: 
        st.altair_chart(chart, use_container_width=True)
else: st.info("Waiting for traffic data stream...")

st.divider()
c1, c2 = st.columns([3, 1])
with c1:
    if system_state == "WARNING": st.subheader("⚠️ Suspicious Activity")
    elif system_state == "CRITICAL": st.subheader("🚨 CRITICAL: Attack In Progress")
    else: st.subheader("📋 Traffic Logs")
with c2:
    if not df_attacks.empty:
        csv_data = df_attacks.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download Logs", csv_data, 'attack_logs.csv', 'text/csv', key='dl_logs')

if not df_attacks.empty:
    try:
        df_display = df_attacks.copy().sort_values(by='timestamp', ascending=False)
        cols = ['timestamp', 'ip_src', 'ip_dst', 'ip_proto', 'packet_count', 'label', 'reason']
        valid_cols = [c for c in cols if c in df_display.columns]
        if 'timestamp' in df_display.columns:
            df_display['timestamp'] = df_display['timestamp'].apply(lambda x: datetime.fromtimestamp(float(x)).strftime('%H:%M:%S') if pd.notnull(x) else x)
        
        # [FIX] Sử dụng width="stretch" cho dataframe
        try: 
            st.dataframe(df_display[valid_cols].head(8), width="stretch", hide_index=True)
        except: 
            st.dataframe(df_display[valid_cols].head(8), use_container_width=True, hide_index=True)
    except: st.dataframe(df_attacks.tail(8))
else: st.info("System is clean.")

st.divider()
st.subheader("🚫 Blocked IP History")
if not df_history.empty:
    # [FIX] Sử dụng width="stretch" cho dataframe
    try: 
        st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), width="stretch", hide_index=True)
    except: 
        st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), use_container_width=True, hide_index=True)

time.sleep(1)
st.rerun()