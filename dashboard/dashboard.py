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

st.set_page_config(
    page_title="SDN AI-Guard Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CẤU HÌNH ĐƯỜNG DẪN ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Logic tìm thư mục gốc thông minh
if os.path.exists(os.path.join(CURRENT_DIR, 'attack_log')):
    PROJECT_ROOT = CURRENT_DIR
elif os.path.exists(os.path.join(os.path.dirname(CURRENT_DIR), 'attack_log')):
    PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
else:
    PROJECT_ROOT = CURRENT_DIR

ATTACK_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'attack_logs.csv')
HISTORY_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'offender_history.csv')
MANUAL_BLOCK_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'manual_blocks.txt')
DDOS_DATASET_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'ddos_captured_dataset.csv')

# --- CSS ---
st.markdown("""
    <style>
    .stApp { background-color: #0E1117; color: #FAFAFA; }
    .metric-card { background-color: #262730; padding: 10px; border-radius: 5px; }
    .stButton>button { width: 100%; }
    </style>
    """, unsafe_allow_html=True)

# --- KHỞI TẠO STATE ---
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = pd.DataFrame(columns=['Time', 'Speed_MBps', 'Type'])
if 'last_net_io' not in st.session_state:
    st.session_state.last_net_io = psutil.net_io_counters().bytes_recv
if 'last_time' not in st.session_state:
    st.session_state.last_time = time.time()
if 'csv_cache' not in st.session_state:
    st.session_state.csv_cache = None

# --- HÀM HỖ TRỢ ---
def load_data(filepath):
    if not os.path.exists(filepath): return pd.DataFrame()
    try:
        if os.path.getsize(filepath) == 0: return pd.DataFrame()
        return pd.read_csv(filepath, on_bad_lines='skip', engine='python')
    except: return pd.DataFrame()

def save_manual_block(ip):
    try:
        os.makedirs(os.path.dirname(MANUAL_BLOCK_FILE), exist_ok=True)
        with open(MANUAL_BLOCK_FILE, "a") as f:
            f.write(f"{ip}\n")
        return True
    except Exception as e:
        st.error(f"Lỗi: {e}")
        return False

def clear_all_logs():
    try:
        files = [ATTACK_LOG_FILE, HISTORY_LOG_FILE, MANUAL_BLOCK_FILE]
        for f in files:
            if os.path.exists(f): os.remove(f)
        st.session_state.traffic_history = pd.DataFrame(columns=['Time', 'Speed_MBps', 'Type'])
        return True
    except Exception as e:
        st.error(f"Lỗi xóa log: {e}")
        return False

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ Control Panel")
    
    st.subheader("Manual Blocking")
    with st.form("block_form", clear_on_submit=True):
        ip_input = st.text_input("IP Address:", placeholder="e.g., 10.0.0.5")
        submitted = st.form_submit_button("🚫 Block IP Now")
        if submitted and ip_input:
            if save_manual_block(ip_input):
                st.success(f"Sent block command: {ip_input}")
                time.sleep(1) 
            
    st.divider()
    st.subheader("💾 Dataset Export")
    if os.path.exists(DDOS_DATASET_FILE):
        try:
            with open(DDOS_DATASET_FILE, "rb") as f:
                st.download_button("📥 Download Dataset", f, "ddos_captured_dataset.csv", "text/csv")
        except: st.warning("Busy...")
    
    st.divider()
    if st.button("🗑️ Clear Logs"):
        if clear_all_logs():
            st.success("Reset Done!")
            time.sleep(1)
            st.rerun()

    st.divider()
    st.caption("✅ System Active | Refresh: 1s")

# --- MAIN PAGE ---
st.title("SDN AI-Guard Monitoring Center")

# Metrics
current_net_io = psutil.net_io_counters().bytes_recv
current_time = time.time()
delta_bytes = current_net_io - st.session_state.last_net_io
delta_time = current_time - st.session_state.last_time

speed_mbps = 0
if delta_time > 0:
    speed_mbps = (delta_bytes / 1024 / 1024) / delta_time

st.session_state.last_net_io = current_net_io
st.session_state.last_time = current_time

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

# --- UPDATE CHART DATA ---
new_row = {'Time': datetime.now().strftime('%H:%M:%S'), 'Speed_MBps': speed_mbps, 'Type': 'Monitoring'}
new_df = pd.DataFrame([new_row])

if st.session_state.traffic_history.empty:
    st.session_state.traffic_history = new_df
else:
    st.session_state.traffic_history = pd.concat([st.session_state.traffic_history, new_df], ignore_index=True).tail(60)

# Display Metrics
c1, c2, c3, c4 = st.columns(4)
with c1:
    if system_state == "CRITICAL": st.metric("System Status", "UNDER ATTACK", delta="- CRITICAL", delta_color="inverse")
    elif system_state == "WARNING": st.metric("System Status", "SUSPICIOUS", delta="! WARNING", delta_color="off")
    else: st.metric("System Status", "SECURE", delta="Active")
with c2: st.metric("Malicious IPs", df_attacks['ip_src'].nunique() if not df_attacks.empty else 0)
with c3: st.metric("Network Traffic", f"{speed_mbps:.2f} MB/s")
with c4: st.metric("CPU Usage", f"{psutil.cpu_percent()}%")

# --- CHART (FIXED GREEN COLOR & ROBUST RENDER) ---
st.divider()
st.subheader("📈 Real-time Network Traffic")
if not st.session_state.traffic_history.empty:
    chart_data = st.session_state.traffic_history
    
    base = alt.Chart(chart_data).encode(
        x=alt.X('Time', axis=alt.Axis(labels=False, title='Windows (60s)', titleAnchor='start')),
        y=alt.Y('Speed_MBps', title='Speed (MB/s)', scale=alt.Scale(domain=[0, 50])), 
        tooltip=['Time', 'Speed_MBps']
    )
    
    # Màu xanh cố định
    line = base.mark_line(strokeWidth=3, color='#00CC96')
    area = base.mark_area(opacity=0.3, color='#00CC96')
    
    chart = line + area
    
    # [FIX] Try-Except Block cho Chart: Tự động chọn tham số phù hợp
    try:
        # Thử dùng lệnh mới (Streamlit >= 1.39)
        st.altair_chart(chart, width="stretch")
    except TypeError:
        # Nếu lỗi (Streamlit < 1.39), dùng lệnh cũ
        st.altair_chart(chart, use_container_width=True)

# Logs
st.divider()
c1, c2 = st.columns([3, 1])
with c1:
    if system_state == "WARNING": st.subheader("⚠️ Suspicious Activity Detected")
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
            df_display['timestamp'] = df_display['timestamp'].apply(
                lambda x: datetime.fromtimestamp(float(x)).strftime('%H:%M:%S') if pd.notnull(x) else x
            )
        
        # [FIX] Try-Except Block cho Dataframe
        try:
            st.dataframe(df_display[valid_cols].head(10), width="stretch", hide_index=True)
        except TypeError:
            st.dataframe(df_display[valid_cols].head(10), use_container_width=True, hide_index=True)

    except: st.dataframe(df_attacks.tail(10))
else:
    st.info("System is clean.")

# History
st.divider()
st.subheader("🚫 Blocked IP History")
if not df_history.empty:
    # [FIX] Try-Except Block cho Dataframe
    try:
        st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), width="stretch", hide_index=True)
    except TypeError:
        st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), use_container_width=True, hide_index=True)

time.sleep(1)
st.rerun()