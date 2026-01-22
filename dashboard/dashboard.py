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
warnings.simplefilter(action='ignore', category=UserWarning) # Tắt cảnh báo date parsing

st.set_page_config(
    page_title="SDN AI-Guard Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CẤU HÌNH ĐƯỜNG DẪN THÔNG MINH ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR) if os.path.exists(os.path.join(os.path.dirname(BASE_DIR), 'attack_log')) else BASE_DIR

# Định nghĩa các file log
ATTACK_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'attack_logs.csv')
HISTORY_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'offender_history.csv')
MANUAL_BLOCK_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'manual_blocks.txt')
DDOS_DATASET_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'ddos_captured_dataset.csv')
TRAFFIC_MONITOR_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'traffic_monitor.csv')
AI_PREDICT_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'ai_predict.csv')

# --- CSS ---
st.markdown("""
    <style>
    .stApp { background-color: #0E1117; color: #FAFAFA; }
    .metric-card { background-color: #262730; padding: 10px; border-radius: 5px; }
    .stButton>button { width: 100%; border-radius: 5px; }
    </style>
    """, unsafe_allow_html=True)

# --- KHỞI TẠO STATE ---
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = pd.DataFrame(columns=['Time', 'Speed_MBps', 'Type'])
if 'last_time' not in st.session_state:
    st.session_state.last_time = time.time()

# --- HÀM HỖ TRỢ ---
def load_data(filepath):
    if not os.path.exists(filepath): return pd.DataFrame()
    try:
        if os.path.getsize(filepath) == 0: return pd.DataFrame()
        return pd.read_csv(filepath, on_bad_lines='skip', engine='python')
    except: return pd.DataFrame()

def save_manual_block(ip):
    try:
        with open(MANUAL_BLOCK_FILE, "a") as f:
            f.write(f"{ip}\n")
            f.flush()
        return True
    except Exception as e:
        st.error(f"Lỗi: {e}")
        return False

# [UPDATE] Hàm xóa log bao gồm cả AI Predict
def clear_all_logs():
    try:
        files = [ATTACK_LOG_FILE, HISTORY_LOG_FILE, MANUAL_BLOCK_FILE, TRAFFIC_MONITOR_FILE, AI_PREDICT_LOG_FILE]
        for f in files:
            if os.path.exists(f): os.remove(f)
        return True
    except Exception as e:
        st.error(f"Lỗi xóa log: {e}")
        return False

# [NEW] Hàm xóa Dataset
def delete_dataset():
    try:
        if os.path.exists(DDOS_DATASET_FILE):
            os.remove(DDOS_DATASET_FILE)
            return True
        return False
    except Exception as e:
        st.error(f"Lỗi xóa dataset: {e}")
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
                st.success(f"Đã gửi lệnh chặn: {ip_input}")
                time.sleep(0.5) 
            
    st.divider()
    st.subheader("💾 Dataset Management")
    
    c1, c2 = st.columns(2)
    with c1:
        if os.path.exists(DDOS_DATASET_FILE):
            with open(DDOS_DATASET_FILE, "rb") as f:
                st.download_button("📥 Download", f, "ddos_captured_dataset.csv", "text/csv")
        else:
            st.button("📥 Download", disabled=True)
    
    with c2:
        if st.button("🗑️ Delete Data"):
            if delete_dataset():
                st.success("Deleted!")
                time.sleep(1)
                st.rerun()
            else:
                st.warning("File not found")
    
    st.divider()
    st.subheader("⚙️ System")
    if st.button("🗑️ Clear All Logs & History"):
        if clear_all_logs():
            st.success("System Cleaned!")
            time.sleep(1)
            st.rerun()

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

# --- LOAD TRAFFIC (FIX LỖI TIMESTAMP) ---
def load_traffic_monitor():
    if not os.path.exists(TRAFFIC_MONITOR_FILE): return pd.DataFrame()
    try:
        # Đọc file, bỏ qua lỗi dòng
        df = pd.read_csv(TRAFFIC_MONITOR_FILE, on_bad_lines='skip')
        
        # Chỉ lấy 60 điểm dữ liệu cuối cùng
        df = df.tail(60).reset_index(drop=True)
        
        # Tạo cột chỉ số giả lập (0 -> 60) thay vì dùng Timestamp thực để tránh lỗi parse
        df['Sequence'] = df.index 
        
        return df
    except: return pd.DataFrame()

df_traffic = load_traffic_monitor()

# Hiển thị Metrics
curr_attack = 0.0
curr_benign = 0.0
if not df_traffic.empty:
    curr_attack = df_traffic.iloc[-1]['Attack_MBps']
    curr_benign = df_traffic.iloc[-1]['Benign_MBps']

c1, c2, c3, c4 = st.columns(4)
with c1:
    if system_state == "CRITICAL": st.metric("System Status", "UNDER ATTACK", delta="- CRITICAL", delta_color="inverse")
    elif system_state == "WARNING": st.metric("System Status", "SUSPICIOUS", delta="! WARNING", delta_color="off")
    else: st.metric("System Status", "SECURE", delta="Active")
with c2: st.metric("Malicious IPs", df_attacks['ip_src'].nunique() if not df_attacks.empty else 0)
with c3: st.metric("Attack Traffic", f"{curr_attack:.2f} MB/s", delta="Inbound", delta_color="inverse")
with c4: st.metric("Benign Traffic", f"{curr_benign:.2f} MB/s", delta="Clean")

# --- CHART (FIX GIAO DIỆN & LỖI) ---
st.divider()
# st.subheader("📈 Network Traffic Analysis") # Có thể bỏ header nếu muốn gọn

if not df_traffic.empty:
    # Melt dữ liệu để vẽ nhiều đường
    df_melt = df_traffic.melt('Sequence', value_vars=['Attack_MBps', 'Benign_MBps'], var_name='Type', value_name='MBps')
    
    # Đổi tên hiển thị cho đẹp
    df_melt['Type'] = df_melt['Type'].replace({
        'Attack_MBps': 'Attack (Blocked)',
        'Benign_MBps': 'Benign (Clean)'
    })

    # Vẽ biểu đồ Area
    chart = alt.Chart(df_melt).mark_area(
        opacity=0.6,
        interpolate='monotone' # Làm mượt đường
    ).encode(
        # Trục X: Ẩn label timestamp, chỉ hiện lưới
        x=alt.X('Sequence', 
                axis=alt.Axis(
                    title='60 Seconds Window', 
                    labels=False,  # Ẩn nhãn số trục X
                    grid=True,     # Hiện lưới dọc
                    tickCount=10
                ),
                scale=alt.Scale(domain=[0, 60]) # Cố định khung 60s
        ),
        # Trục Y: Traffic MB/s
        y=alt.Y('MBps', 
                title='Throughput (MB/s)', 
                stack=None, # None = Layered (chồng lên nhau trong suốt), True = Stacked (cộng dồn)
                scale=alt.Scale(domain=[0, 50]) # Cố định scale 50MB
        ),
        # Màu sắc
        color=alt.Color('Type', 
                        scale=alt.Scale(domain=['Attack (Blocked)', 'Benign (Clean)'], range=['#FF4B4B', '#00CC96']),
                        legend=alt.Legend(title="Traffic Type", orient="top-left")
        ),
        tooltip=['Type', 'MBps']
    ).properties(
        height=350
    )

    # Hiển thị biểu đồ an toàn
    try:
        st.altair_chart(chart, use_container_width=True)
    except:
        st.altair_chart(chart, theme="streamlit") # Fallback
else:
    # Hiển thị biểu đồ rỗng nếu chưa có data để giữ layout
    st.info("Waiting for traffic data stream...")

# Logs
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
        
        # Format lại timestamp để hiển thị đẹp hơn
        if 'timestamp' in df_display.columns:
            df_display['timestamp'] = df_display['timestamp'].apply(
                lambda x: datetime.fromtimestamp(float(x)).strftime('%H:%M:%S') if pd.notnull(x) else x
            )
        
        try:
            st.dataframe(df_display[valid_cols].head(8), use_container_width=True, hide_index=True)
        except TypeError:
            st.dataframe(df_display[valid_cols].head(8), width=1000, hide_index=True)

    except: st.dataframe(df_attacks.tail(8))
else:
    st.info("System is clean.")

# History
st.divider()
st.subheader("🚫 Blocked IP History")
if not df_history.empty:
    try:
        st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), use_container_width=True, hide_index=True)
    except TypeError:
        st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), width=1000, hide_index=True)

time.sleep(1)
st.rerun()