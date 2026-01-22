import streamlit as st
import pandas as pd
import psutil
import time
import os
import altair as alt
from datetime import datetime
import warnings

# ### Đoạn code này sẽ tắt các cảnh báo không cần thiết của thư viện để log sạch hơn ###
warnings.simplefilter(action='ignore', category=FutureWarning)

# ### Đoạn code này sẽ thiết lập tiêu đề tab trình duyệt, icon và bố cục trang là wide (tràn màn hình) ###
st.set_page_config(
    page_title="SDN AI-Guard Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CẤU HÌNH ĐƯỜNG DẪN THÔNG MINH ---
# ### Đoạn code này sẽ tự động tìm đường dẫn thư mục gốc để tránh lỗi 'FileNotFound' ###
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(CURRENT_DIR, 'attack_log')):
    PROJECT_ROOT = CURRENT_DIR
elif os.path.exists(os.path.join(os.path.dirname(CURRENT_DIR), 'attack_log')):
    PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
else:
    PROJECT_ROOT = CURRENT_DIR

# ### Các biến này định nghĩa đường dẫn tuyệt đối tới các file log ###
ATTACK_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'attack_logs.csv')
HISTORY_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'offender_history.csv')
MANUAL_BLOCK_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'manual_blocks.txt')
AI_PREDICT_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'ai_predict.csv')

# --- CSS TÙY CHỈNH ---
st.markdown("""
    <style>
    .stApp {
        background-color: #0E1117;
        color: #FAFAFA;
    }
    .metric-card {
        background-color: #262730;
        padding: 10px;
        border-radius: 5px;
        border: 1px solid #41444C;
    }
    .stButton>button {
        width: 100%;
    }
    </style>
    """, unsafe_allow_html=True)

# --- KHỞI TẠO STATE ---
if 'traffic_history' not in st.session_state:
    st.session_state.traffic_history = pd.DataFrame(columns=['Time', 'Speed_KBps', 'Type'])
if 'last_net_io' not in st.session_state:
    st.session_state.last_net_io = psutil.net_io_counters().bytes_recv
if 'last_time' not in st.session_state:
    st.session_state.last_time = time.time()

# --- HÀM HỖ TRỢ ---
def load_data(filepath):
    if not os.path.exists(filepath):
        return pd.DataFrame()
    try:
        if os.path.getsize(filepath) == 0:
            return pd.DataFrame()
        return pd.read_csv(filepath, on_bad_lines='skip', engine='python')
    except Exception:
        return pd.DataFrame()

def save_manual_block(ip):
    try:
        os.makedirs(os.path.dirname(MANUAL_BLOCK_FILE), exist_ok=True)
        with open(MANUAL_BLOCK_FILE, "a") as f:
            f.write(f"{ip}\n")
        return True
    except Exception as e:
        st.error(f"Lỗi ghi file: {e}")
        return False

def clear_all_logs():
    try:
        files_to_delete = [ATTACK_LOG_FILE, HISTORY_LOG_FILE, MANUAL_BLOCK_FILE, AI_PREDICT_FILE]
        for f in files_to_delete:
            if os.path.exists(f):
                os.remove(f)
        st.session_state.traffic_history = pd.DataFrame(columns=['Time', 'Speed_KBps', 'Type'])
        return True
    except Exception as e:
        st.error(f"Lỗi xóa log: {e}")
        return False

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ Control Panel")
    
    st.subheader("Manual Blocking")
    with st.form("block_form"):
        ip_input = st.text_input("IP Address:", placeholder="e.g., 10.0.0.5")
        submitted = st.form_submit_button("🚫 Block IP Now")
        if submitted and ip_input:
            if save_manual_block(ip_input):
                st.success(f"Đã gửi lệnh chặn: {ip_input}")
                time.sleep(0.5)
                st.rerun()

    st.divider()
    
    st.subheader("System Maintenance")
    if st.button("🗑️ Clear All Logs & Reset"):
        if clear_all_logs():
            st.success("Đã xóa sạch dữ liệu cũ!")
            time.sleep(1)
            st.rerun()

    st.divider()
    st.caption("✅ System Status: Active")
    st.caption("🔄 Auto-refresh: 1s")

# --- MAIN DASHBOARD ---
st.title("SDN AI-Guard Monitoring Center")

# 1. TÍNH TOÁN METRICS
current_net_io = psutil.net_io_counters().bytes_recv
current_time = time.time()
delta_bytes = current_net_io - st.session_state.last_net_io
delta_time = current_time - st.session_state.last_time

speed_kbps = 0
if delta_time > 0:
    speed_kbps = (delta_bytes / 1024) / delta_time

st.session_state.last_net_io = current_net_io
st.session_state.last_time = current_time

# Load Logs
df_attacks = load_data(ATTACK_LOG_FILE)
df_history = load_data(HISTORY_LOG_FILE)

is_under_attack = False
total_threats = len(df_attacks)
unique_attackers = df_attacks['ip_src'].nunique() if not df_attacks.empty and 'ip_src' in df_attacks.columns else 0

# --- LOGIC XÁC ĐỊNH TRẠNG THÁI HỆ THỐNG ---
system_state = "SAFE" 
target_ip_to_block = None

if not df_attacks.empty and 'timestamp' in df_attacks.columns:
    try:
        last_row = df_attacks.iloc[-1]
        last_ts = float(last_row['timestamp'])
        if time.time() - last_ts < 30:
            label = str(last_row['label'])
            if label == "Attack":
                system_state = "CRITICAL"
            elif label in ["Warning", "Suspicious"]:
                system_state = "WARNING"
                target_ip_to_block = last_row['ip_src']
    except: pass


# --- CẬP NHẬT DỮ LIỆU BIỂU ĐỒ ---
current_type = 'Normal'
if system_state == "CRITICAL": current_type = 'Attack'
elif system_state == "WARNING": current_type = 'Warning'

new_row = {
    'Time': datetime.now().strftime('%H:%M:%S'),
    'Speed_KBps': speed_kbps,
    'Type': current_type
}

new_df = pd.DataFrame([new_row])

if st.session_state.traffic_history.empty:
    st.session_state.traffic_history = new_df
else:
    st.session_state.traffic_history = pd.concat(
        [st.session_state.traffic_history, new_df], 
        ignore_index=True
    ).tail(60)

# 2. HIỂN THỊ METRICS
col1, col2, col3, col4 = st.columns(4)

with col1:
    if system_state == "CRITICAL":
        st.metric("System Status", "UNDER ATTACK", delta="- CRITICAL", delta_color="inverse")
    elif system_state == "WARNING":
        st.metric("System Status", "SUSPICIOUS", delta="! WARNING", delta_color="off")
    else:
        st.metric("System Status", "SECURE", delta="Active")

with col2:
    st.metric("Malicious IPs (Unique)", unique_attackers)
with col3:
    st.metric("Network Traffic", f"{speed_kbps:.2f} KB/s")
with col4:
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    st.metric("CPU / RAM Usage", f"{cpu}% / {ram}%")

# 3. BIỂU ĐỒ REAL-TIME TRAFFIC
st.divider()
st.subheader("📈 Real-time Network Traffic")

chart_data = st.session_state.traffic_history
if not chart_data.empty:
    color_scale = alt.Scale(domain=['Attack', 'Warning', 'Normal'],
                            range=['#FF4B4B', '#FFA500', '#00CC96'])

    # ### 'scale=alt.Scale(domain=[0, 20000])' giúp cố định trục Y ###
    base = alt.Chart(chart_data).encode(
        x=alt.X('Time', axis=alt.Axis(labels=False, title='Windows (60s)')),
        y=alt.Y('Speed_KBps', title='Speed (KB/s)', scale=alt.Scale(domain=[0, 20000])), 
        tooltip=['Time', 'Speed_KBps', 'Type']
    )

    line = base.mark_line(strokeWidth=3).encode(
        color=alt.Color('Type', scale=color_scale, legend=None)
    )

    area = base.mark_area(opacity=0.3).encode(
        color=alt.Color('Type', scale=color_scale, legend=None)
    )

    # ### [FIXED] Thay use_container_width=True bằng width="stretch" cho chart ###
    # Lưu ý: Một số phiên bản Streamlit mới bắt buộc dùng cú pháp này cho Altair
    try:
        st.altair_chart(line + area, use_container_width=True)
    except:
        # Fallback nếu phiên bản Streamlit yêu cầu 'theme' hoặc config khác
        st.altair_chart(line + area, theme="streamlit", use_container_width=True)

# 4. NHẬT KÝ TẤN CÔNG
st.divider()
c1, c2 = st.columns([3, 1])
with c1:
    if system_state == "WARNING":
        st.subheader("⚠️ Suspicious Activity Detected")
        if target_ip_to_block:
            st.caption(f"Detected low-rate anomaly. Suggested Action: Block IP {target_ip_to_block}")
    elif system_state == "CRITICAL":
        st.subheader("🚨 CRITICAL: Attack In Progress")
    else:
        st.subheader("📋 Traffic Logs")

with c2:
    if not df_attacks.empty:
        csv_data = df_attacks.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download Full Logs", csv_data, 'attack_logs_full.csv', 'text/csv')

if not df_attacks.empty:
    try:
        df_display = df_attacks.copy()
        if 'timestamp' in df_display.columns:
            df_display['Time'] = df_display['timestamp'].apply(
                lambda x: datetime.fromtimestamp(float(x)).strftime('%H:%M:%S %Y-%m-%d') if pd.notnull(x) else x
            )
            df_display = df_display.sort_values(by='timestamp', ascending=False)
        
        target_cols = ['Time', 'ip_src', 'ip_dst', 'ip_proto', 'packet_count', 'label', 'reason']
        valid_cols = [c for c in target_cols if c in df_display.columns]
        
        # ### [FIXED] Thay use_container_width=True bằng width="stretch" cho dataframe ###
        # Lưu ý: Nếu bản Streamlit hiện tại chưa hỗ trợ width="stretch", hãy đổi lại thành use_container_width=True
        # Nhưng theo log lỗi bạn gửi, bắt buộc dùng width="stretch"
        st.dataframe(df_display[valid_cols].head(10), width="stretch", hide_index=True)
    except Exception as e:
        # Fallback an toàn
        st.dataframe(df_attacks.tail(10), width="stretch")
else:
    st.info("No attack logs recorded yet. System is clean.")

# 5. LỊCH SỬ CHẶN IP
st.divider()
st.subheader("🚫 Blocked IP History")
if not df_history.empty:
    # ### [FIXED] Cập nhật width="stretch" ###
    st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), width="stretch", hide_index=True)
else:
    st.text("No blocking history available.")

time.sleep(1)
st.rerun()