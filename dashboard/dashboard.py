import streamlit as st
import pandas as pd
import psutil
import time
import os
import altair as alt
import html
from datetime import datetime
import warnings

# --- TẮT CẢNH BÁO ---
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)

# Import auto-refresh (install: pip install streamlit-autorefresh)
try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False

# Check if st.fragment is available (Streamlit >= 1.33)
HAS_FRAGMENT = hasattr(st, 'fragment')

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
MANUAL_UNBLOCK_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'manual_unblocks.txt')
CURRENT_BLOCKS_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'current_blocks.csv')
DDOS_DATASET_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'ddos_captured_dataset.csv')
TRAFFIC_MONITOR_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'traffic_monitor.csv')
AI_PREDICT_LOG_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'ai_predict.csv')
FIREWALL_STATUS_FILE = os.path.join(PROJECT_ROOT, 'attack_log', 'firewall_status.txt')

st.markdown(
        """
<style>
    .stApp { background-color: #0E1117; color: #FAFAFA; font-family: "Segoe UI", "Segoe UI Variable", "Tahoma", "Arial", sans-serif; }
    h1, h2, h3, h4, h5, h6, p, span, div, label { font-family: "Segoe UI", "Segoe UI Variable", "Tahoma", "Arial", sans-serif; }
    .stButton>button { width: 100%; border-radius: 6px; }

    /* Top status bar (matches screenshot style) */
    .status-row {
        background: radial-gradient(1200px 400px at 20% -50%, rgba(56,189,248,0.08), rgba(0,0,0,0)),
                    linear-gradient(180deg, rgba(15,23,42,0.72), rgba(2,6,23,0.72));
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 16px;
        padding: 18px 18px;
    }
    .status-grid {
        display: grid;
        grid-template-columns: repeat(5, minmax(0, 1fr));
        gap: 14px;
        align-items: start;
    }
    .status-item {
        padding: 4px 6px;
    }
    .status-title {
        font-size: 13px;
        color: rgba(250,250,250,0.70);
        letter-spacing: 0.2px;
        margin-bottom: 10px;
    }
    .status-value {
        font-size: 40px;
        font-weight: 750;
        line-height: 1.1;
        margin: 0 0 12px 0;
        color: rgba(250,250,250,0.98);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    .status-pill {
        display: inline-flex;
        gap: 6px;
        align-items: center;
        font-size: 12px;
        padding: 4px 10px;
        border-radius: 999px;
        border: 1px solid rgba(255,255,255,0.14);
        color: rgba(250,250,250,0.90);
        background: rgba(255,255,255,0.06);
    }
    .pill-critical { background: rgba(239, 68, 68, 0.18); border-color: rgba(239, 68, 68, 0.35); }
    .pill-warning  { background: rgba(245, 158, 11, 0.18); border-color: rgba(245, 158, 11, 0.35); }
    .pill-ok       { background: rgba(16, 185, 129, 0.16); border-color: rgba(16, 185, 129, 0.35); }
    .pill-off      { background: rgba(148, 163, 184, 0.14); border-color: rgba(148, 163, 184, 0.30); }

    /* Chart section container */
    .chart-title {
        font-size: 16px;
        font-weight: 650;
        margin: 0 0 6px 0;
    }
    .chart-subtitle {
        font-size: 12px;
        color: rgba(250,250,250,0.65);
        margin: 0 0 10px 0;
    }
</style>
""",
        unsafe_allow_html=True,
)

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

def save_manual_unblock(ip):
    try:
        with open(MANUAL_UNBLOCK_FILE, "a") as f: f.write(f"{ip}\n"); f.flush()
        return True
    except Exception as e: st.error(f"Lỗi: {e}"); return False

def load_current_blocks():
    if not os.path.exists(CURRENT_BLOCKS_FILE): return pd.DataFrame()
    try:
        if os.path.getsize(CURRENT_BLOCKS_FILE) == 0: return pd.DataFrame()
        return pd.read_csv(CURRENT_BLOCKS_FILE, on_bad_lines='skip', engine='python')
    except: return pd.DataFrame()

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


def status_row(cards):
    items_html = ""
    for c in cards:
        title = html.escape(str(c.get('title', '')))
        value = html.escape(str(c.get('value', '')))
        pill_text = c.get('pill_text')
        pill_variant = c.get('pill_variant', 'ok')
        if pill_text:
            pill_text = html.escape(str(pill_text))
            pill = f"<span class='status-pill pill-{pill_variant}'>↑ {pill_text}</span>"
        else:
            pill = ""

        items_html += (
            "<div class='status-item'>"
            f"<div class='status-title'>{title}</div>"
            f"<div class='status-value'>{value}</div>"
            f"{pill}"
            "</div>"
        )

    return f"""
<div class='status-row'>
  <div class='status-grid'>
    {items_html}
  </div>
</div>
"""

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
    st.caption("System Active | Refresh: 1s")

# --- MAIN PAGE ---
st.title("SDN AI-Guard Monitoring Center")

# --- SYSTEM HEALTH SECTION (moved to top) ---
st.subheader("💻 System Health")

# Get system metrics
cpu_percent = psutil.cpu_percent(interval=0.1)
memory = psutil.virtual_memory()
ram_percent = memory.percent
ram_used = memory.used / (1024**3)  # GB
ram_total = memory.total / (1024**3)  # GB

# Display in columns
h1, h2, h3, h4 = st.columns(4)

with h1:
    # CPU Usage with color indicator
    if cpu_percent >= 80:
        st.metric("🔴 CPU Usage", f"{cpu_percent:.1f}%", delta="High", delta_color="inverse")
    elif cpu_percent >= 50:
        st.metric("🟡 CPU Usage", f"{cpu_percent:.1f}%", delta="Medium", delta_color="off")
    else:
        st.metric("🟢 CPU Usage", f"{cpu_percent:.1f}%", delta="Normal")

with h2:
    # RAM Usage with color indicator
    if ram_percent >= 80:
        st.metric("🔴 RAM Usage", f"{ram_percent:.1f}%", delta="High", delta_color="inverse")
    elif ram_percent >= 50:
        st.metric("🟡 RAM Usage", f"{ram_percent:.1f}%", delta="Medium", delta_color="off")
    else:
        st.metric("🟢 RAM Usage", f"{ram_percent:.1f}%", delta="Normal")

with h3:
    st.metric("📊 RAM Used", f"{ram_used:.2f} GB", delta=f"of {ram_total:.1f} GB")

with h4:
    # Network connections count
    try:
        net_connections = len(psutil.net_connections(kind='inet'))
        st.metric("🌐 Net Connections", net_connections)
    except:
        st.metric("🌐 Net Connections", "N/A")

st.divider()

# --- SYSTEM STATUS ---
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
        required_cols = ['Blocked_MBps', 'Suspicious_MBps', 'Benign_MBps']
        if not all(col in df.columns for col in required_cols): return pd.DataFrame()
        df = df.tail(60).reset_index(drop=True)
        df['Sequence'] = df.index 
        return df
    except: return pd.DataFrame()

df_traffic = load_traffic_monitor()
curr_blocked = 0.0
curr_suspicious = 0.0
curr_benign = 0.0

if not df_traffic.empty:
    curr_blocked = df_traffic.iloc[-1]['Blocked_MBps']
    curr_suspicious = df_traffic.iloc[-1]['Suspicious_MBps']
    curr_benign = df_traffic.iloc[-1]['Benign_MBps']

# --- SYSTEM STATUS BAR (LIKE SCREENSHOT) ---
if not new_fw_state:
    status_text = "DISABLED"
    status_pill = "Off"
    status_variant = "off"
elif system_state == "CRITICAL":
    status_text = "UNDER ATTACK"
    status_pill = "CRITICAL"
    status_variant = "critical"
elif system_state == "WARNING":
    status_text = "SUSPICIOUS"
    status_pill = "WARNING"
    status_variant = "warning"
else:
    status_text = "SECURE"
    status_pill = "Active"
    status_variant = "ok"

malicious_ips = df_attacks['ip_src'].nunique() if not df_attacks.empty and 'ip_src' in df_attacks.columns else 0

cards = [
    {"title": "System Status", "value": status_text, "pill_text": status_pill, "pill_variant": status_variant},
    {"title": "Malicious IPs", "value": str(malicious_ips), "pill_text": None, "pill_variant": "ok"},
    {"title": "Blocked Traffic", "value": format_speed(float(curr_blocked)), "pill_text": "Stopped", "pill_variant": "ok"},
    {"title": "Suspicious Traffic", "value": format_speed(float(curr_suspicious)), "pill_text": "Detected", "pill_variant": "warning"},
    {"title": "Benign Traffic", "value": format_speed(float(curr_benign)), "pill_text": "Clean", "pill_variant": "ok"},
]

st.markdown(status_row(cards), unsafe_allow_html=True)


# --- TRAFFIC CHART (AREA + LINES LIKE SCREENSHOT) ---
st.divider()
st.markdown("<div class='chart-title'>Traffic Status</div>", unsafe_allow_html=True)

if not df_traffic.empty:
    # Use Mbps like the screenshot
    df_plot = df_traffic[['Sequence', 'Blocked_MBps', 'Suspicious_MBps', 'Benign_MBps']].copy()
    df_plot['Blocked_MBps'] = pd.to_numeric(df_plot['Blocked_MBps'], errors='coerce').fillna(0.0)
    df_plot['Suspicious_MBps'] = pd.to_numeric(df_plot['Suspicious_MBps'], errors='coerce').fillna(0.0)
    df_plot['Benign_MBps'] = pd.to_numeric(df_plot['Benign_MBps'], errors='coerce').fillna(0.0)
    max_seq = int(df_plot['Sequence'].max()) if not df_plot.empty else 0
    df_plot['Sequence_RTL'] = max_seq - df_plot['Sequence'] + 1

    max_val = float(df_plot[['Blocked_MBps', 'Suspicious_MBps', 'Benign_MBps']].max().max())
    y_max = max(1.0, max_val * 1.2)

    df_long = df_plot.melt(
        id_vars=['Sequence_RTL'],
        value_vars=['Blocked_MBps', 'Suspicious_MBps', 'Benign_MBps'],
        var_name='Type',
        value_name='Value'
    )
    df_long['Type'] = df_long['Type'].replace({
        'Blocked_MBps': 'Blocked Traffic',
        'Suspicious_MBps': 'Suspicious Traffic',
        'Benign_MBps': 'Benign Traffic'
    })

    domain = ['Blocked Traffic', 'Suspicious Traffic', 'Benign Traffic']
    colors = ['#EF4444', '#F59E0B', '#22C55E']

    base = alt.Chart(df_long).encode(
        x=alt.X(
            'Sequence_RTL:Q',
            axis=alt.Axis(
                title=None,
                labels=True,
                ticks=True,
                grid=False,
                values=[1, max_seq + 1],
                labelExpr='datum.value - 1'
            ),
            scale=alt.Scale(reverse=True),
        ),
        y=alt.Y(
            'Value:Q',
            axis=alt.Axis(title='Throughput (Mbps)', grid=True),
            scale=alt.Scale(domain=[0, y_max]),
        ),
        color=alt.Color(
            'Type:N',
            scale=alt.Scale(domain=domain, range=colors),
            legend=alt.Legend(title='Traffic Status', orient='top-left'),
        ),
        tooltip=[
            alt.Tooltip('Type:N', title='Type'),
            alt.Tooltip('Value:Q', title='Mbps', format='.2f'),
        ],
    )

    blocked_area = (
        base.transform_filter(alt.datum.Type == 'Blocked Traffic')
        .mark_area(opacity=0.25)
    )
    lines = base.mark_line(strokeWidth=3)

    chart = (
        (blocked_area + lines)
        .properties(height=450)
        .configure_view(stroke=None, fill='#0E1117')
        .configure_axis(
            labelColor='rgba(250,250,250,0.70)',
            titleColor='rgba(250,250,250,0.85)',
            gridColor='rgba(148,163,184,0.18)',
            tickColor='rgba(148,163,184,0.20)',
            labelFont='Segoe UI',
            titleFont='Segoe UI',
        )
        .configure_legend(
            labelColor='rgba(250,250,250,0.80)',
            titleColor='rgba(250,250,250,0.85)',
            labelFont='Segoe UI',
            titleFont='Segoe UI',
        )
        .configure_title(
            font='Segoe UI'
        )
    )

    st.altair_chart(chart, use_container_width=True)
    st.caption("60 Seconds Window")
else:
    st.info("Waiting for traffic data stream...")

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
        
        # Hiển thị từng dòng log với nút Block cho Warning/Attack
        df_top = df_display[valid_cols].head(8)
        
        # Header row
        hcol1, hcol2, hcol3, hcol4, hcol5, hcol6, hcol7, hcol8 = st.columns([1.2, 1.5, 1.5, 0.8, 1, 1, 2, 1])
        with hcol1: st.markdown("**Time**")
        with hcol2: st.markdown("**Source IP**")
        with hcol3: st.markdown("**Dest IP**")
        with hcol4: st.markdown("**Proto**")
        with hcol5: st.markdown("**Packets**")
        with hcol6: st.markdown("**Label**")
        with hcol7: st.markdown("**Reason**")
        with hcol8: st.markdown("**Action**")
        
        st.markdown("---")
        
        # Data rows với nút Block
        for row_idx, row in df_top.iterrows():
            col1, col2, col3, col4, col5, col6, col7, col8 = st.columns([1.2, 1.5, 1.5, 0.8, 1, 1, 2, 1])
            
            with col1: st.text(str(row.get('timestamp', '-')))
            with col2: st.text(str(row.get('ip_src', '-')))
            with col3: st.text(str(row.get('ip_dst', '-')))
            with col4: 
                proto_val = row.get('ip_proto', '-')
                proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                st.text(proto_map.get(int(proto_val), str(proto_val)) if str(proto_val).isdigit() else str(proto_val))
            with col5: st.text(str(row.get('packet_count', '-')))
            with col6:
                label = str(row.get('label', '-'))
                if label == 'Attack':
                    st.markdown(f"🔴 **{label}**")
                elif label == 'Warning':
                    st.markdown(f"🟠 **{label}**")
                else:
                    st.text(label)
            with col7: st.text(str(row.get('reason', '-'))[:25])
            with col8:
                src_ip = str(row.get('ip_src', ''))
                label = str(row.get('label', ''))
                # Hiển thị nút Block cho Warning và Attack (nếu firewall ON)
                if label in ['Warning', 'Attack'] and new_fw_state and src_ip:
                    if st.button("🚫", key=f"log_block_{src_ip}_{row_idx}", help=f"Block {src_ip}"):
                        if save_manual_block(src_ip):
                            st.toast(f"✅ Blocked {src_ip}")
                            time.sleep(0.3)
                            st.rerun()
                else:
                    st.text("-")
                    
    except Exception as e: 
        st.dataframe(df_attacks.tail(8), width="stretch")
else: st.info("System is clean.")

st.divider()

# --- CURRENT BLOCKED IPs SECTION ---
st.subheader("🔒 Currently Blocked IPs")
df_current_blocks = load_current_blocks()

if not df_current_blocks.empty and 'IP' in df_current_blocks.columns:
    # Header row
    hcol1, hcol2, hcol3, hcol4, hcol5 = st.columns([2, 1.5, 1.5, 2.5, 1])
    with hcol1: st.markdown("**IP Address**")
    with hcol2: st.markdown("**Time Left**")
    with hcol3: st.markdown("**Protocol**")
    with hcol4: st.markdown("**Reason**")
    with hcol5: st.markdown("**Action**")
    
    st.markdown("---")
    
    # Data rows với nút Unblock
    for idx, row in df_current_blocks.iterrows():
        col1, col2, col3, col4, col5 = st.columns([2, 1.5, 1.5, 2.5, 1])
        
        ip_addr = str(row.get('IP', '-'))
        time_left = int(row.get('Time_Left', 0))
        duration = int(row.get('Duration', 60))
        proto = str(row.get('Protocol', '-'))
        reason = str(row.get('Reason', '-'))
        
        with col1: 
            st.markdown(f"🚫 **{ip_addr}**")
        with col2: 
            if time_left > 0:
                st.text(f"{time_left}s / {duration}s")
            else:
                st.text("Expiring...")
        with col3:
            st.text(proto)
        with col4:
            st.text(reason[:30] if len(reason) > 30 else reason)
        with col5:
            if new_fw_state:
                if st.button("🔓", key=f"unblock_{ip_addr}_{idx}", help=f"Unblock {ip_addr}"):
                    if save_manual_unblock(ip_addr):
                        st.toast(f"✅ Unblocked {ip_addr}")
                        time.sleep(0.3)
                        st.rerun()
            else:
                st.text("-")
else:
    st.info("No IPs currently blocked.")

st.divider()
st.subheader("🚫 Blocked IP History")
if not df_history.empty:
    # [FIX] Sử dụng width="stretch" cho dataframe
    try: 
        st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), width="stretch", hide_index=True)
    except: 
        st.dataframe(df_history.sort_values(by='Total_Blocks', ascending=False), width="stretch", hide_index=True)

# Auto-refresh every 1 second (1000ms) để tránh chớp tắt
if HAS_AUTOREFRESH:
    st_autorefresh(interval=1000, limit=None, key="dashboard_refresh")