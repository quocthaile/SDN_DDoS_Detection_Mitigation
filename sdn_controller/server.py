from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import pandas as pd
import psutil
import os
import time

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_FOLDER = os.path.abspath(os.path.join(CURRENT_DIR, '../dashboard'))
LOG_FILE = os.path.abspath(os.path.join(CURRENT_DIR, '../attack_log/attack_logs.csv'))
MANUAL_BLOCK_FILE = os.path.abspath(os.path.join(CURRENT_DIR, '../attack_log/manual_blocks.txt'))

app = Flask(__name__, static_folder=DASHBOARD_FOLDER, static_url_path='')
CORS(app)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

def get_attack_data():
    try:
        # Check file size to avoid empty errors
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
            return pd.read_csv(LOG_FILE, on_bad_lines='skip')
    except: pass
    return pd.DataFrame()

@app.route('/')
def serve_index(): return send_from_directory(DASHBOARD_FOLDER, 'index.html')

@app.route('/<path:path>')
def serve_static(path): return send_from_directory(DASHBOARD_FOLDER, path)

@app.route('/api/stats')
def get_stats():
    df = get_attack_data()
    total_attacks = 0
    unique_attackers = 0
    recent_alerts = []
    is_under_attack = False # Cờ báo trạng thái tấn công thực

    if not df.empty:
        total_attacks = len(df)
        if 'ip_src' in df.columns:
            unique_attackers = df['ip_src'].nunique()
        
        # Lấy 10 alert mới nhất
        alerts_df = df.tail(10).iloc[::-1]
        
        # [FIX] Kiểm tra dòng log mới nhất có phải vừa xảy ra không (trong vòng 30s)
        if not alerts_df.empty:
            last_ts = float(alerts_df.iloc[0].get('timestamp', 0))
            if time.time() - last_ts < 30: # Nếu log mới nhất < 30 giây trước
                is_under_attack = True

        for _, row in alerts_df.iterrows():
            ts = row.get('timestamp', time.time())
            try: time_str = time.strftime('%H:%M:%S', time.localtime(float(ts)))
            except: time_str = "Unknown"
            
            recent_alerts.append({
                "time": time_str,
                "src_ip": row.get('ip_src', '-'),
                "dst_ip": row.get('ip_dst', '-'),
                "type": row.get('reason', 'DDoS'),
                "score": row.get('label', 'Attack')
            })

    return jsonify({
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "net_recv": psutil.net_io_counters().bytes_recv,
        "total_threats": total_attacks,
        "unique_ips": unique_attackers,
        "alerts": recent_alerts,
        "is_under_attack": is_under_attack # Gửi cờ này xuống Client
    })

# ... (Giữ nguyên các API block_ip, incidents, policies cũ) ...
@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip')
    if ip:
        try:
            with open(MANUAL_BLOCK_FILE, "a") as f: f.write(f"{ip}\n")
            return jsonify({"status": "success"})
        except Exception as e: return jsonify({"error": str(e)}), 500
    return jsonify({"error": "No IP"}), 400

@app.route('/api/incidents')
def get_incidents():
    df = get_attack_data()
    incidents = {"detected": [], "investigating": [], "mitigating": [], "resolved": []}
    if not df.empty:
        for _, row in df.tail(20).iloc[::-1].iterrows():
            ts = float(row.get('timestamp', 0))
            t_ago = int((time.time() - ts)/60)
            item = {
                "id": f"INC-{int(ts)}", "src": row.get('ip_src'), "type": row.get('reason'),
                "priority": "P1", "time": f"{t_ago}m ago", "score": "Attack"
            }
            if t_ago < 5: incidents["detected"].append(item)
            elif t_ago < 30: incidents["mitigating"].append(item)
            else: incidents["resolved"].append(item)
    return jsonify(incidents)

@app.route('/api/policies')
def get_policies():
    # ... (Giữ nguyên code cũ) ...
    return jsonify({"blacklist": [], "rules": []}) # Placeholder để code gọn

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)