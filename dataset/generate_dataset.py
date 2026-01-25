import pandas as pd
import numpy as np
import glob
import os
import warnings

# Tắt cảnh báo để output sạch đẹp
warnings.filterwarnings("ignore")

# --- CẤU HÌNH ---
# Thư mục chứa các file CIC-DDoS2019
INPUT_FOLDER = r'D:\CIC-DDoS2019 30GB (Full Dataset CSV Files)\script\input_csv'
OUTPUT_FILE = 'dataset.csv' # File kết quả
TARGET_TOTAL_ROWS = 2_000_000      # Mục tiêu tổng số dòng
CHUNK_SIZE = 100000                # Đọc từng đoạn nhỏ

def clean_column_names(df):
    """Chuẩn hóa tên cột"""
    df.columns = [c.strip() for c in df.columns]
    return df

def create_icmp_flood_from_udp(df, ratio=0.3):
    """
    Sao chép hành vi UDP Flood (rate cao, count cao) thành ICMP Flood
    - Lọc UDP flow có packet_count > 100 và packet_count_per_second > 10
    - Sao chép và chuyển đổi thành ICMP (protocol=1)
    - Thêm vào dataset với ratio % so với UDP gốc
    """
    # Lọc UDP Flood flows (protocol=17, rate cao, count cao)
    udp_floods = df[
        (df['ip_proto'] == 17) & 
        (df['packet_count'] > 100) & 
        (df['packet_count_per_second'] > 10) &
        (df['label'] == 1)  # Chỉ lấy attack
    ].copy()
    
    if len(udp_floods) == 0:
        return pd.DataFrame()
    
    # Lấy một phần theo ratio
    sample_size = max(1, int(len(udp_floods) * ratio))
    icmp_floods = udp_floods.sample(n=sample_size, random_state=42)
    
    # Biến đổi thành ICMP Flood
    icmp_floods['ip_proto'] = 1  # ICMP
    icmp_floods['tp_src'] = 0    # ICMP không dùng port
    icmp_floods['tp_dst'] = 0
    icmp_floods['icmp_type'] = 8  # Echo Request
    icmp_floods['icmp_code'] = 0
    icmp_floods['flags'] = 0      # ICMP không có flags
    
    # Tạo Flow ID mới cho ICMP
    icmp_floods['flow_id'] = (
        icmp_floods['ip_src'] + '0' + 
        icmp_floods['ip_dst'] + '0' + '1'
    )
    
    return icmp_floods

def normalize_chunk(df):
    """
    Hàm này thực hiện:
    1. Đổi tên cột CIC sang chuẩn Ryu Controller
    2. Tính toán Feature (Rate, Duration...)
    3. Gán Label (0: Benign, 1: Attack)
    """
    # 1. Map tên cột
    col_mapping = {
        'Source IP': 'ip_src', 'Src IP': 'ip_src',
        'Source Port': 'tp_src', 'Src Port': 'tp_src',
        'Destination IP': 'ip_dst', 'Dst IP': 'ip_dst',
        'Destination Port': 'tp_dst', 'Dst Port': 'tp_dst',
        'Protocol': 'ip_proto',
        'Flow Duration': 'flow_duration',
        'Total Fwd Packets': 'fwd_pkts',
        'Total Backward Packets': 'bwd_pkts',
        'Total Length of Fwd Packets': 'fwd_bytes',
        'Total Length of Bwd Packets': 'bwd_bytes',
        'Label': 'raw_label',
        'Timestamp': 'timestamp_orig'
    }
    df.rename(columns={k: v for k, v in col_mapping.items() if k in df.columns}, inplace=True)
    
    # Các cột bắt buộc
    required_cols = ['ip_src', 'tp_src', 'ip_dst', 'tp_dst', 'ip_proto']
    for c in required_cols:
        if c not in df.columns:
            df[c] = 0

    # 2. Xử lý dữ liệu
    df['ip_src'] = df['ip_src'].astype(str)
    df['ip_dst'] = df['ip_dst'].astype(str)
    
    # Tạo Flow ID
    df['flow_id'] = (
        df['ip_src'] + 
        df['tp_src'].fillna(0).astype(int).astype(str) + 
        df['ip_dst'] + 
        df['tp_dst'].fillna(0).astype(int).astype(str) + 
        df['ip_proto'].fillna(0).astype(int).astype(str)
    )

    # --- TÍNH TOÁN DURATION (FLOAT) ---
    if 'flow_duration' in df.columns:
        # CIC đơn vị là microsecond -> đổi sang second (float)
        df['duration_float'] = df['flow_duration'] / 1_000_000.0
    else:
        df['duration_float'] = 0.0

    # Tính Packet & Byte Count
    fwd_p = df['fwd_pkts'] if 'fwd_pkts' in df.columns else 0
    bwd_p = df['bwd_pkts'] if 'bwd_pkts' in df.columns else 0
    df['packet_count'] = fwd_p + bwd_p

    fwd_b = df['fwd_bytes'] if 'fwd_bytes' in df.columns else 0
    bwd_b = df['bwd_bytes'] if 'bwd_bytes' in df.columns else 0
    df['byte_count'] = fwd_b + bwd_b

    # Tính Rates (Dùng duration_float vừa tạo)
    # Tránh chia cho 0 hoặc số quá nhỏ
    df['packet_count_per_second'] = df.apply(
        lambda x: x['packet_count'] / x['duration_float'] if x['duration_float'] > 1e-6 else 0, axis=1
    )
    df['byte_count_per_second'] = df.apply(
        lambda x: x['byte_count'] / x['duration_float'] if x['duration_float'] > 1e-6 else 0, axis=1
    )
    
    # Tạo lại các cột _sec và _nsec để khớp với cấu trúc Controller cũ (nếu cần dùng)
    df['flow_duration_sec'] = df['duration_float'].astype(int) 
    df['flow_duration_nsec'] = ((df['duration_float'] - df['flow_duration_sec']) * 1e9).astype(int)

    df['packet_count_per_nsecond'] = 0
    df['byte_count_per_nsecond'] = 0

    # 3. Gán Label
    if 'raw_label' in df.columns:
        df['label'] = df['raw_label'].astype(str).apply(lambda x: 0 if 'BENIGN' in x.upper() else 1)
    else:
        df['label'] = 1

    # 4. Cột phụ
    df['timestamp'] = 0 
    df['datapath_id'] = 0
    
    # === ICMP Type/Code (dựa trên Protocol) ===
    # ICMP (ip_proto == 1): Type 8 (Echo Request - Ping Flood), Code 0
    # TCP/UDP: Type 0, Code 0 (không áp dụng)
    df['icmp_type'] = df['ip_proto'].apply(lambda x: 8 if x == 1 else 0)
    df['icmp_code'] = 0  # Luôn là 0 với Echo Request
    
    # === Flags (dựa trên Protocol) ===
    # TCP (ip_proto == 6): Có flags (SYN, ACK, FIN...)
    # UDP/ICMP: flags = 0 (không có)
    # Nếu file có cột flags sẵn thì dùng, nếu không và là TCP thì gán 2 (SYN)
    if 'flags' in df.columns:
        df['flags'] = df['flags'].fillna(0).astype(int)
    else:
        df['flags'] = df['ip_proto'].apply(lambda x: 2 if x == 6 else 0)  # 2 = SYN flag cho TCP
    
    df['idle_timeout'] = 0
    df['hard_timeout'] = 0

    # 5. Lọc cột
    target_columns = [
        'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst',
        'ip_proto', 'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec',
        'idle_timeout', 'hard_timeout', 'flags', 'packet_count', 'byte_count',
        'packet_count_per_second', 'packet_count_per_nsecond',
        'byte_count_per_second', 'byte_count_per_nsecond', 'label'
    ]
    
    return df.reindex(columns=target_columns, fill_value=0)

def main():
    print(f"--- BẮT ĐẦU TẠO DATASET ĐA DẠNG (TARGET: {TARGET_TOTAL_ROWS} ROWS) ---")
    
    csv_files = glob.glob(os.path.join(INPUT_FOLDER, '**/*.csv'), recursive=True)
    if not csv_files:
        print(f"Lỗi: Không tìm thấy file .csv trong thư mục '{INPUT_FOLDER}'")
        return
    
    print(f"Tìm thấy {len(csv_files)} file nguồn.")
    
    target_ddos_total = TARGET_TOTAL_ROWS // 2
    target_ddos_per_file = target_ddos_total // len(csv_files)
    
    global_benign_list = []
    global_ddos_list = []

    for i, file_path in enumerate(csv_files):
        file_name = os.path.basename(file_path)
        print(f"\n[{i+1}/{len(csv_files)}] Đang xử lý: {file_name}...")
        
        file_benign = []
        file_ddos = []
        ddos_collected = 0
        
        try:
            for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE, on_bad_lines='skip', low_memory=False):
                chunk = clean_column_names(chunk)
                processed = normalize_chunk(chunk)
                
                chunk_benign = processed[processed['label'] == 0]
                chunk_ddos = processed[processed['label'] == 1]
                
                if not chunk_benign.empty:
                    file_benign.append(chunk_benign)
                
                if ddos_collected < target_ddos_per_file and not chunk_ddos.empty:
                    needed = target_ddos_per_file - ddos_collected
                    take = chunk_ddos.head(needed)
                    file_ddos.append(take)
                    ddos_collected += len(take)
        
        except Exception as e:
            print(f"   Lỗi đọc file {file_name}: {e}")
            continue

        # Gộp kết quả của file hiện tại (Sửa lỗi SyntaxError tại đây)
        if file_benign:
            global_benign_list.append(pd.concat(file_benign))
        if file_ddos:
            global_ddos_list.append(pd.concat(file_ddos))
            
            # Tạo ICMP Flood từ UDP Flood
            file_ddos_concat = pd.concat(file_ddos)
            icmp_floods = create_icmp_flood_from_udp(file_ddos_concat, ratio=0.3)
            if not icmp_floods.empty:
                global_ddos_list.append(icmp_floods)
        
        # Log thông tin xử lý file
        total_benign = sum(len(b) for b in file_benign) if file_benign else 0
        total_ddos = len(pd.concat(file_ddos)) if file_ddos else 0
        icmp_count = len(icmp_floods) if 'icmp_floods' in locals() and not icmp_floods.empty else 0
        print(f"Benign: {total_benign} | UDP DDoS: {total_ddos}/{target_ddos_per_file} | ICMP Flood: {icmp_count} | Tổng: {total_benign + total_ddos + icmp_count}")

    print("\n--- TỔNG HỢP DỮ LIỆU ---")
    
    if not global_benign_list:
        print("CẢNH BÁO: Không tìm thấy Benign!")
        return

    full_benign = pd.concat(global_benign_list)
    full_ddos = pd.concat(global_ddos_list)
    
    limit = min(len(full_benign), len(full_ddos))
    print(f"-> Cân bằng về mức: {limit} dòng mỗi loại.")
    
    final_dataset = pd.concat([
        full_benign.sample(n=limit, random_state=42),
        full_ddos.sample(n=limit, random_state=42)
    ])
    
    final_dataset = final_dataset.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Đang lưu file {OUTPUT_FILE} ({len(final_dataset)} dòng)...")
    final_dataset.to_csv(OUTPUT_FILE, index=False)
    print("HOÀN TẤT!")

if __name__ == "__main__":
    main()