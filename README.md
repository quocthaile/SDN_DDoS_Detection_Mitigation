# SDN AI-Guard: DDoS Detection & Mitigation System

This project implements a robust Software-Defined Networking (SDN) security pipeline designed to detect and mitigate Distributed Denial of Service (DDoS) attacks in real-time. It leverages the **Ryu Controller** for network orchestration, a **Random Forest** machine learning model for traffic classification, and a **Streamlit** dashboard for monitoring and manual intervention.

## 1. System Architecture

The system operates on a closed-loop control model consisting of three distinct planes:

1. **Data Plane (Mininet & Open vSwitch):**
   * Simulates the network topology.
   * Forwards packets based on flow rules.
   * Sends `Packet-In` messages and flow statistics to the controller.
2. **Control Plane (Ryu Controller):**
   * **Traffic Monitoring:** Periodically requests flow statistics (packets/sec, bytes/sec) from switches.
   * **Hybrid Detection Engine:** Combines **Machine Learning (Random Forest)** for precise classification with **Rule-based Thresholds** (Safety/Fallback limits) to minimize false positives.
   * **Mitigation:** Automatically installs `DROP` rules with high priority for malicious IPs.
3. **Application Plane (Streamlit Dashboard):**
   * A web-based interface for real-time traffic visualization.
   * Displays attack logs and system health (CPU/RAM).
   * Provides a control panel for manual IP blocking.

---

## 2. Dataset & Feature Engineering

The training data is derived from the **CIC-DDoS2019** dataset, processed to match the specific statistics available in OpenFlow environments.

### 2.1 Feature Extraction Pipeline

The script `dataset/generate_dataset.py` processes raw PCAP/CSV files to extract 14 key features compatible with the Ryu Controller:

| Feature Group | Features                                     | Description                                 |
| :------------ | :------------------------------------------- | :------------------------------------------ |
| **Protocol**  | `ip_proto`, `icmp_code`, `icmp_type`         | Identifies TCP, UDP, or ICMP traffic types. |
| **Time**      | `duration_sec`, `duration_nsec`              | Duration of the flow.                       |
| **Volume**    | `packet_count`, `byte_count`                 | Total traffic volume.                       |
| **Rate**      | `pps_rate`, `bps_rate`                       | Calculated speed (packets/sec, bytes/sec).  |
| **Flags**     | `total_fwd_packets`, `total_bwd_packets`     | Directional packet counts.                  |

### 2.2 Data Processing

* **Cleaning:** Removal of `NaN` and `Infinity` values.
* **Labeling:** Traffic is labeled as `0` (Benign) or `1` (DDoS).
* **Output:** The processed dataset is saved as `dataset/dataset.csv` for model training.

---

## 3. Machine Learning Model

The `machine_learning/ML.py` module evaluates multiple algorithms to determine the best classifier.

### Algorithm Comparison (Accuracy)

Based on experimental results:

1. **Random Forest:** **98.44%** (Selected)
2. **Decision Tree:** 98.38%
3. **K-Nearest Neighbors:** 97.55%
4. **Logistic Regression:** 73.90%
5. **Naive Bayes:** 57.00%

### Why Random Forest?

* **Highest Accuracy:** Achieved ~98.5% on the test set.
* **Robustness:** The ensemble method (bagging) reduces the risk of overfitting compared to single Decision Trees.
* **Non-linearity:** Effectively handles complex, non-linear patterns in network traffic data better than linear models like Logistic Regression.

**Artifacts:**

* `models/rf_model.pkl`: The trained model used by the controller.
* `models/scaler.pkl`: The data scaler for normalization.

---

## 4. Installation & Setup

### 4.1 Prerequisites

Ensure the system has Python 3.9+ and the required system tools installed:

```bash
# System dependencies
sudo apt update
sudo apt install mininet openvswitch-switch hping3 -y

# Python libraries
pip install ryu scikit-learn pandas numpy streamlit altair psutil
```

### 4.2 Running the System

Open three separate terminals to run the components simultaneously.

**Terminal 1: SDN Controller** (Runs the logic and AI engine)

```bash
# Change to controller's directory
cd sdn_controller

# Run ryu controller
ryu-manager controller.py
```

Note: This generates `attack_log/attack_logs.csv` and `attack_log/manual_blocks.txt`.

**Terminal 2: Monitoring Dashboard** (Web Interface)

```bash
# Run streamlit
streamlit run dashboard.py
```

### **Terminal 3: Network Topology** (Mininet)

```bash
sudo python3 mininet_topology.py
# Inside Mininet CLI, verify connectivity:
mininet> pingall
```

## 5. Attack Scenarios & Testing

This project was re-tested against **10 scenarios** (as documented in the attached report). All tests are executed from the **Mininet CLI**.

### Setup (common for all scenarios)

* Victim host: `h18` (IP: `10.0.0.18`)
* Tools: `iperf` (legitimate high-bandwidth traffic) and `hping3` (attack traffic)
* The `-i uXXXX` option sets the packet interval in microseconds (e.g., `u10000` ≈ 100 PPS).
* For flood tests, adding `timeout` is recommended to stop the generator automatically.

### 5.1 Scenario 1: 4K Video / High-bandwidth legitimate traffic

**Goal:** Verify no false-positive blocking for legitimate high-bandwidth UDP streams.

```bash
mininet> h18 iperf -s -u &
mininet> h1 iperf -c 10.0.0.18 -u -b 25M -l 1400 -t 30
```

**Expected result:** `ALLOWED` (whitelist based on large average packet size).

### 5.2 Scenario 2: Normal web-like traffic (~100 PPS)

**Goal:** Verify the pre-filter/threshold avoids wasting AI compute on harmless traffic.

```bash
mininet> h2 hping3 --udp -p 80 -i u10000 10.0.0.18
```

**Expected result:** `ALLOWED` (below minimum threshold; AI can be skipped).

### 5.3 Scenario 3: UDP Flood (Max Speed)

**Goal:** Validate immediate mitigation for volumetric floods.

```bash
mininet> h3 timeout 10s hping3 --flood --udp -p 80 10.0.0.18
```

**Expected result:** `BLOCKED` (hard volumetric rule, no AI needed).

### 5.4 Scenario 4: “Video-rate” UDP Flood (small packets)

**Goal:** Detect a stealth technique that mimics video PPS but uses tiny packets.

```bash
mininet> h4 hping3 --udp -p 80 -i u450 10.0.0.18
```

**Expected result:** `BLOCKED` (behavior rule: high PPS + small packet size).

### 5.5 Scenario 5: Low-intensity Botnet UDP (Stealthy)

**Goal:** Evaluate ML detection in the “gray zone” (not large enough for hard rules).

```bash
mininet> h5 hping3 --udp -p 80 -i u1500 10.0.0.18
```

**Expected result:** `WARNING` (AI raises suspicion). Admin can use **manual block** to immediately switch this to `BLOCKED`.

### 5.6 Scenario 6: TCP SYN Flood (Max Speed)

**Goal:** Detect resource-exhaustion attempts against TCP services.

```bash
mininet> h6 timeout 10s hping3 -S -p 80 --flood 10.0.0.18
```

**Expected result:** `BLOCKED` (TCP behavior: SYN-like tiny packets at high PPS).

### 5.7 Scenario 7: TCP SYN Flood (Controlled Rate)

**Goal:** Detect SYN flood even when attacker rate-limits to evade simple bandwidth filters.

```bash
mininet> h7 hping3 -S -p 80 -i u1000 10.0.0.18
```

**Expected result:** `BLOCKED`.

### 5.8 Scenario 8: ICMP Echo Flood (Max Speed)

**Goal:** Validate mitigation for ICMP volumetric floods.

```bash
mininet> h8 timeout 10s hping3 --icmp --flood 10.0.0.18
```

**Expected result:** `BLOCKED` (volumetric threshold).

### 5.9 Scenario 9: ICMP Echo Flood (Controlled Rate)

**Goal:** Validate that the system can escalate from “suspicious” to “blocked” using AI confidence over time.

```bash
mininet> h9 hping3 --icmp -i u1000 10.0.0.18
```

**Expected result:** Initially flagged as suspicious; after observation AI confidence increases and traffic becomes `BLOCKED`.

### 5.10 Scenario 10: Distributed Attack (DDoS) from multiple hosts

**Goal:** Validate per-source detection/mitigation for a small botnet.

```bash
mininet> h18 iperf -s -u -p 80 &

# Run these in parallel (background)
mininet> h10 hping3 --udp -p 80 -i u500 10.0.0.18 &
mininet> h11 hping3 --udp -p 80 -i u500 10.0.0.18 &
mininet> h12 hping3 --udp -p 80 -i u500 10.0.0.18 &
```

**Expected result:** all botnet sources are added to blacklist independently; dashboard shows multiple malicious IPs.

## 6. Monitoring & Dashboard

The Streamlit dashboard is the operational console for real-time visibility and human-in-the-loop control.

### 6.1 Real-time traffic monitoring

* The dashboard updates an **area chart every ~1 second**.
* **Green (Benign):** legitimate traffic.
* **Red (Blocked):** attack traffic that has been identified and mitigated (dropped).
* **Orange (Allowed Attack / Passive Detect):** suspicious/attack traffic detected while running in **Passive Mode** (IDS-like).

In the experiments, the red ingress region represents traffic that was already dropped at the edge switch (Data Plane). This can be validated by observing that the victim-side traffic becomes negligible when mitigation is active.

### 6.2 IDS/IPS mode switching (Firewall toggle)

The system supports switching between:

* **Passive Mode (IDS):** detect + visualize + log (no dropping).
* **Active Mode (IPS):** detect + push `DROP` rules to the switch.

This is useful for demonstration, maintenance, and validating the model before enabling automatic mitigation.

### 6.3 Manual intervention

* **Manual block:** admin can block an IP immediately without waiting for AI decisions.
* **Unblock:** remove an IP from the current block list.
* **Blocked IP History:** tracks offenders and the reason (e.g., `Manual-Block`).

### 6.4 Resource monitoring & logs

* **CPU/RAM monitoring** for the controller host during high-rate floods.
* **Traffic Logs** table (time, src/dst, protocol, rate, reason).
* **Download Logs (CSV)** for reporting/forensics.
* **Clear logs** for clean re-tests.
* Optional: exported CSV can be re-used as a compatible dataset format for future model improvements.

### 6.5 Accessing the dashboard

Once the dashboard is running, open:

* Local: `http://localhost:8501`
* LAN: `http://<CONTROLLER_IP>:8501`

---

## 7. Future Work & Development Roadmap

Key limitations observed in the report:

* The system currently focuses on **flow-based statistics**, which makes **application-layer attacks** (e.g., HTTP Flood / Slowloris) harder to detect without deeper packet inspection.
* The ML model is trained **offline**; accuracy may degrade over time as attackers change patterns.

Proposed development directions:

1. **Online learning (continuous updates):** allow the ML model to learn from new labeled data during operation without stopping the system.
2. **P4 programmable data plane:** complement/replace OpenFlow with P4 to extract richer packet features at the switch (e.g., TCP flags, payload signatures) to improve app-layer detection.
3. **Deep learning models:** experiment with LSTM/CNN to better capture temporal attack behavior.
4. **Adaptive response:** automatically tune thresholds based on network load/time-of-day and observed user behavior.

---

