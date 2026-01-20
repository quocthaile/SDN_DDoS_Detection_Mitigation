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

| Feature Group      | Features                                     | Description                                 |
| :----------------- | :------------------------------------------- | :------------------------------------------ |
| **Protocol** | `ip_proto`, `icmp_code`, `icmp_type`   | Identifies TCP, UDP, or ICMP traffic types. |
| **Time**     | `duration_sec`, `duration_nsec`          | Duration of the flow.                       |
| **Volume**   | `packet_count`, `byte_count`             | Total traffic volume.                       |
| **Rate**     | `pps_rate`, `bps_rate`                   | Calculated Speed (Packets/sec, Bytes/sec).  |
| **Flags**    | `total_fwd_packets`, `total_bwd_packets` | Directional packet counts.                  |

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

We use `hping3` within the Mininet CLI to simulate various attack vectors. Below are the specific commands used to test the system's detection capabilities.

### 5.1 UDP Flood (Bandwidth Exhaustion)
*Target: Consuming network bandwidth using high-frequency UDP packets (Protocol 17).*

**Scenario A: Max Speed Flood**
Sends packets as fast as possible to overwhelm the link.
```bash
h1 timeout 10s hping3 --flood --udp -p 80 h2
```

**Scenario B: Controlled Rate Attacks**
Using the -i flag to set specific intervals (u1000 = 1000 microseconds = 1000 packets/sec).

* **Standard High Rate (1,000 pps):** Simulates a standard volumetric attack.
```bash
h3 hping3 --udp -p 80 -i u1000 h4
```

* **AI Sensitivity Check (100 pps): ** Testing if the AI detects attacks at lower rates (u10000 approx 100 pps) or if it treats them as benign.
```bash
h5 hping3 --udp -p 80 -i u10000 h6
```

* **High Load Stress Test (10,000 pps): ** Generating extremely high load (-i u100) to test controller stability and ensure it does not freeze under pressure.
```bash
h7 hping3 --udp -p 80 -i u100 h8
```

### 5.2 TCP SYN Flood (Resource Exhaustion)
*Target: Exhausting server resources (RAM/Connections) using TCP SYN packets (Protocol 6) with high frequency.*

**Scenario A: SYN Flood (Max Speed)**
```bash
h9 timeout 20s hping3 -S --flood -p 80 h10
```

**Scenario B: SYN Flood (Controlled Rate)**
```bash
h11 timeout 20s hping3 -S -p 80 -i u1000 h12
```

### 5.3 ICMP Flood (Ping Flood)
*Target: Overwhelming the target with ICMP Echo Requests.*

**Scenario A: ICMP Flood (Max Speed)**
```bash
h13 timeout 20s hping3 --flood --icmp h14
```

**Scenario B: ICMP Flood (Controlled Rate)**
```bash
h15 timeout 20s hping3 --icmp -i u1000 h16
```

## 6. Monitoring & Dashboard

The Streamlit dashboard serves as the central command center, providing real-time visibility into the network's security posture.

### 6.1 Dashboard Features
* **Real-time Traffic Visualization:**
    * A dynamic area chart displaying network throughput in **KB/s** or **MB/s**.
    * **Visual Alert:** The chart line turns **RED** immediately when the AI detects malicious activity, and **GREEN** during normal operation.
* **Live Attack Logs:**
    * Displays the most recent 10 detected threats.
    * Columns include: `Timestamp`, `Source IP`, `Destination IP`, `Attack Type` (e.g., UDP Flood, SYN Flood), and `AI Confidence Score`.
    * **Export:** Includes a "Download Full Logs" button to export the complete history to CSV for forensic analysis.
* **System Health Monitoring:**
    * Tracks the **CPU** and **RAM** usage of the controller machine to ensure the security system itself is not being overwhelmed (DoS against the Controller).
* **Manual Control Panel:**
    * A sidebar interface allowing administrators to manually input and **Block** specific IP addresses immediately, overriding the AI's decision if necessary.

### 6.2 Accessing the Dashboard
Once `dashboard.py` is running, open your web browser and navigate to:
* **Local URL:** `http://localhost:8501`
* **Network URL:** `http://<CONTROLLER_IP>:8501`

---

## 7. Future Work & Development Roadmap

While the current system effectively handles standard DDoS scenarios, the following improvements are proposed to enhance scalability and robustness in production environments:

### 7.1 Database Integration
* **Current State:** The system relies on CSV files (`attack_logs.csv`) for logging. This can lead to file-locking issues (race conditions) when high-frequency attacks occur while the dashboard is trying to read the file.
* **Proposal:** Migrate to a lightweight SQL database (e.g., **SQLite**) or a time-series database (e.g., **InfluxDB**) to handle concurrent read/write operations efficiently without blocking I/O.

### 7.2 Mitigation Strategy Optimization
* **Current State:** Mitigation is primarily based on **Source IP Blocking**.
* **Limitation:** This is less effective against **IP Spoofing** attacks (e.g., `--rand-source`), as the attacker generates infinite unique source IPs, rapidly filling the switch's flow table.
* **Proposal:**
    * Implement **Destination-based Blocking**: If a victim host is overwhelmed, temporarily drop all UDP traffic destined for that host.
    * Utilize **OpenFlow Meter Tables**: Instead of hard drops, use meters to perform **Rate Limiting** (QoS), ensuring legitimate traffic can still pass through at a reduced speed.

### 7.3 Advanced Feature Engineering
* **Current State:** The model uses flow-based statistics (Packet Count, Byte Count, Duration).
* **Proposal:** Introduce **Entropy-based features** (e.g., Shannon Entropy of Source IPs per Destination). A sudden spike in Source IP entropy is a strong indicator of a Distributed (DDoS) attack versus a Single-source (DoS) attack.

### 7.4 Intelligent Unbanning Mechanism
* **Current State:** Blocked IPs are released after a fixed duration of **60 seconds**.
* **Proposal:** Implement an **Exponential Backoff** algorithm.
    * 1st Offense: Block for 1 minute.
    * 2nd Offense: Block for 5 minutes.
    * 3rd Offense: Block for 30 minutes.
    This penalizes persistent attackers more severely while allowing legitimate users (who may have been infected) to return sooner after cleaning their systems.