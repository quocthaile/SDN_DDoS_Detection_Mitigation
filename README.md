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
