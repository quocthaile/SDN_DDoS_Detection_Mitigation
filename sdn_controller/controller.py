"""
SDN DDoS Detection and Mitigation Controller
=============================================
This module implements a Ryu SDN controller with AI-powered DDoS detection.
It monitors network traffic, analyzes flow statistics, and automatically
blocks malicious traffic using OpenFlow rules.

Key Features:
    - Real-time traffic monitoring via OpenFlow 1.3
    - AI-based attack detection using Random Forest classifier
    - Rule-based detection for volumetric attacks (UDP flood, TCP SYN flood)
    - Automatic IP blocking with escalating ban durations
    - Web dashboard integration for monitoring and manual control
    - Whitelist protection for legitimate high-bandwidth traffic

Architecture:
    Mininet Hosts -> OVS Switches -> Ryu Controller (this module)
                                          |
                                     AI Model (rf_model.pkl)
                                          |
                                     Dashboard (Streamlit)

Author: SDN DDoS Detection Project
"""

"""
# Config/threshold variables for the controller 
# are grouped in __init__ under SECTION 2/3 as 
# CONFIG_FLAGS, THRESHOLDS, and DISPLAY_TIMERS.
"""


# ============================================================
# SECTION 1: IMPORT LIBRARIES
# ============================================================

# --- Ryu Framework Core ---
from ryu.controller import ofp_event           # OpenFlow event definitions (PacketIn, FlowStats, etc.)
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
# MAIN_DISPATCHER: Switch is fully connected and operational
# DEAD_DISPATCHER: Switch connection is lost
# CONFIG_DISPATCHER: Switch is being configured (initial handshake)

from ryu.controller.handler import set_ev_cls  # Decorator to register event handlers
from ryu.base import app_manager              # Base class for Ryu applications
from ryu.ofproto import ofproto_v1_3          # OpenFlow 1.3 protocol constants

# --- Packet Parsing Libraries ---
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp, arp
# packet: Container for parsed packet data
# ethernet: Ethernet frame header (MAC addresses, EtherType)
# ether_types: Constants for EtherType values (IP=0x0800, ARP=0x0806, etc.)
# ipv4: IPv4 header (src/dst IP, protocol, TTL, etc.)
# tcp/udp/icmp: Layer 4 protocol headers

from ryu.lib import hub                        # Greenlet-based threading for background tasks

# --- Data Processing & Machine Learning ---
from datetime import datetime                  # Timestamp generation
import pandas as pd                            # DataFrame operations for logging
import numpy as np                             # Numerical arrays for ML features
import joblib                                  # Load pre-trained ML model (.pkl files)
from sklearn.preprocessing import StandardScaler  # Feature normalization (not used directly, loaded from file)

# --- System Utilities ---
import time                                    # Sleep, timestamps
import os                                      # File system operations
import sys                                     # stdout for dashboard output
import shutil                                  # File copy operations (unused but imported)
import textwrap                                # Reason wrapping for CLI display


class SimpleMonitor13(app_manager.RyuApp):
    """
    Main SDN Controller Application
    ================================
    Inherits from Ryu's app_manager.RyuApp base class.
    Implements OpenFlow 1.3 controller with DDoS detection capabilities.
    
    Attributes:
        OFP_VERSIONS: List of supported OpenFlow versions
        mac_to_port: MAC address learning table {dpid: {mac: port}}
        datapaths: Connected switches {dpid: datapath_object}
        blocked_ips: Currently blocked IPs {ip: {unlock_time, victim, proto, duration, reason}}
        flow_history: Historical flow statistics for rate calculation
        model: Loaded Random Forest classifier
        scaler: Feature scaler for ML model input normalization
    """
    
    # Declare supported OpenFlow version (1.3 required for advanced matching)
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initialize the controller application.
        
        This constructor:
        1. Sets up detection thresholds
        2. Initializes data structures
        3. Spawns monitoring thread
        4. Loads AI model and scaler
        5. Initializes log files
        """
        # Call parent class constructor (required for Ryu apps)
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        
        # ============================================================
        # SECTION 2: CONFIGURATION FLAGS (GROUPED)
        # ============================================================
        CONFIG_FLAGS = {
            'ENABLE_AI_PREDICT_LOG': True,   # Enable/disable AI prediction logging to CSV
            'STATUS_INTERVAL': 1.0,          # Dashboard refresh interval in seconds
            'DEBUG_LOGS': False,             # Enable/disable DEBUG lines in CLI
            'DEBUG_BLOCKED_FLOW_LOGS': False,  # Enable/disable [BLOCKED FLOW] logs
            'MANUAL_UNBLOCK_GRACE': 60,      # Seconds to prevent re-block after manual unblock
            'ENABLE_WHITELIST_FILTER': True,  # Enable/disable whitelist filter
            'ENABLE_VOLUMETRIC_THRESHOLD': False,  # Enable/disable volumetric threshold rule
        }

        # ============================================================
        # SECTION 3: DETECTION THRESHOLDS (GROUPED)
        # ============================================================
        # These values control detection sensitivity and accuracy.
        # Adjust based on network characteristics and attack patterns.
        THRESHOLDS = {
            # --- Basic Rate Thresholds ---
            'MIN_PPS_THRESHOLD': 150,        # Minimum packets/sec to trigger analysis
            'VOLUMETRIC_THRESHOLD': 4000,    # Maximum allowed PPS before hard block

            # --- AI Confidence Thresholds ---
            'AI_CONFIDENCE_THRESHOLD': 0.6, # AI probability threshold for blocking
            'AI_HIGH_CONFIDENCE': 0.99,      # Threshold for "absolute certainty"
            'AI_WARNING_THRESHOLD': 0.5,     # Threshold for warning (suspicious traffic)

            # --- Whitelist Protection (Video/Large File Transfers) ---
            'WHITELIST_PKT_SIZE': 1000,      # Minimum avg packet size (bytes) to whitelist

            # --- Blacklist Detection Rules ---
            'UDP_FLOOD_PPS': 1000,           # Minimum PPS to trigger UDP flood check
            'UDP_FLOOD_SIZE': 100,           # Max packet size for UDP flood classification
            'UDP_FLOOD_MIN_SIZE': 60,        # (Unused) kept for compatibility
            'SYN_FLOOD_PPS': 300,            # Minimum PPS to trigger SYN flood check
            'SYN_FLOOD_SIZE': 120,           # Max packet size for SYN flood classification
            'ICMP_FLOOD_PPS': 300,           # Minimum PPS to trigger ICMP flood check
        }

        # --- Dashboard Display Timer (Grouped) ---
        DISPLAY_TIMERS = {
            'PRED_LOCK_SECONDS': 3,          # Seconds to hold prediction on CLI dashboard
            'LOW_PRIORITY_ROTATE_SECONDS': 3 # Rotate NORMAL/WARNING display interval
        }

        self.ENABLE_AI_PREDICT_LOG = CONFIG_FLAGS['ENABLE_AI_PREDICT_LOG']
        self.STATUS_INTERVAL = CONFIG_FLAGS['STATUS_INTERVAL']
        self.DEBUG_LOGS = CONFIG_FLAGS['DEBUG_LOGS']
        self.DEBUG_BLOCKED_FLOW_LOGS = CONFIG_FLAGS['DEBUG_BLOCKED_FLOW_LOGS']
        self.MANUAL_UNBLOCK_GRACE = CONFIG_FLAGS['MANUAL_UNBLOCK_GRACE']
        self.ENABLE_WHITELIST_FILTER = CONFIG_FLAGS['ENABLE_WHITELIST_FILTER']
        self.ENABLE_VOLUMETRIC_THRESHOLD = CONFIG_FLAGS['ENABLE_VOLUMETRIC_THRESHOLD']

        self.MIN_PPS_THRESHOLD = THRESHOLDS['MIN_PPS_THRESHOLD']
        self.VOLUMETRIC_THRESHOLD = THRESHOLDS['VOLUMETRIC_THRESHOLD']
        self.AI_CONFIDENCE_THRESHOLD = THRESHOLDS['AI_CONFIDENCE_THRESHOLD']
        self.AI_HIGH_CONFIDENCE = THRESHOLDS['AI_HIGH_CONFIDENCE']
        self.AI_WARNING_THRESHOLD = THRESHOLDS['AI_WARNING_THRESHOLD']
        self.WHITELIST_PKT_SIZE = THRESHOLDS['WHITELIST_PKT_SIZE']
        self.UDP_FLOOD_PPS = THRESHOLDS['UDP_FLOOD_PPS']
        self.UDP_FLOOD_SIZE = THRESHOLDS['UDP_FLOOD_SIZE']
        self.UDP_FLOOD_MIN_SIZE = THRESHOLDS['UDP_FLOOD_MIN_SIZE']
        self.SYN_FLOOD_PPS = THRESHOLDS['SYN_FLOOD_PPS']
        self.SYN_FLOOD_SIZE = THRESHOLDS['SYN_FLOOD_SIZE']
        self.ICMP_FLOOD_PPS = THRESHOLDS['ICMP_FLOOD_PPS']

        self.PRED_LOCK_SECONDS = DISPLAY_TIMERS['PRED_LOCK_SECONDS']
        self.LOW_PRIORITY_ROTATE_SECONDS = DISPLAY_TIMERS['LOW_PRIORITY_ROTATE_SECONDS']
        
        # ============================================================
        # SECTION 4: RUNTIME STATE VARIABLES
        # ============================================================
        
        self.firewall_enabled = True         # Master switch for blocking functionality
                                             # When False: detect only, no blocking
        
        self.mac_to_port = {}                # MAC learning table: {dpid: {mac_addr: port_num}}
                                             # Used for L2 forwarding decisions
        
        self.datapaths = {}                  # Connected switches: {dpid: datapath_object}
                                             # datapath provides API to send OpenFlow messages
        
        # Spawn background monitoring thread using Ryu's greenlet hub
        # _monitor() runs continuously, checking stats every STATUS_INTERVAL
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.blocked_ips = {}                # Currently blocked IPs with metadata
                                             # {ip: {unlock_time, victim, proto, duration, reason}}

        self.manual_allow = {}               # Manual unblocks with grace period
                             # {ip: unlock_time}
        
        self.flow_history = {}               # Historical flow stats for rate calculation
                                             # {flow_key: (last_pkts, last_bytes, last_timestamp)}
        
        self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
                                             # Aggregate flow counts by protocol
        
        self.switch_stats = {}               # Per-switch statistics: {dpid: {proto: count}}
        
        self.active_flow_stats = {}          # Active flows with rates for dashboard
                                             # {flow_key: {rate, type, timestamp}}
        
        # --- CLI Dashboard State ---
        self.latest_pred = {
            'src': '-', 'dst': '-', 'proto': '-',
            'rate': 0, 'result': 'IDLE', 'conf': '-', 'reason': '-',
            'priority': -1
        }  # Current prediction displayed on CLI dashboard
        
        self.pred_lock_until = 0             # Timestamp when prediction display lock expires
        self.pred_lock_priority = -1         # Priority level of locked prediction
        self.last_low_priority = "NORMAL"    # Last shown low-priority type (NORMAL/WARNING)
        self.last_low_rotate_ts = 0          # Last time low-priority display rotated
        self.last_monitor_flows = []         # Cached top flows for real-time monitor
        self.last_monitor_update = 0         # Timestamp of last non-empty monitor snapshot
        self.last_blocked_proto = {}         # Remember last known proto per blocked IP
        
        # ============================================================
        # SECTION 5: FILE PATH CONFIGURATION
        # ============================================================
        
        # Get absolute path of this script's directory
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        # Navigate to attack_log directory (one level up, then into attack_log)
        LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../attack_log"))
        
        # Create log directory if it doesn't exist
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)

        # Define paths for all log/data files
        self.HISTORY_FILE = os.path.join(LOG_DIR, "offender_history.csv")
        # Stores historical attacker data: IP, block count, attack methods, last seen
        
        self.DDOS_DATASET_FILE = os.path.join(LOG_DIR, "ddos_captured_dataset.csv")
        # Full dataset with all flow features for training/analysis
        
        self.MANUAL_BLOCK_FILE = os.path.join(LOG_DIR, "manual_blocks.txt")
        # Queue file for manual IP blocks from dashboard
        
        self.MANUAL_UNBLOCK_FILE = os.path.join(LOG_DIR, "manual_unblocks.txt")
        # Queue file for manual IP unblocks from dashboard
        
        self.CURRENT_BLOCKS_FILE = os.path.join(LOG_DIR, "current_blocks.csv")
        # Current blocked IPs for dashboard display
        
        self.ATTACK_LOG_FILE = os.path.join(LOG_DIR, "attack_logs.csv")
        # Log of detected attacks with timestamps and reasons
        
        self.AI_PREDICT_LOG_FILE = os.path.join(LOG_DIR, "ai_predict.csv")
        # Detailed AI prediction log with probabilities
        
        self.TRAFFIC_MONITOR_FILE = os.path.join(LOG_DIR, "traffic_monitor.csv")
        # Time-series traffic data for dashboard charts
        
        self.DEBUG_FILE = "debug_ai_prediction.log"
        # Debug output for troubleshooting
        
        self.FIREWALL_STATUS_FILE = os.path.join(LOG_DIR, "firewall_status.txt")
        # Firewall ON/OFF state (read by controller, written by dashboard)
        
        # ============================================================
        # SECTION 6: INITIALIZE PERSISTENT DATA
        # ============================================================
        
        self.offender_history = {}           # In-memory copy of offender history
        self._load_offender_history()        # Load from CSV file
        
        self._init_files()                   # Initialize data files with headers
        self._init_traffic_monitor()         # Initialize traffic monitor CSV
        self._init_firewall_status()         # Initialize firewall status file

        # ============================================================
        # SECTION 7: LOAD AI MODEL
        # ============================================================
        
        print("Loading AI Model...")
        try:
            # Construct paths to model files
            model_path = os.path.join(BASE_DIR, '../models/rf_model.pkl')
            scaler_path = os.path.join(BASE_DIR, '../models/scaler.pkl')
            
            if os.path.exists(model_path):
                # Load pre-trained Random Forest model
                self.model = joblib.load(model_path)
                # Load feature scaler (StandardScaler) for input normalization
                self.scaler = joblib.load(scaler_path)
                print("-> Model & Scaler loaded successfully!")
            else:
                self.model = None
                print(f"ERROR: Model not found at {model_path}")
        except Exception as e:
            print(f"ERROR loading model: {e}")
            self.model = None

    # ============================================================
    # SECTION 8: INITIALIZATION HELPER METHODS
    # ============================================================

    def _load_offender_history(self):
        """
        Load offender history from CSV file into memory.
        
        File format: Attacker_IP, Total_Blocks, Attack_Methods, Last_Seen
        
        Populates self.offender_history dictionary with:
            {ip: {'count': int, 'methods': set, 'last': str}}
        """
        if os.path.exists(self.HISTORY_FILE):
            try:
                # Check if file has content
                if os.path.getsize(self.HISTORY_FILE) > 0:
                    df = pd.read_csv(self.HISTORY_FILE)
                    for _, row in df.iterrows():
                        ip = str(row['Attacker_IP'])
                        count = int(row['Total_Blocks'])
                        m_str = str(row['Attack_Methods'])
                        # Split "TCP+UDP" into set {'TCP', 'UDP'}
                        methods = set(m_str.split('+')) if m_str else set()
                        self.offender_history[ip] = {
                            'count': count,
                            'methods': methods,
                            'last': row['Last_Seen']
                        }
                    print(f"-> Loaded history for {len(self.offender_history)} IPs.")
            except Exception as e:
                print(f"Error loading history: {e}")

    def _init_traffic_monitor(self):
        """
        Initialize traffic monitor CSV file with headers.
        
        Creates new file, overwriting any existing data.
        Sets file permissions to 666 (read/write for all) for dashboard access.
        """
        with open(self.TRAFFIC_MONITOR_FILE, "w") as f:
            f.write("Timestamp,Blocked_MBps,Suspicious_MBps,Benign_MBps\n")
        try:
            os.chmod(self.TRAFFIC_MONITOR_FILE, 0o666)  # Make file accessible to dashboard
        except:
            pass

    def _init_files(self):
        """
        Initialize data files with appropriate headers.
        
        Creates DDoS dataset file and AI prediction log if they don't exist.
        """
        # Initialize DDoS dataset file
        if not os.path.exists(self.DDOS_DATASET_FILE):
            # Define all columns for the dataset (matches training data format)
            cols = [
                "timestamp", "datapath_id", "flow_id", "ip_src", "tp_src",
                "ip_dst", "tp_dst", "ip_proto", "icmp_code", "icmp_type",
                "flow_duration_sec", "flow_duration_nsec", "idle_timeout", "hard_timeout",
                "flags", "packet_count", "byte_count",
                "packet_count_per_second", "packet_count_per_nsecond",
                "byte_count_per_second", "byte_count_per_nsecond", "label"
            ]
            with open(self.DDOS_DATASET_FILE, "w") as f:
                f.write(",".join(cols) + "\n")
            try:
                os.chmod(self.DDOS_DATASET_FILE, 0o666)
            except:
                pass

        # Initialize AI prediction log file
        if self.ENABLE_AI_PREDICT_LOG and not os.path.exists(self.AI_PREDICT_LOG_FILE):
            headers = "Timestamp,SrcIP,DstIP,Proto,PPS,AI_Prob_Normal,AI_Prob_Attack,Verdict,Action,Reason\n"
            with open(self.AI_PREDICT_LOG_FILE, "w") as f:
                f.write(headers)
            try:
                os.chmod(self.AI_PREDICT_LOG_FILE, 0o666)
            except:
                pass

    def _init_firewall_status(self):
        """
        Initialize firewall status file.
        
        Creates file with "ON" if it doesn't exist.
        This file is read by controller and written by dashboard for control.
        """
        if not os.path.exists(self.FIREWALL_STATUS_FILE):
            with open(self.FIREWALL_STATUS_FILE, "w") as f:
                f.write("ON")
            try:
                os.chmod(self.FIREWALL_STATUS_FILE, 0o666)
            except:
                pass

    def _debug_print(self, message):
        """
        Print debug messages when DEBUG_LOGS is enabled.
        """
        if self.DEBUG_LOGS:
            print(message)

    # ============================================================
    # SECTION 9: OPENFLOW EVENT HANDLERS
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handle switch connection and initial configuration.
        
        Called when a new switch connects to the controller.
        Installs table-miss flow entry to send unmatched packets to controller.
        
        Args:
            ev: EventOFPSwitchFeatures event containing switch capabilities
        
        Flow installed:
            Match: ANY (empty match)
            Action: OUTPUT to CONTROLLER
            Priority: 0 (lowest, acts as default/table-miss)
        """
        datapath = ev.msg.datapath           # Switch connection object
        ofproto = datapath.ofproto           # OpenFlow protocol constants for this version
        parser = datapath.ofproto_parser     # Message builder for this OpenFlow version
        
        # Create empty match (matches all packets)
        match = parser.OFPMatch()
        
        # Action: send packet to controller with no buffer limit
        # OFPP_CONTROLLER: special port number for controller
        # OFPCML_NO_BUFFER: send entire packet (don't buffer in switch)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # Install table-miss flow entry with priority 0
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """
        Install a flow entry in the switch's flow table.
        
        Args:
            datapath: Switch connection object
            priority: Flow entry priority (higher = matched first)
            match: OFPMatch object specifying packet matching criteria
            actions: List of OFPAction objects (what to do with matched packets)
            buffer_id: ID of buffered packet (optional, for PacketIn responses)
            idle_timeout: Remove flow after N seconds of inactivity (0 = no timeout)
            hard_timeout: Remove flow after N seconds regardless of activity (0 = no timeout)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Wrap actions in instruction (APPLY_ACTIONS = execute actions immediately)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # Build FlowMod message
        if buffer_id:
            # If we have a buffered packet, reference it
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        
        # Send FlowMod to switch
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handle packets sent to controller (table-miss or explicit OUTPUT to CONTROLLER).
        
        This is the main L2 learning switch logic:
        1. Learn source MAC -> ingress port mapping
        2. Lookup destination MAC to find egress port
        3. Install flow entry for this traffic pattern
        4. Forward the packet
        
        Also implements firewall blocking for banned IPs.
        
        Args:
            ev: EventOFPPacketIn event containing the packet data
        """
        msg = ev.msg                          # OpenFlow message
        datapath = msg.datapath               # Switch that sent the packet
        ofproto = datapath.ofproto            # Protocol constants
        parser = datapath.ofproto_parser      # Message builder
        in_port = msg.match['in_port']        # Port where packet arrived
        
        # Parse the raw packet data
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]  # Get Ethernet header

        # Ignore LLDP packets (Link Layer Discovery Protocol)
        # LLDP is used for topology discovery, not user traffic
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # FIREWALL CHECK: Block packets from banned IPs
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            if self.firewall_enabled and src_ip in self.blocked_ips:
                return  # Drop packet silently (don't forward or install flow)

        # Extract MAC addresses
        dst = eth.dst  # Destination MAC
        src = eth.src  # Source MAC
        dpid = datapath.id  # Switch datapath ID

        # MAC LEARNING: Remember which port this MAC is on
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # DESTINATION LOOKUP: Find output port for destination MAC
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]  # Known destination
        else:
            out_port = ofproto.OFPP_FLOOD  # Unknown: flood to all ports

        # Build output action
        actions = [parser.OFPActionOutput(out_port)]

        # SMART FLOW MATCHING: For IP packets, install granular flow entries
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            
            # Build match criteria dictionary
            match_kwargs = {
                'in_port': in_port,
                'eth_dst': dst,
                'eth_src': src,
                'eth_type': ether_types.ETH_TYPE_IP,
                'ipv4_src': ip_pkt.src,
                'ipv4_dst': ip_pkt.dst,
                'ip_proto': ip_pkt.proto
            }

            # Service ports to match specifically (for traffic classification)
            SERVICE_PORTS = [80, 443, 8080]  # HTTP, HTTPS, alt-HTTP

            # Add protocol-specific matching
            if ip_pkt.proto == 1:  # ICMP
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt:
                    match_kwargs['icmpv4_type'] = icmp_pkt.type
                    
            elif ip_pkt.proto == 6:  # TCP
                t = pkt.get_protocol(tcp.tcp)
                if t:
                    # Match on service port for better flow granularity
                    if t.dst_port in SERVICE_PORTS:
                        match_kwargs['tcp_dst'] = t.dst_port
                    elif t.src_port in SERVICE_PORTS:
                        match_kwargs['tcp_src'] = t.src_port

            elif ip_pkt.proto == 17:  # UDP
                u = pkt.get_protocol(udp.udp)
                if u:
                    if u.dst_port in SERVICE_PORTS:
                        match_kwargs['udp_dst'] = u.dst_port
                    elif u.src_port in SERVICE_PORTS:
                        match_kwargs['udp_src'] = u.src_port

            # Create match object from criteria
            match = parser.OFPMatch(**match_kwargs)
            
            # Install flow entry (priority 1, above table-miss)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id)
            else:
                self.add_flow(datapath, 1, match, actions)

        # FORWARD THE PACKET (for this specific packet)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data  # Packet data is in the message
        
        # Build and send PacketOut message
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Handle switch connection state changes.
        
        Tracks connected switches in self.datapaths dictionary.
        Cleans up state when switches disconnect.
        
        Args:
            ev: State change event
        """
        datapath = ev.datapath
        
        if ev.state == MAIN_DISPATCHER:
            # Switch connected and ready
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                
        elif ev.state == DEAD_DISPATCHER:
            # Switch disconnected
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
            if datapath.id in self.switch_stats:
                del self.switch_stats[datapath.id]

    # ============================================================
    # SECTION 10: FIREWALL CONTROL METHODS
    # ============================================================

    def _clear_all_blocks(self):
        """
        Remove all blocking flow entries from all switches.
        
        Called when firewall is disabled to restore normal traffic flow.
        Deletes all flows with priority 1000 (blocking rules).
        """
        print("!!! FIREWALL DISABLED: Clearing all Drop Rules !!!")
        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # Delete only blocking flows (priority 1000) without touching
            # table-miss or learned forwarding rules.
            # NOTE: For OFPFC_DELETE, priority is ignored unless strict.
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE_STRICT,  # Match strictly on priority
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=1000,
                match=parser.OFPMatch()
            )
            datapath.send_msg(mod)
            
            # Send barrier to ensure deletion completes
            datapath.send_msg(parser.OFPBarrierRequest(datapath))

    def _check_firewall_file(self):
        """
        Read firewall status from file and update state.
        
        Dashboard writes "ON" or "OFF" to firewall_status.txt.
        Controller reads this file to sync state.
        
        State transitions:
            ON -> OFF: Clear all blocks, disable detection actions
            OFF -> ON: Re-enable detection and blocking
        """
        try:
            if os.path.exists(self.FIREWALL_STATUS_FILE):
                with open(self.FIREWALL_STATUS_FILE, "r") as f:
                    content = f.read().strip().upper()
                
                new_state = (content == "ON")
                
                # Transition: ON -> OFF
                if self.firewall_enabled and not new_state:
                    self.firewall_enabled = False
                    self.blocked_ips.clear()      # Clear blocked IPs list
                    self._clear_all_blocks()       # Remove blocking flows
                    # Reset runtime stats so dashboard reflects new state
                    self.flow_history.clear()
                    self.active_flow_stats.clear()
                    self.switch_stats.clear()
                    self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
                    self.latest_pred = {
                        'src': '-', 'dst': '-', 'proto': '-',
                        'rate': 0, 'result': 'IDLE', 'conf': '-', 'reason': '-',
                        'priority': -1
                    }
                    self.pred_lock_until = 0
                    self.pred_lock_priority = -1
                    self.last_low_priority = "NORMAL"
                    self.last_low_rotate_ts = 0
                    self._init_traffic_monitor()
                    
                # Transition: OFF -> ON
                elif not self.firewall_enabled and new_state:
                    self.firewall_enabled = True
                    print("!!! FIREWALL ENABLED !!!")
                    # Reset runtime stats so dashboard reflects new state
                    self.flow_history.clear()
                    self.active_flow_stats.clear()
                    self.switch_stats.clear()
                    self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
                    self.latest_pred = {
                        'src': '-', 'dst': '-', 'proto': '-',
                        'rate': 0, 'result': 'IDLE', 'conf': '-', 'reason': '-',
                        'priority': -1
                    }
                    self.pred_lock_until = 0
                    self.pred_lock_priority = -1
                    self.last_low_priority = "NORMAL"
                    self.last_low_rotate_ts = 0
                    self._init_traffic_monitor()
                    
        except Exception as e:
            print(f"Error checking firewall status: {e}")

    # ============================================================
    # SECTION 11: MONITORING THREAD
    # ============================================================

    def _monitor(self):
        """
        Background monitoring thread (runs continuously).
        
        Executes every STATUS_INTERVAL seconds:
        1. Check firewall status file
        2. Clean up expired blocked IPs
        3. Request flow statistics from switches
        4. Check for manual block requests
        5. Aggregate traffic data for dashboard
        6. Update CLI dashboard display
        """
        while True:
            # Check if dashboard changed firewall state
            self._check_firewall_file()

            # Reset offender history if file was deleted (dashboard cleanup)
            if not os.path.exists(self.HISTORY_FILE) and len(self.offender_history) > 0:
                self.offender_history = {}

            # Fix auto reblock---------------
            current_time = time.time()
            
            # List copy to pass "dictionary changed size during iteration"
            for ip in list(self.blocked_ips.keys()):
                info = self.blocked_ips[ip]
                # Nếu không phải chặn thủ công VÀ đã hết giờ
                if info['reason'] != "Manual-Block" and current_time > info['unlock_time']:
                    print(f"[TIMER] Time expired for {ip}. Unbanning...")
                    self._unblock_ip(ip)
            # Fix auto reblock-------------

            # CLEANUP EXPIRED BLOCKS
            current_ts = datetime.now().timestamp()
            expired_ips = [ip for ip, data in self.blocked_ips.items()
                          if current_ts > data['unlock_time']]
            for ip in expired_ips:
                del self.blocked_ips[ip]

            # CLEANUP EXPIRED MANUAL UNBLOCK GRACE
            expired_allow = [ip for ip, ts in self.manual_allow.items()
                             if current_ts > ts]
            for ip in expired_allow:
                del self.manual_allow[ip]

            # Reset prediction display lock if expired
            if time.time() >= self.pred_lock_until:
                self.pred_lock_priority = -1
                self.latest_pred['priority'] = -1

            # REQUEST STATS FROM ALL SWITCHES
            for dp in self.datapaths.values():
                self._request_stats(dp)
                if self.firewall_enabled:
                    self._check_manual_blocks(dp)
                    self._check_manual_unblocks(dp)
            
            # Write current blocked IPs to file for dashboard
            self._write_current_blocks()

            # Wait for stats replies to arrive
            time.sleep(1.0)

            # AGGREGATE TRAFFIC DATA FOR DASHBOARD
            monitor_ts = time.time()
            total_blocked = 0.0
            total_suspicious = 0.0
            total_benign = 0.0
            
            # Debug: count flows by type before aggregation
            blocked_count = sum(1 for k, v in self.active_flow_stats.items() if v.get('type') == 'Blocked')
            benign_count = sum(1 for k, v in self.active_flow_stats.items() if v.get('type') == 'Benign')
            if blocked_count > 0 or benign_count > 0:
                self._debug_print(f"[DEBUG AGGREGATE] Blocked: {blocked_count}, Benign: {benign_count} flows in active_flow_stats")
                # Print top benign flows
                for k, v in self.active_flow_stats.items():
                    if v.get('type') == 'Benign' and v.get('rate', 0) > 0.01:
                        self._debug_print(f"[DEBUG AGGREGATE] Benign flow: {k[1]} -> {k[2]} Rate: {v.get('rate', 0):.4f} Mbps")

            # Sum up traffic rates from active flows
            stale_count = 0
            low_rate_count = 0
            blocked_ip_skip_count = 0
            counted_benign = 0
            
            for key in list(self.active_flow_stats.keys()):
                info = self.active_flow_stats[key]
                
                # Remove stale entries (blocked flows are kept longer for display)
                info_type = info.get('type', 'Benign')
                stale_limit = 15.0 if info_type == 'Blocked' else 1.5
                if monitor_ts - info['ts'] > stale_limit:
                    stale_count += 1
                    del self.active_flow_stats[key]
                    continue

                # FIREWALL OFF: aggregate all traffic directly (no low-rate filtering)
                if not self.firewall_enabled:
                    rate = info.get('rate', 0)
                    if rate > 0:
                        if info.get('type') in ['Suspicious', 'Blocked']:
                            total_suspicious += rate
                        else:
                            total_benign += rate
                    continue
                
                # Categorize traffic by type
                # NOTE: BLOCKED flows should ALWAYS be counted, regardless of blocked_ips status
                # because they represent attack traffic that was successfully stopped
                if info['type'] == 'Blocked':
                    # Always count blocked traffic, even if rate is low
                    if info['rate'] > 0:
                        total_blocked += info['rate']
                elif info['type'] == 'Suspicious':
                    if info['rate'] > 0.001:
                        total_suspicious += info['rate']
                else:
                    # Skip benign flows with negligible rate
                    if info['rate'] <= 0.001:
                        low_rate_count += 1
                        # Debug: show first few low rate flows
                        if low_rate_count <= 5:
                            self._debug_print(f"[DEBUG LOW_RATE] key={key}, rate={info['rate']}, type={info['type']}")
                        continue
                        
                    # Only skip benign flows involving blocked IPs (prevents ghost traffic)
                    src_ip = key[1] if len(key) > 1 else None
                    dst_ip = key[2] if len(key) > 2 else None
                    
                    # Check if source IP is blocked
                    if src_ip and src_ip in self.blocked_ips:
                        if monitor_ts < self.blocked_ips[src_ip]['unlock_time']:
                            blocked_ip_skip_count += 1
                            del self.active_flow_stats[key]
                            continue
                    
                    # Check if destination IP is blocked (response traffic to blocked attacker)
                    if dst_ip and dst_ip in self.blocked_ips:
                        if monitor_ts < self.blocked_ips[dst_ip]['unlock_time']:
                            blocked_ip_skip_count += 1
                            del self.active_flow_stats[key]
                            continue
                    
                    counted_benign += 1
                    total_benign += info['rate']
                    # Debug first 5 counted flows
                    if counted_benign <= 5:
                        self._debug_print(f"[DEBUG COUNTED] key={key} rate={info['rate']:.4f} type={info['type']}")
            
            # Clear stale CLI prediction when no traffic is observed
            if total_blocked == 0 and total_suspicious == 0 and total_benign == 0:
                if time.time() >= self.pred_lock_until:
                    self.latest_pred = {
                        'src': '-', 'dst': '-', 'proto': '-',
                        'rate': 0, 'result': 'IDLE', 'conf': '-', 'reason': '-',
                        'priority': -1
                    }
                    self.pred_lock_priority = -1
                    self.pred_lock_until = 0

            # Debug summary
            self._debug_print(f"[DEBUG SUMMARY] Stale: {stale_count}, LowRate: {low_rate_count}, BlockedIPSkip: {blocked_ip_skip_count}, Counted: {counted_benign}")
            self._debug_print(f"[DEBUG TOTALS] Blocked: {total_blocked:.4f} Mbps, Benign: {total_benign:.4f} Mbps, Suspicious: {total_suspicious:.4f} Mbps")
            
            # Debug: show all flows with rate > 0.01
            high_rate_flows = [(k, v) for k, v in self.active_flow_stats.items() if v.get('rate', 0) > 0.01]
            if high_rate_flows:
                self._debug_print(f"[DEBUG HIGH_RATE] {len(high_rate_flows)} flows with rate > 0.01:")
                for k, v in high_rate_flows[:5]:
                    self._debug_print(f"    {k} -> rate={v['rate']:.4f}, type={v['type']}")

            # WRITE TRAFFIC DATA TO FILE (for dashboard charts)
            try:
                ts_str = datetime.now().strftime('%H:%M:%S')
                if not os.path.exists(self.TRAFFIC_MONITOR_FILE):
                    with open(self.TRAFFIC_MONITOR_FILE, "w") as f:
                        f.write("Timestamp,Blocked_MBps,Suspicious_MBps,Benign_MBps\n")

                with open(self.TRAFFIC_MONITOR_FILE, "a") as f:
                    f.write(f"{ts_str},{total_blocked:.4f},{total_suspicious:.4f},{total_benign:.4f}\n")
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
                
                # Debug: log traffic values if blocked traffic exists
                if total_blocked > 0.001:
                    print(f"[TRAFFIC] Blocked: {total_blocked:.4f} Mbps | Suspicious: {total_suspicious:.4f} Mbps | Benign: {total_benign:.4f} Mbps")
                if total_benign > 0.001:
                    print(f"[TRAFFIC] Benign: {total_benign:.4f} Mbps")
            except Exception as e:
                print(f"[ERROR] Failed to write traffic monitor: {e}")

            # Update CLI dashboard
            self._print_dashboard()

    def _check_manual_blocks(self, datapath):
        """
        Check for manual block requests from dashboard.
        
        Dashboard writes IPs to manual_blocks.txt (one per line).
        This method reads the file and blocks each IP.
        File is cleared after processing.
        
        Args:
            datapath: Switch to install blocking rules on
        """
        if not os.path.exists(self.MANUAL_BLOCK_FILE):
            return
            
        ips_to_block = []
        try:
            # Read all IPs from file
            with open(self.MANUAL_BLOCK_FILE, "r") as f:
                lines = f.readlines()
            
            if lines:
                for line in lines:
                    ip = line.strip()
                    if ip:
                        ips_to_block.append(ip)
                        
                # Clear the file after reading
                with open(self.MANUAL_BLOCK_FILE, "w") as f:
                    f.write("")
        except:
            return

        # Block each IP
        for ip in ips_to_block:
            if ip not in self.blocked_ips:
                self._block_ip(datapath, ip, "Manual-Block", 0, reason="Manual-Block")

    def _check_manual_unblocks(self, datapath):
        """
        Check for manual unblock requests from dashboard.
        
        Dashboard writes IPs to manual_unblocks.txt (one per line).
        This method reads the file and unblocks each IP.
        File is cleared after processing.
        
        Args:
            datapath: Switch to remove blocking rules from
        """
        if not os.path.exists(self.MANUAL_UNBLOCK_FILE):
            return
            
        ips_to_unblock = []
        try:
            # Read all IPs from file
            with open(self.MANUAL_UNBLOCK_FILE, "r") as f:
                lines = f.readlines()
            
            if lines:
                for line in lines:
                    ip = line.strip()
                    if ip:
                        ips_to_unblock.append(ip)
                        
                # Clear the file after reading
                with open(self.MANUAL_UNBLOCK_FILE, "w") as f:
                    f.write("")
        except:
            return

        # Unblock each IP
        for ip in ips_to_unblock:
            if ip in self.blocked_ips:
                self._unblock_ip(ip)

    # def _unblock_ip(self, datapath, ip_src):
    #     """
    #     Unblock an IP address by removing its DROP flow rule.
        
    #     Args:
    #         datapath: Switch to remove rule from
    #         ip_src: IP address to unblock
    #     """
    #     if ip_src not in self.blocked_ips:
    #         return
            
    #     # Remove from blocked_ips dictionary
    #     del self.blocked_ips[ip_src]

    #     # Add grace period to prevent immediate re-block
    #     self.manual_allow[ip_src] = datetime.now().timestamp() + self.MANUAL_UNBLOCK_GRACE
        
    #     # Remove blocking flow rule from switch
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
        
    #     # Match the blocking rule
    #     match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        
    #     # Delete the flow
    #     mod = parser.OFPFlowMod(
    #         datapath=datapath,
    #         command=ofproto.OFPFC_DELETE,
    #         out_port=ofproto.OFPP_ANY,
    #         out_group=ofproto.OFPG_ANY,
    #         match=match
    #     )
    #     datapath.send_msg(mod)
        
    #     print(f"[UNBLOCK] Removed block for {ip_src}")
    
    def _unblock_ip(self, ip):
        print(f"[INFO] Unblocking IP: {ip}")
        
        # 1. Gửi lệnh xóa luật DROP trên TOÀN BỘ Switch
        # Phải đảm bảo Match y hệt lúc chặn (eth_type=0x0800, ipv4_src=ip)
        for dpid in self.datapaths:
            datapath = self.datapaths[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            
            # Lệnh DELETE phải cực kỳ cụ thể
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE, # Lệnh xóa
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=100,     # [QUAN TRỌNG] Priority phải khớp với Hard Rule
                match=match,
                table_id=0        # [QUAN TRỌNG] Phải chỉ rõ bảng 0
            )
            datapath.send_msg(mod)

        # 2. Xóa khỏi danh sách quản lý Block
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]

        # 3. [FIX BUG] Dọn dẹp sạch sẽ "Tiền án" (History & Cache)
        # Nếu không xóa, lần sau IP này xuất hiện sẽ bị tính toán sai dựa trên số liệu cũ
        keys_to_remove = []
        
        # Quét sạch history liên quan đến IP này (cả chiều đi và chiều về nếu cần)
        for key in list(self.flow_history.keys()):
            # key structure: (dpid, src, dst, proto, priority)
            # Kiểm tra nếu src_ip trùng với IP vừa unban
            if key[1] == ip: 
                keys_to_remove.append(key)
        
        # Thực hiện xóa
        for key in keys_to_remove:
            if key in self.flow_history:
                del self.flow_history[key]
            if key in self.active_flow_stats:
                del self.active_flow_stats[key]
                
        print(f"-> Unban complete for {ip}. History cleared.")

    def _write_current_blocks(self):
        """
        Write current blocked IPs to CSV file for dashboard display.
        """
        try:
            current_ts = datetime.now().timestamp()
            
            with open(self.CURRENT_BLOCKS_FILE, "w") as f:
                f.write("IP,Time_Left,Duration,Protocol,Reason\n")
                
                for ip, data in self.blocked_ips.items():
                    time_left = max(0, int(data['unlock_time'] - current_ts))
                    duration = data.get('duration', 60)
                    proto_num = data.get('proto', 0)
                    proto_map = {0: 'MANUAL', 1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                    proto_str = proto_map.get(proto_num, str(proto_num))
                    reason = data.get('reason', 'Unknown').replace(',', ';')  # Escape commas
                    
                    f.write(f"{ip},{time_left},{duration},{proto_str},{reason}\n")
                
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        except Exception as e:
            print(f"[ERROR] Failed to write current blocks: {e}")

    def _request_stats(self, datapath):
        """
        Request flow statistics from a switch.
        
        Sends OFPFlowStatsRequest message. Switch will respond with
        OFPFlowStatsReply containing all flow entries and their counters.
        
        Args:
            datapath: Switch to request stats from
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Request stats for all flows (empty match = all flows)
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # ============================================================
    # SECTION 12: ATTACK DETECTION HELPERS
    # ============================================================

    def _get_attack_reason(self, proto, pps):
        """
        Generate human-readable attack reason based on protocol and rate.
        
        Args:
            proto: IP protocol number (1=ICMP, 6=TCP, 17=UDP)
            pps: Packets per second
            
        Returns:
            String describing the attack type
        """
        if pps < self.MIN_PPS_THRESHOLD:
            return "Normal Traffic"
        if proto == 17:
            return "UDP Volumetric Flood"
        if proto == 6:
            return "TCP SYN Flood"
        if proto == 1:
            return "ICMP Echo Flood"
        return f"High Packet Rate ({int(pps)} pps)"

    def _log_full_dataset(self, dpid, src, dst, proto, stat, pps, bps, label):
        """
        Log complete flow features to dataset file (for ML training).
        
        Args:
            dpid: Switch datapath ID
            src: Source IP
            dst: Destination IP
            proto: IP protocol number
            stat: Flow statistics object
            pps: Packets per second
            bps: Bytes per second
            label: Classification label (0=benign, 1=attack)
        """
        try:
            timestamp = datetime.now().timestamp()
            pps_nsec = pps / 1e9 if pps > 0 else 0
            bps_nsec = bps / 1e9 if bps > 0 else 0
            icmp_code = stat.match.get('icmpv4_code') or 0
            icmp_type = stat.match.get('icmpv4_type') or 0
            # Extract TCP flags from match for dataset logging
            flags = stat.match.get('tcp_flags', stat.match.get('tcp_flags_mask', 0)) or 0
            flow_id = f"{src}-{dst}-{proto}"
            
            # Build row matching dataset columns
            row = [
                timestamp, dpid, flow_id, src, 0, dst, 0, proto,
                icmp_code, icmp_type, stat.duration_sec, stat.duration_nsec,
                stat.idle_timeout, stat.hard_timeout, flags, stat.packet_count, stat.byte_count,
                f"{pps:.2f}", f"{pps_nsec:.9f}", f"{bps:.2f}", f"{bps_nsec:.9f}", label
            ]
            
            with open(self.DDOS_DATASET_FILE, "a") as f:
                f.write(",".join(map(str, row)) + "\n")
        except:
            pass

    # ============================================================
    # SECTION 13: FLOW STATISTICS HANDLER (MAIN DETECTION LOGIC)
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Process flow statistics from switch (MAIN DETECTION LOGIC).
        
        This is the core detection engine that:
        1. Calculates packet/byte rates from flow counters
        2. Applies AI model for classification
        3. Applies rule-based detection
        4. Executes blocking actions
        5. Updates dashboards and logs
        
        Args:
            ev: EventOFPFlowStatsReply containing flow statistics
            
        Flow Processing Pipeline:
            1. Skip priority 0 (table-miss) flows
            2. Handle blocked flows (priority >= 100)
            3. Calculate rates for normal flows
            4. If rate > MIN_PPS_THRESHOLD:
               a. Run AI classification
               b. Apply detection rules (whitelist, blacklist)
               c. Execute action (BLOCK, WARNING, ALLOW)
        """
        body = ev.msg.body                    # List of flow statistics
        dpid = ev.msg.datapath.id            # Switch ID
        local_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        current_time = time.time()
        
        # Debug: count high-priority (blocked) flows
        blocked_flow_count = sum(1 for stat in body if stat.priority >= 100)
        if blocked_flow_count > 0:
            self._debug_print(f"[DEBUG] Found {blocked_flow_count} blocked flows in stats reply")

        # Best real-time display candidates for this stats cycle
        best_attack_pred = None
        best_warning_pred = None
        best_normal_pred = None
        best_attack_pps = -1
        best_warning_pps = -1
        best_normal_pps = -1
        suspicious_pairs = set()

        # Process each flow entry
        for stat in body:
            try:
                # Skip table-miss entry (priority 0)
                if stat.priority == 0:
                    continue
                    
                ip_proto = stat.match.get('ip_proto', 0)

                # COUNT FLOWS BY PROTOCOL
                if ip_proto == 1:
                    local_summary['ICMP'] += 1
                elif ip_proto == 6:
                    local_summary['TCP'] += 1
                elif ip_proto == 17:
                    local_summary['UDP'] += 1
                local_summary['Total'] += 1

                # ========================================
                # CASE 1: BLOCKED FLOWS (priority >= 100)
                # ========================================
                if stat.priority >= 100:
                    src_key = stat.match.get('ipv4_src', '0.0.0.0')
                    dst_key = 'BLOCK'

                    if ip_proto == 0:
                        if src_key in self.blocked_ips:
                            ip_proto = self.blocked_ips[src_key].get('proto', 0)
                        elif src_key in self.last_blocked_proto:
                            ip_proto = self.last_blocked_proto.get(src_key, 0)

                    packet_count = stat.packet_count
                    byte_count = stat.byte_count
                    
                    # Debug: Always log blocked flow detection with all match fields
                    match_fields = {k: v for k, v in stat.match.items()}
                    self._debug_print(f"[DEBUG BLOCKED] Priority:{stat.priority} Match:{match_fields} Pkts:{packet_count} Bytes:{byte_count} Duration:{stat.duration_sec}s")

                    # Calculate blocked traffic rate
                    flow_key = (dpid, src_key, dst_key, ip_proto, stat.priority)
                    mbps_current = 0
                    pps_current = 0
                    if flow_key in self.flow_history:
                        last_pkts, last_bytes, last_ts = self.flow_history[flow_key]
                        delta_bytes = byte_count - last_bytes
                        delta_pkts = packet_count - last_pkts
                        dt = current_time - last_ts
                        if 0.1 < dt < 3.0:
                            # Only show rate if there are new bytes (attack still ongoing)
                            if delta_bytes > 0:
                                mbps_current = (delta_bytes * 8) / dt / 1000000
                                pps_current = delta_pkts / dt if delta_pkts > 0 else 0
                            else:
                                # No new bytes = attack stopped, rate = 0
                                mbps_current = 0
                                pps_current = 0
                    else:
                        # New flow after cache cleanup: do NOT infer rate from total counters.
                        # Wait for the next report to compute deltas.
                        mbps_current = 0
                        pps_current = 0
                    self.flow_history[flow_key] = (packet_count, byte_count, current_time)

                    # Determine label for dataset
                    src_ip = stat.match.get('ipv4_src')
                    current_label = '1'  # Default: attack
                    if src_ip in self.blocked_ips:
                        if self.blocked_ips[src_ip].get('reason') == "Manual-Block":
                            current_label = 'MANUALBLOCK'
                    dst_ip = stat.match.get('ipv4_dst', '0.0.0.0')
                    if not self.firewall_enabled and src_ip:
                        suspicious_pairs.add((src_ip, dst_ip))

                    # Log to dataset
                    self._log_full_dataset(dpid, src_ip, dst_ip, ip_proto, stat, 0, 0, current_label)
                    
                    # Update active flow stats for dashboard
                    flow_type = 'Blocked' if self.firewall_enabled else 'Suspicious'
                    blocked_reason = "Detected"
                    blocked_ai_conf = None
                    if src_key in self.blocked_ips:
                        blocked_reason = self.blocked_ips[src_key].get('reason', blocked_reason)
                        blocked_ai_conf = self.blocked_ips[src_key].get('ai_conf')
                    rule_verdict = "NORMAL"
                    ai_verdict = "-"
                    ai_conf = blocked_ai_conf
                    if blocked_reason.startswith("Trigger:") or blocked_reason.startswith("Policy:"):
                        rule_verdict = "BLOCK"
                    elif blocked_reason.startswith("AI Classification:"):
                        ai_verdict = "ATTACK"
                    if ai_conf is not None and ai_verdict == "-":
                        ai_verdict = "SCORE"
                    self.active_flow_stats[flow_key] = {
                        'rate': mbps_current,
                        'pps': pps_current,
                        'proto': ip_proto,
                        'type': flow_type,
                        'reason': blocked_reason,
                        'rule_verdict': rule_verdict,
                        'ai_verdict': ai_verdict,
                        'ai_conf': ai_conf,
                        'ts': current_time
                    }
                    if ip_proto != 0:
                        self.last_blocked_proto[src_key] = ip_proto
                    
                    # Debug: log blocked flow stats
                    if self.DEBUG_BLOCKED_FLOW_LOGS and mbps_current > 0.001:
                        print(f"[BLOCKED FLOW] {src_ip} -> DROP | Rate: {mbps_current:.4f} Mbps | Packets: {packet_count} | Bytes: {byte_count}")
                    continue

                # ========================================
                # CASE 2: NORMAL FLOWS (priority < 100)
                # ========================================
                src_key = stat.match.get('ipv4_src', '0.0.0.0')
                dst_key = stat.match.get('ipv4_dst', '0.0.0.0')
                packet_count = stat.packet_count
                byte_count = stat.byte_count
                flow_key = (dpid, src_key, dst_key, ip_proto, stat.priority)

                # CALCULATE RATES
                pps_rate = 0
                bps_rate = 0
                mbps_current = 0
                delta_pkts = None
                delta_bytes = None

                if flow_key in self.flow_history:
                    last_pkts, last_bytes, last_ts = self.flow_history[flow_key]
                    delta_pkts = packet_count - last_pkts
                    delta_bytes = byte_count - last_bytes
                    delta_time = current_time - last_ts

                    # Only calculate if time delta is reasonable (0.1-3 seconds)
                    if delta_time > 0.1 and delta_time < 3.0:
                        if delta_pkts > 0:  # Changed from >= 0 to > 0 to ensure rate=0 when no new packets
                            pps_rate = delta_pkts / delta_time      # Packets per second
                            bps_rate = delta_bytes / delta_time     # Bytes per second
                            mbps_current = (bps_rate * 8) / 1000000 # Convert to Mbps
                        else:
                            # No new packets = no active traffic, set rate to 0
                            mbps_current = 0
                            pps_rate = 0
                            bps_rate = 0
                else:
                    # New flow after cache cleanup: do NOT infer PPS from total counters.
                    # Wait for the next report to compute deltas.
                    mbps_current = 0
                    pps_rate = 0
                    bps_rate = 0

                # Update flow history for next calculation
                self.flow_history[flow_key] = (packet_count, byte_count, current_time)

                traffic_type = 'Benign'  # Default classification
                flow_reason = self.active_flow_stats.get(flow_key, {}).get('reason', '')
                flow_rule_verdict = self.active_flow_stats.get(flow_key, {}).get('rule_verdict', 'NORMAL')
                flow_ai_verdict = self.active_flow_stats.get(flow_key, {}).get('ai_verdict', '-')
                flow_ai_conf = self.active_flow_stats.get(flow_key, {}).get('ai_conf')

                # Skip ICMP Echo Reply (type 0) - these are responses, not attacks
                icmp_type_stat = stat.match.get('icmpv4_type')
                if ip_proto == 1 and icmp_type_stat == 0:
                    self.active_flow_stats[flow_key] = {
                        'rate': mbps_current,
                        'pps': pps_rate,
                        'proto': ip_proto,
                        'type': 'Benign',
                        'reason': '',
                        'rule_verdict': 'NORMAL',
                        'ai_verdict': '-',
                        'ai_conf': None,
                        'ts': current_time
                    }
                    continue

                # Skip flows without source IP
                if 'ipv4_src' not in stat.match:
                    self.active_flow_stats[flow_key] = {
                        'rate': mbps_current,
                        'pps': pps_rate,
                        'proto': ip_proto,
                        'type': 'Benign',
                        'reason': '',
                        'rule_verdict': 'NORMAL',
                        'ai_verdict': '-',
                        'ai_conf': None,
                        'ts': current_time
                    }
                    continue

                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                
                # Skip if source IP is currently blocked (prevents ghost traffic in dashboard)
                if ip_src in self.blocked_ips:
                    if current_time < self.blocked_ips[ip_src]['unlock_time']:
                        # Remove this flow from active stats to prevent dashboard showing blocked traffic
                        if flow_key in self.active_flow_stats:
                            del self.active_flow_stats[flow_key]
                        continue
                
                # Skip if destination is already blocked (response traffic to blocked attacker)
                if ip_dst in self.blocked_ips:
                    if current_time < self.blocked_ips[ip_dst]['unlock_time']:
                        # Remove this flow from active stats
                        if flow_key in self.active_flow_stats:
                            del self.active_flow_stats[flow_key]
                        continue

                # ========================================
                # DETECTION LOGIC (only for high-rate flows)
                # ========================================
                if pps_rate >= self.MIN_PPS_THRESHOLD:  # > 150 PPS
                    
                    # Calculate average packet size
                    avg_pkt_size = bps_rate / pps_rate if pps_rate > 0 else 0

                    # -----------------------------------------
                    # STEP 1: AI PREDICTION
                    # -----------------------------------------
                    # icmp_type = 8 if ip_proto == 1 else 0
                    # icmp_code = 0
                    icmp_type = stat.match.get('icmpv4_type', 0)
                    icmp_code = stat.match.get('icmpv4_code', 0)
                    # Extract TCP flags (if present in flow match). Fall back to 0.
                    flags = stat.match.get('tcp_flags', stat.match.get('tcp_flags_mask', 0)) or 0

                    # Build feature vector (must match training data format)
                    features = np.array([[
                        ip_proto, icmp_code, icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        0, 0,  # Reserved fields
                        flags, packet_count, byte_count,
                        pps_rate, 0, bps_rate, 0
                    ]])

                    ai_conf_score = 0.0
                    ai_verdict = "Normal"

                    if self.model:
                        try:
                            # Normalize features using trained scaler
                            features_scaled = self.scaler.transform(features)
                            # Get prediction probabilities [P(normal), P(attack)]
                            probs = self.model.predict_proba(features_scaled)[0]
                            ai_conf_score = probs[1]  # Attack probability
                            
                            if ai_conf_score >= self.AI_CONFIDENCE_THRESHOLD:
                                ai_verdict = "AI_ATTACK"
                        except:
                            pass

                    # -----------------------------------------
                    # STEP 2: DECISION RULES
                    # -----------------------------------------
                    final_action = "MONITOR"
                    reason = f"AI Classification: Benign (Confidence: {ai_conf_score:.2f})"
                    display_priority = 1

                    # Get source port for whitelist check
                    tp_src = stat.match.get('tcp_src') or stat.match.get('udp_src') or 0

                    # RULE 0: WHITELIST - Server Response Traffic
                    # Traffic from service ports (server responses) is always allowed
                    if tp_src in [80, 443, 8080]:
                        final_action = "ALLOW"
                        reason = f"Policy: Allow - Server Response (Port {tp_src})"
                        display_priority = 1
                        traffic_type = 'Benign'
                        flow_rule_verdict = "ALLOW"

                    # RULE 1: WHITELIST - Large Packets (Video/File Transfer)
                    # Large packets indicate legitimate bulk data transfer (video, files)
                    # Must be checked BEFORE volumetric to protect streaming traffic
                    elif self.ENABLE_WHITELIST_FILTER and avg_pkt_size > self.WHITELIST_PKT_SIZE:
                        final_action = "ALLOW"
                        reason = f"Policy: Whitelist - Large Packet ({int(avg_pkt_size)}B)"
                        display_priority = 1
                        traffic_type = 'Benign'
                        flow_rule_verdict = "ALLOW"

                    # RULE 2: BLOCK - Volumetric Attack (hard threshold)
                    # Only applies to small-packet floods (not video/file transfers)
                    elif self.ENABLE_VOLUMETRIC_THRESHOLD and pps_rate > self.VOLUMETRIC_THRESHOLD:
                        final_action = "BLOCK"
                        reason = f"Trigger: Rate Threshold Exceeded ({int(pps_rate)}pps, {int(avg_pkt_size)}B)"
                        display_priority = 3
                        flow_rule_verdict = "BLOCK"
                        flow_ai_conf = ai_conf_score

                    # RULE 3: BLOCK - UDP Small Packet Flood
                    # Match backup/spec: block if PPS > threshold and avg packet size < 100B
                    # This rule can be disabled via ENABLE_WHITELIST_FILTER flag
                    elif (
                        self.ENABLE_WHITELIST_FILTER
                        and ip_proto == 17
                        and pps_rate > self.UDP_FLOOD_PPS
                        and avg_pkt_size < self.UDP_FLOOD_SIZE
                    ):
                        final_action = "BLOCK"
                        reason = f"Trigger: Small UDP Flood ({int(avg_pkt_size)}B)"
                        display_priority = 3
                        flow_rule_verdict = "BLOCK"
                        flow_ai_conf = ai_conf_score

                    # RULE 4: BLOCK - TCP SYN Flood
                    elif ip_proto == 6 and pps_rate > self.SYN_FLOOD_PPS and avg_pkt_size < self.SYN_FLOOD_SIZE:
                        final_action = "BLOCK"
                        reason = f"Trigger: TCP SYN Flood ({int(avg_pkt_size)}B)"
                        display_priority = 3
                        flow_rule_verdict = "BLOCK"
                        flow_ai_conf = ai_conf_score

                    # RULE 4.5: BLOCK - ICMP Flood
                    elif ip_proto == 1 and pps_rate > self.ICMP_FLOOD_PPS:
                        final_action = "BLOCK"
                        reason = f"Trigger: ICMP Flood ({int(pps_rate)}pps)"
                        display_priority = 3
                        flow_rule_verdict = "BLOCK"
                        flow_ai_conf = ai_conf_score

                    # RULE 5: BLOCK - AI Detection
                    elif ai_verdict == "AI_ATTACK":
                        final_action = "BLOCK"
                        if ai_conf_score > self.AI_HIGH_CONFIDENCE:
                            reason = f"AI Classification: Attack (Confidence: {ai_conf_score:.2f}, High PPS)"
                        else:
                            reason = f"AI Classification: Attack (Confidence: {ai_conf_score:.2f})"
                        display_priority = 3
                        flow_ai_verdict = "ATTACK"
                        flow_ai_conf = ai_conf_score

                    # RULE 6: WARNING - Suspicious Traffic
                    elif ai_conf_score > self.AI_WARNING_THRESHOLD:
                        final_action = "WARNING"
                        reason = f"AI Classification: Suspicious (Confidence: {ai_conf_score:.2f})"
                        display_priority = 2
                        flow_ai_verdict = "WARNING"
                        flow_ai_conf = ai_conf_score

                    # Prefer AI reason when AI confidence exceeds threshold
                    if final_action == "BLOCK" and ai_conf_score >= self.AI_CONFIDENCE_THRESHOLD:
                        if ai_conf_score > self.AI_HIGH_CONFIDENCE:
                            reason = f"AI Classification: Attack (Confidence: {ai_conf_score:.2f}, High PPS)"
                        else:
                            reason = f"AI Classification: Attack (Confidence: {ai_conf_score:.2f})"
                        flow_ai_verdict = "ATTACK"
                        flow_ai_conf = ai_conf_score

                    # -----------------------------------------
                    # STEP 3: EXECUTE ACTION
                    # -----------------------------------------
                    if final_action == "BLOCK":
                        if self.firewall_enabled:
                            traffic_type = 'Blocked'
                            # Install blocking flow and log attack
                            self._block_ip(ev.msg.datapath, ip_src, ip_dst, ip_proto, reason=reason, ai_conf=flow_ai_conf)
                            self._log_attack(ip_src, ip_dst, ip_proto, packet_count,
                                           label="Attack", reason=reason)
                        else:
                            # Firewall off: detect only, don't block
                            traffic_type = 'Suspicious'
                            suspicious_pairs.add((ip_src, ip_dst))
                            self._log_attack(ip_src, ip_dst, ip_proto, packet_count,
                                           label="Passive Detect", reason=f"[FW-OFF] {reason}")

                    elif final_action == "WARNING":
                        log_label = "Warning" if self.firewall_enabled else "Passive Warning"
                        self._log_attack(ip_src, ip_dst, ip_proto, packet_count,
                                       label=log_label, reason=reason)
                        # Display warning traffic as orange (same as Suspicious)
                        traffic_type = 'Suspicious'

                    # Reclassify reverse traffic during suspicious detection (FW OFF)
                    if not self.firewall_enabled and traffic_type == 'Benign':
                        if (ip_dst, ip_src) in suspicious_pairs:
                            traffic_type = 'Suspicious'

                    if traffic_type in ['Blocked', 'Suspicious']:
                        flow_reason = reason
                    else:
                        flow_reason = ''

                    # -----------------------------------------
                    # STEP 4: SELECT CLI DISPLAY CANDIDATE
                    # -----------------------------------------
                    # If traffic is already listed in CURRENTLY BLOCKED,
                    # don't show it again in REAL-TIME INSPECTION.
                    should_show = True
                    if final_action == "BLOCK" and self.firewall_enabled:
                        should_show = False

                    if should_show:
                        # Map action to display result
                        result_str = "NORMAL"
                        if final_action == "BLOCK":
                            result_str = "ATTACK"
                            if not self.firewall_enabled:
                                result_str = "SUSPICIOUS"
                        elif final_action == "WARNING":
                            result_str = "WARNING"
                        elif final_action == "ALLOW":
                            result_str = "NORMAL"

                        candidate = {
                            'src': ip_src,
                            'dst': ip_dst,
                            'proto': ip_proto,
                            'rate': f"{pps_rate:.0f}",
                            'result': result_str,
                            'conf': f"{ai_conf_score:.2f}",
                            'reason': reason,
                            'priority': display_priority
                        }

                        if display_priority == 3:
                            if pps_rate > best_attack_pps:
                                best_attack_pps = pps_rate
                                best_attack_pred = candidate
                        elif display_priority == 2:
                            if pps_rate > best_warning_pps:
                                best_warning_pps = pps_rate
                                best_warning_pred = candidate
                        else:
                            if pps_rate > best_normal_pps:
                                best_normal_pps = pps_rate
                                best_normal_pred = candidate

                # Update active flow stats - allow decay to 0 to avoid ghost traffic
                existing = self.active_flow_stats.get(flow_key, {})
                existing_rate = existing.get('rate', 0)
                existing_ts = existing.get('ts', 0)
                
                # Update if: new rate is higher, OR entry is stale (>1s old), OR no existing entry,
                # OR no new packets but previous rate was > 0 (decay to 0)
                should_update = (
                    mbps_current >= existing_rate
                    or (current_time - existing_ts) > 1.0
                    or flow_key not in self.active_flow_stats
                )
                if not should_update and mbps_current == 0 and existing_rate > 0:
                    if delta_pkts is None or delta_pkts <= 0:
                        should_update = True

                if should_update:
                    self.active_flow_stats[flow_key] = {
                        'rate': mbps_current,
                        'pps': pps_rate,
                        'proto': ip_proto,
                        'type': traffic_type,
                        'reason': flow_reason,
                        'rule_verdict': flow_rule_verdict,
                        'ai_verdict': flow_ai_verdict,
                        'ai_conf': flow_ai_conf,
                        'ts': current_time
                    }
                
                # Debug: log high-rate benign flows AND verify storage
                if traffic_type == 'Benign' and mbps_current > 0.01:
                    stored = self.active_flow_stats.get(flow_key, {})
                    self._debug_print(f"[DEBUG BENIGN] {src_key} -> {dst_key} | Rate: {mbps_current:.4f} Mbps | Stored: {stored.get('rate', 'N/A')} | Key: {flow_key}")

            except Exception as e:
                # Catch any errors to prevent crash
                continue

        # UPDATE CLI DASHBOARD (attack first; warning/normal alternate)
        chosen_pred = None
        chosen_priority = -1

        if best_attack_pred:
            chosen_pred = best_attack_pred
            chosen_priority = 3
        elif best_warning_pred and best_normal_pred:
            # Alternate warning/normal when both present
            now_ts = time.time()
            should_rotate = (now_ts - self.last_low_rotate_ts) >= self.LOW_PRIORITY_ROTATE_SECONDS
            if should_rotate:
                # Flip when interval elapsed
                if self.last_low_priority == "WARNING":
                    chosen_pred = best_normal_pred
                    chosen_priority = 1
                    self.last_low_priority = "NORMAL"
                else:
                    chosen_pred = best_warning_pred
                    chosen_priority = 2
                    self.last_low_priority = "WARNING"
                self.last_low_rotate_ts = now_ts
            else:
                # Keep current low-priority type until interval passes
                if self.last_low_priority == "WARNING":
                    chosen_pred = best_warning_pred
                    chosen_priority = 2
                else:
                    chosen_pred = best_normal_pred
                    chosen_priority = 1
        elif best_warning_pred:
            chosen_pred = best_warning_pred
            chosen_priority = 2
            self.last_low_priority = "WARNING"
            self.last_low_rotate_ts = time.time()
        elif best_normal_pred:
            chosen_pred = best_normal_pred
            chosen_priority = 1
            self.last_low_priority = "NORMAL"
            self.last_low_rotate_ts = time.time()

        if chosen_pred:
            self.latest_pred = chosen_pred
            if chosen_priority == 3:
                lock_duration = self.PRED_LOCK_SECONDS
            else:
                lock_duration = self.LOW_PRIORITY_ROTATE_SECONDS
            self.pred_lock_until = time.time() + lock_duration
            self.pred_lock_priority = chosen_priority
        else:
            # Fix stale traffic
            # No attack/warning/normal candidate in this cycle
            # Keep last displayed traffic as requested.
            self.latest_pred = {
                'src': '-', 'dst': '-', 'proto': '-', 
                'rate': 0, 'result': 'IDLE', 'conf': '-', 'reason': '-',
                'priority': -1
            }
            # Fix stale traffic
            self.pred_lock_priority = -1

        # UPDATE AGGREGATED STATISTICS
        self.switch_stats[dpid] = local_summary
        
        # Sum stats from all switches
        total = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        for stats in self.switch_stats.values():
            total['TCP'] += stats.get('TCP', 0)
            total['UDP'] += stats.get('UDP', 0)
            total['ICMP'] += stats.get('ICMP', 0)
            total['Total'] += stats.get('Total', 0)
        self.traffic_summary = total

    # ============================================================
    # SECTION 14: LOGGING METHODS
    # ============================================================

    def _log_ai_prediction(self, src, dst, proto, pps, probs, verdict, action, reason):
        """
        Log AI prediction details to CSV file.
        
        Args:
            src: Source IP
            dst: Destination IP
            proto: Protocol number
            pps: Packets per second
            probs: Probability array [P(normal), P(attack)]
            verdict: AI verdict string
            action: Action taken
            reason: Reason string
        """
        if not self.ENABLE_AI_PREDICT_LOG:
            return
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            prob_normal = f"{probs[0]:.2f}"
            prob_attack = f"{probs[1]:.2f}"
            line = f"{timestamp},{src},{dst},{proto},{pps:.0f},{prob_normal},{prob_attack},{verdict},{action},{reason}\n"
            with open(self.AI_PREDICT_LOG_FILE, "a") as f:
                f.write(line)
        except:
            pass

    def _log_attack(self, src, dst, proto, pkts, label="Attack", reason="Unknown"):
        """
        Log detected attack to attack_logs.csv.
        
        Args:
            src: Source IP (attacker)
            dst: Destination IP (victim)
            proto: Protocol number
            pkts: Packet count
            label: Classification label (Attack, Warning, etc.)
            reason: Detection reason
        """
        try:
            log_df = pd.DataFrame([{
                'timestamp': datetime.now().timestamp(),
                'ip_src': src,
                'ip_dst': dst,
                'ip_proto': proto,
                'packet_count': pkts,
                'label': label,
                'reason': reason
            }])
            
            # Write header only if file doesn't exist
            header = not os.path.exists(self.ATTACK_LOG_FILE)
            log_df.to_csv(self.ATTACK_LOG_FILE, mode='a', header=header, index=False)
            os.chmod(self.ATTACK_LOG_FILE, 0o666)
        except:
            pass

    # ============================================================
    # SECTION 15: OFFENDER HISTORY MANAGEMENT
    # ============================================================

    def _update_offender_history(self, ip_src, proto):
        """
        Update offender history when an IP is blocked.
        
        Tracks:
            - Total block count per IP
            - Attack methods used (TCP, UDP, ICMP)
            - Last seen timestamp
            
        Saves to CSV file for persistence across restarts.
        
        Args:
            ip_src: Blocked IP address
            proto: Protocol number used in attack
        """
        # Map protocol number to name
        proto_map = {0: 'MANUAL', 1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        proto_name = proto_map.get(proto, 'UNK')
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Initialize entry if new offender
        if ip_src not in self.offender_history:
            self.offender_history[ip_src] = {
                'count': 0,
                'methods': set(),
                'last': timestamp
            }
        
        # Update offender record
        self.offender_history[ip_src]['count'] += 1
        self.offender_history[ip_src]['methods'].add(proto_name)
        self.offender_history[ip_src]['last'] = timestamp
        
        # Save to CSV file
        try:
            data_list = []
            for ip, info in self.offender_history.items():
                methods_str = "+".join(list(info['methods']))
                data_list.append({
                    'Attacker_IP': ip,
                    'Total_Blocks': info['count'],
                    'Attack_Methods': methods_str,
                    'Last_Seen': info['last']
                })
            df = pd.DataFrame(data_list)
            df.to_csv(self.HISTORY_FILE, index=False)
            os.chmod(self.HISTORY_FILE, 0o666)
        except:
            pass

    # ============================================================
    # SECTION 16: IP BLOCKING IMPLEMENTATION
    # ============================================================

    def _block_ip(self, datapath, ip_src, ip_dst, proto, reason="Unknown", ai_conf=None):
        """
        Block an IP address by installing a DROP flow rule.
        
        Implements escalating ban durations:
            - 1st offense: 30 seconds
            - 2nd offense: 60 seconds
            - 3rd+ offense: 120 seconds
            
        Args:
            datapath: Switch to install rule on
            ip_src: IP address to block
            ip_dst: Victim IP (for logging)
            proto: Protocol number
            reason: Reason for blocking
        """
        current_time = datetime.now().timestamp()

        # Respect manual unblock grace period
        if ip_src in self.manual_allow and current_time < self.manual_allow[ip_src]:
            return
        
        # Check if IP is already blocked and not expired
        if ip_src in self.blocked_ips:
            if current_time < self.blocked_ips[ip_src]['unlock_time']:
                return  # Still blocked, no action needed

        # CLEANUP OLD FLOW DATA (prevents ghost traffic in stats)
        # Only remove BENIGN flows (not blocked flows) from active_flow_stats
        # Keep flow_history for blocked flow rate calculation
        keys_to_remove_active = [k for k in self.active_flow_stats 
                                  if k[1] == ip_src and self.active_flow_stats[k].get('type') != 'Blocked']
        for k in keys_to_remove_active:
            del self.active_flow_stats[k]
        
        # Remove response traffic to blocked IP (destination)
        keys_to_remove_active_dst = [k for k in self.active_flow_stats 
                                      if len(k) > 2 and k[2] == ip_src and self.active_flow_stats[k].get('type') != 'Blocked']
        for k in keys_to_remove_active_dst:
            del self.active_flow_stats[k]

        # UPDATE OFFENDER HISTORY
        self._update_offender_history(ip_src, proto)
        
        # CALCULATE BAN DURATION (escalating)
        offense_count = self.offender_history[ip_src]['count']
        if offense_count == 1:
            duration = 30
        elif offense_count == 2:
            duration = 60
        else:
            duration = 120
            
        # RECORD BLOCKED IP
        self.blocked_ips[ip_src] = {
            'unlock_time': current_time + duration,
            'victim': ip_dst,
            'proto': proto,
            'duration': duration,
            'reason': reason,
            'ai_conf': ai_conf
        }
        self.last_blocked_proto[ip_src] = proto
        
        # INSTALL BLOCKING FLOW RULE
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match all packets from this source IP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        
        # First, DELETE any existing flows from this IP
        mod_del = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod_del)
        
        # Barrier to ensure delete completes before add
        datapath.send_msg(parser.OFPBarrierRequest(datapath))
        
        # ADD blocking flow with CLEAR_ACTIONS (drops packet)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        mod_add = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,              # High priority to override other flows
            match=match,
            instructions=inst,          # Empty actions = DROP
            idle_timeout=duration,      # Auto-remove after inactivity
            hard_timeout=duration       # Auto-remove after duration
        )
        datapath.send_msg(mod_add)

    def _write_debug_log(self, src, dst, proto, rate, reason, result, action):
        """
        Write debug information to log file.
        
        Args:
            src: Source IP
            dst: Destination IP
            proto: Protocol
            rate: Packet rate
            reason: Detection reason
            result: Detection result
            action: Action taken
        """
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            line = f"{timestamp},{src},{dst},{proto},{rate:.0f},{reason},{result},{action}\n"
            with open(self.DEBUG_FILE, "a") as f:
                f.write(line)
        except:
            pass

    # ============================================================
    # SECTION 17: CLI DASHBOARD
    # ============================================================

    def _print_dashboard(self):
        """
        Print real-time monitoring dashboard to terminal.
        
        Displays:
            - System status (firewall state, flow counts)
            - Real-time traffic monitor (top flows)
            - Currently blocked IPs
            - Top offenders history
            
        Uses ANSI escape codes for colors:
            - Green (92m): Normal/safe
            - Yellow (93m): Warning
            - Red (91m): Attack/block
        """
        # Clear screen and move cursor to top-left
        sys.stdout.write("\033[H\033[J")
        
        now = datetime.now().strftime('%H:%M:%S')
        W = 125      # Total width
        IW = W - 4   # Inner width (minus borders)

        # Helper function: horizontal line
        def h_line(char='═'):
            print(f"╠{char*(W-2)}╣")

        # Helper function: print padded line
        def p_line(text):
            # Adjust for emoji width
            visual_offset = 1 if "🚫" in text else 0
            padding_len = IW - len(text) - visual_offset
            if padding_len < 0:
                padding_len = 0
            print(f"║ {text}{' ' * padding_len} ║")

        # Helper function: print colored alert line
        def p_alert_line(label, info_text, color_code):
            raw_text = f"[{label}] {info_text}"
            padding = IW - len(raw_text)
            if padding < 0:
                padding = 0
            print(f"║ {color_code}[{label}]\033[0m {info_text}{' ' * padding} ║")

        # === HEADER ===
        print(f"╔{'═'*(W-2)}╗")
        fw_status = "ON" if self.firewall_enabled else "OFF"
        title = "SDN AI-GUARD by Group 01"
        time_str = f"Time: {now}"
        gap = IW - len(title) - len(time_str)
        if gap < 0:
            gap = 1
        print(f"║ {title}{' '*gap}{time_str} ║")
        h_line()

        # === CONFIG STATUS ===
        p_line("CONFIG STATUS")
        thresholds_msg = (
            f"> FIREWALL: {fw_status} | "
            f"MIN_PPS_THRESHOLD: {self.MIN_PPS_THRESHOLD} | "
            f"VOLUMETRIC_THRESHOLD: {self.VOLUMETRIC_THRESHOLD} | "
            f"ENABLE_VOLUMETRIC_THRESHOLD: {self.ENABLE_VOLUMETRIC_THRESHOLD}"
        )
        p_line(thresholds_msg)
        whitelist_msg = f"> ENABLE_WHITELIST_FILTER: {self.ENABLE_WHITELIST_FILTER}"
        p_line(whitelist_msg)
        h_line()

        # === SYSTEM STATUS ===
        p_line("SYSTEM STATUS")
        stats_msg = f"> Flow Inventory: {self.traffic_summary['Total']} (ICMP:{self.traffic_summary['ICMP']} TCP:{self.traffic_summary['TCP']} UDP:{self.traffic_summary['UDP']})"
        p_line(stats_msg)
        h_line()

        # === FIREWALL WARNING (if disabled) ===
        if not self.firewall_enabled:
            p_alert_line("MODE", "Firewall Disabled - Monitoring Only", "\033[93m")
            h_line()

        # === REAL-TIME TRAFFIC MONITOR (Top 5 Flows) ===
        p_line("REAL-TIME TRAFFIC MONITOR (Top 5 Flows)")
        col_time_w = 8
        col_ip_w = 12
        col_proto_w = 9
        col_pps_w = 6
        col_rate_w = 10
        fixed_len = (
            1 + 10 + 2 + 1 +  # [TYPE] and space
            col_time_w + 1 +
            col_ip_w + 4 + col_ip_w + 3 +
            col_proto_w + 3 +
            col_pps_w + 3 +
            col_rate_w + 3 +
            len("Reason")
        )
        reason_w = max(10, IW - fixed_len)
        header = (
            f"[{('TYPE').ljust(10)}] {('Time').ljust(col_time_w)} {('Source').ljust(col_ip_w)} -> {('Dest').ljust(col_ip_w)} | "
            f"{('Protocol').ljust(col_proto_w)} | {('PPS').rjust(col_pps_w)} | {('Rate(Mbps)').rjust(col_rate_w)} | {('Reason').ljust(reason_w)}"
        )
        p_line(header)
        p_line("-" * (IW-2))
        now_ts = time.time()
        flow_rows = []
        for key, info in self.active_flow_stats.items():
            rate = info.get('rate', 0)
            pps_val = info.get('pps', 0)
            if pps_val <= 0:
                continue
            info_type = info.get('type', 'Benign')
            stale_limit = 15.0 if info_type == 'Blocked' else 1.5
            if now_ts - info.get('ts', 0) > stale_limit:
                continue
            src = key[1] if len(key) > 1 else '-'
            dst = key[2] if len(key) > 2 else '-'
            proto = info.get('proto', key[3] if len(key) > 3 else 0)
            flow_rows.append({
                'src': src,
                'dst': dst,
                'proto': proto,
                'rate': rate,
                'pps': pps_val,
                'type': info.get('type', 'Benign'),
                'reason': info.get('reason', ''),
                'rule_verdict': info.get('rule_verdict', 'NORMAL'),
                'ai_verdict': info.get('ai_verdict', '-'),
                'ai_conf': info.get('ai_conf'),
                'ts': info.get('ts', now_ts)
            })

        type_priority = {'Blocked': 2, 'Suspicious': 1, 'Benign': 0}
        flow_rows.sort(
            key=lambda x: (-type_priority.get(x['type'], 0), -x['rate'])
        )
        top_flows = flow_rows[:5]
        if top_flows:
            self.last_monitor_flows = top_flows
            self.last_monitor_update = now_ts

        proto_map = {0: 'MANUAL', 1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        type_color = {
            'Blocked': "\033[91m",
            'Suspicious': "\033[93m",
            'Benign': "\033[92m",
        }
        type_label = {
            'Blocked': "BLOCKED",
            'Suspicious': "SUSPICIOUS",
            'Benign': "BENIGN",
        }

        display_flows = top_flows if top_flows else self.last_monitor_flows
        monitor_lines = []

        if not display_flows:
            monitor_lines.append({'type': 'line', 'text': "[IDLE] Status: Awaiting traffic..."})
        else:
            for flow in display_flows:
                proto_num = int(flow['proto']) if str(flow['proto']).isdigit() else flow['proto']
                proto_name = proto_map.get(proto_num, 'UNK')
                proto_name = f"{proto_name} ({proto_num})"
                ts_str = datetime.fromtimestamp(flow.get('ts', now_ts)).strftime('%H:%M:%S')
                pps_str = f"{flow['pps']:.0f}"
                rate_str = f"{flow['rate']:.3f}"
                base_info = (
                    f"{ts_str.ljust(col_time_w)} {str(flow['src']).ljust(col_ip_w)} -> {str(flow['dst']).ljust(col_ip_w)} | "
                    f"{proto_name.ljust(col_proto_w)} | {pps_str.rjust(col_pps_w)} | {rate_str.rjust(col_rate_w)}"
                )
                label = type_label.get(flow['type'], "BENIGN").ljust(10)
                color = type_color.get(flow['type'], "\033[92m")
                reason_text = flow.get('reason', '') or 'N/A'
                if flow['type'] in ['Blocked', 'Suspicious']:
                    ai_conf = flow.get('ai_conf')
                    if flow['type'] == 'Blocked':
                        ai_score = f"{ai_conf:.2f}" if isinstance(ai_conf, (int, float)) else "-"
                        reason_text = f"R:{reason_text} | AI:{ai_score}"
                reason_chunks = textwrap.wrap(
                    reason_text,
                    width=reason_w,
                    break_long_words=False,
                    break_on_hyphens=False
                ) or [""]
                info = f"{base_info} | {reason_chunks[0].ljust(reason_w)}"

                monitor_lines.append({'type': 'alert', 'label': label, 'info': info, 'color': color})
                if len(reason_chunks) > 1:
                    cont_prefix = " " * len(base_info) + " | "
                    for chunk in reason_chunks[1:]:
                        monitor_lines.append({
                            'type': 'line',
                            'text': f"{cont_prefix}{chunk.ljust(reason_w)}"
                        })

        # Render exactly 10 lines to avoid box jumping
        MAX_MONITOR_LINES = 10
        lines_rendered = 0
        for item in monitor_lines:
            if lines_rendered >= MAX_MONITOR_LINES:
                break
            if item['type'] == 'alert':
                p_alert_line(item['label'], item['info'], item['color'])
            else:
                p_line(item['text'])
            lines_rendered += 1

        while lines_rendered < MAX_MONITOR_LINES:
            p_line("")
            lines_rendered += 1

        h_line()

        # === CURRENTLY BLOCKED IPs ===
        if self.firewall_enabled:
            p_line("ACTIVE BLOCKS (Mitigation Enabled)")
            if not self.blocked_ips:
                p_line("[ No active blocks ]")
            else:
                current_ts = datetime.now().timestamp()
                count = 0
                header = f"   {'IP Address':<15} | {'Time Left':<9} | {'Protocol':<8} | {'Trigger'}"
                p_line(header)
                p_line("-" * (IW-2))
                
                for ip, data in self.blocked_ips.items():
                    if count >= 5:
                        p_line(f"... (+{len(self.blocked_ips)-5} others)")
                        break
                        
                    rem = int(data['unlock_time'] - current_ts)
                    duration = data.get('duration', 60)
                    reason = data.get('reason', 'Unknown')
                    proto_num = data.get('proto', 0)
                    proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 0: 'ALL'}
                    proto_str = proto_map.get(proto_num, str(proto_num))
                    
                    # Truncate long reasons
                    if len(reason) > 50:
                        reason = reason[:47] + "..."
                        
                    if rem > 0:
                        time_display = f"{rem}s/{duration}s"
                        row = f"🚫 {ip:<15} | {time_display:<9} | {proto_str:<8} | {reason}"
                        p_line(row)
                        count += 1
            h_line()

        # === TOP OFFENDERS HISTORY ===
        p_line("TOP OFFENDERS (History)")
        if not self.offender_history:
            p_line("[ No history yet ]")
        else:
            p_line(f"{'No.':<4}{'IP Address':<18}{'Blocks':<10}{'Methods':<15}{'Last Seen':<12}")
            p_line("-" * (IW-2))
            
            # Sort by block count (descending)
            sorted_hist = sorted(
                self.offender_history.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )
            
            # Show top 5
            for i, (ip, info) in enumerate(sorted_hist[:5]):
                m = "+".join(list(info['methods']))
                last = info.get('last', '-')
                row = f"{i+1:<4}{ip:<18}{info['count']:<10}{m:<15}{last:<12}"
                p_line(row)
                
        # === FOOTER ===
        print(f"╚{'═'*(W-2)}╝")