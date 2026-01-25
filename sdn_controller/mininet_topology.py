"""
SDN Mininet Topology Module
============================
This module creates a Software-Defined Network topology using Mininet.
It sets up 6 switches in a linear topology with 18 hosts (3 hosts per switch).
The network uses OpenFlow 1.3 protocol and connects to a remote Ryu controller.

Topology Structure:
    [s1] ── h1, h2, h3
    [s2] ── h4, h5, h6
    [s3] ── h7, h8, h9
    [s4] ── h10, h11, h12
    [s5] ── h13, h14, h15
    [s6] ── h16, h17, h18
    
    Switch Links: s1──s2──s3──s4──s5──s6

Author: SDN DDoS Detection Project
"""

# --- IMPORT LIBRARIES ---
from mininet.topo import Topo              # Base class for creating custom topologies
from mininet.net import Mininet            # Main Mininet network emulator class
from mininet.link import TCLink            # Traffic Control Link - allows bandwidth/delay configuration
from mininet.log import setLogLevel        # Controls logging verbosity (debug, info, warning, error)
from mininet.cli import CLI                # Command Line Interface for interacting with the network
from mininet.node import OVSKernelSwitch   # Open vSwitch kernel-mode switch implementation
from mininet.node import RemoteController  # Connects to external SDN controller (e.g., Ryu, ONOS)
from mininet.clean import cleanup          # Cleans up leftover Mininet processes and network namespaces


class MyTopo(Topo):
    """
    Custom Topology Class
    ---------------------
    Inherits from Mininet's Topo base class.
    Defines a linear topology with 6 switches and 18 hosts.
    Each switch connects to 3 hosts and adjacent switches form a chain.
    
    Attributes:
        Inherited from Topo: nodes, links, ports, etc.
    """
    
    def build(self):
        """
        Build the network topology.
        This method is called automatically when MyTopo() is instantiated.
        It creates all switches, hosts, and links in the network.
        
        Returns:
            None - Topology is built in-place
        """
        
        # ==========================================
        # SECTION 1: CREATE SWITCHES
        # ==========================================
        # OpenFlow13 protocol is REQUIRED for Ryu controller compatibility.
        # OVSKernelSwitch runs in Linux kernel space for better performance.
        # Each switch is assigned a unique name (s1, s2, ..., s6).
        
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        # addSwitch() params:
        #   - 's1': Switch name/identifier (also determines DPID)
        #   - cls: Switch class to instantiate (OVSKernelSwitch for kernel-mode OVS)
        #   - protocols: OpenFlow version(s) to support ('OpenFlow13' = OF 1.3)
        
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s5 = self.addSwitch('s5', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s6 = self.addSwitch('s6', cls=OVSKernelSwitch, protocols='OpenFlow13')

        # ==========================================
        # SECTION 2: CREATE HOSTS
        # ==========================================
        # Each host is configured with:
        #   - cpu: CPU bandwidth limit (0.05 = 5% of host CPU to prevent system overload)
        #   - mac: Static MAC address (using real vendor OUIs for realism)
        #   - ip: Static IP address in 10.0.0.0/24 subnet
        
        # --- Switch s1 Hosts (h1, h2, h3) ---
        h1 = self.addHost('h1', cpu=0.05, mac="3c:52:82:a1:7b:04", ip="10.0.0.1/24")
        # addHost() params:
        #   - 'h1': Host name/identifier
        #   - cpu: Fraction of CPU allocated (prevents flood attacks from freezing system)
        #   - mac: 48-bit MAC address (3c:52:82 = Dell OUI)
        #   - ip: IPv4 address with CIDR notation (/24 = 255.255.255.0 subnet)
        
        h2 = self.addHost('h2', cpu=0.05, mac="00:1a:2b:3c:4d:5e", ip="10.0.0.2/24")   # Ayecom OUI
        h3 = self.addHost('h3', cpu=0.05, mac="f4:8e:38:9d:2c:11", ip="10.0.0.3/24")   # Apple OUI

        # --- Switch s2 Hosts (h4, h5, h6) ---
        h4 = self.addHost('h4', cpu=0.05, mac="50:eb:f6:c8:a3:72", ip="10.0.0.4/24")   # ASUSTek OUI
        h5 = self.addHost('h5', cpu=0.05, mac="d4:3d:7e:b5:91:f8", ip="10.0.0.5/24")   # Micro-Star OUI
        h6 = self.addHost('h6', cpu=0.05, mac="88:d7:f6:42:1e:c9", ip="10.0.0.6/24")   # ASUSTek OUI

        # --- Switch s3 Hosts (h7, h8, h9) ---
        h7 = self.addHost('h7', cpu=0.05, mac="a4:c3:f0:73:dc:85", ip="10.0.0.7/24")   # Intel OUI
        h8 = self.addHost('h8', cpu=0.05, mac="00:25:90:e4:5a:3f", ip="10.0.0.8/24")   # Super Micro OUI
        h9 = self.addHost('h9', cpu=0.05, mac="ec:f4:bb:d6:17:ae", ip="10.0.0.9/24")   # Dell OUI

        # --- Switch s4 Hosts (h10, h11, h12) ---
        h10 = self.addHost('h10', cpu=0.05, mac="2c:4d:54:f9:28:b6", ip="10.0.0.10/24")  # ASUSTek OUI
        h11 = self.addHost('h11', cpu=0.05, mac="78:2b:cb:a7:e3:94", ip="10.0.0.11/24")  # Dell OUI
        h12 = self.addHost('h12', cpu=0.05, mac="b4:2e:99:51:d4:0c", ip="10.0.0.12/24")  # Giga-Byte OUI

        # --- Switch s5 Hosts (h13, h14, h15) ---
        h13 = self.addHost('h13', cpu=0.05, mac="00:50:56:8f:1c:7a", ip="10.0.0.13/24")  # VMware OUI
        h14 = self.addHost('h14', cpu=0.05, mac="ac:1f:6b:2e:86:d3", ip="10.0.0.14/24")  # Super Micro OUI
        h15 = self.addHost('h15', cpu=0.05, mac="1c:69:7a:63:f5:21", ip="10.0.0.15/24")  # EliteGroup OUI

        # --- Switch s6 Hosts (h16, h17, h18) ---
        h16 = self.addHost('h16', cpu=0.05, mac="70:85:c2:ba:49:e7", ip="10.0.0.16/24")  # ASRock OUI
        h17 = self.addHost('h17', cpu=0.05, mac="54:bf:64:c0:8d:52", ip="10.0.0.17/24")  # Dell OUI
        h18 = self.addHost('h18', cpu=0.05, mac="e8:40:f2:19:ac:6b", ip="10.0.0.18/24")  # Pegatron OUI

        # ==========================================
        # SECTION 3: CREATE LINKS
        # ==========================================
        # Links connect hosts to switches and switches to each other.
        # addLink() creates a bidirectional virtual Ethernet connection.
        
        # --- Host-to-Switch Links ---
        # Connect each group of 3 hosts to their respective switch
        self.addLink(h1, s1); self.addLink(h2, s1); self.addLink(h3, s1)   # s1: h1, h2, h3
        self.addLink(h4, s2); self.addLink(h5, s2); self.addLink(h6, s2)   # s2: h4, h5, h6
        self.addLink(h7, s3); self.addLink(h8, s3); self.addLink(h9, s3)   # s3: h7, h8, h9
        self.addLink(h10, s4); self.addLink(h11, s4); self.addLink(h12, s4)  # s4: h10, h11, h12
        self.addLink(h13, s5); self.addLink(h14, s5); self.addLink(h15, s5)  # s5: h13, h14, h15
        self.addLink(h16, s6); self.addLink(h17, s6); self.addLink(h18, s6)  # s6: h16, h17, h18

        # --- Switch-to-Switch Links (Linear Topology) ---
        # Creates a chain: s1 <-> s2 <-> s3 <-> s4 <-> s5 <-> s6
        # This linear topology means traffic between distant hosts traverses multiple switches.
        self.addLink(s1, s2)  # Link between switch 1 and switch 2
        self.addLink(s2, s3)  # Link between switch 2 and switch 3
        self.addLink(s3, s4)  # Link between switch 3 and switch 4
        self.addLink(s4, s5)  # Link between switch 4 and switch 5
        self.addLink(s5, s6)  # Link between switch 5 and switch 6


def startNetwork():
    """
    Initialize and start the Mininet network.
    
    This function:
    1. Cleans up any leftover Mininet processes
    2. Creates the topology
    3. Connects to the remote SDN controller
    4. Starts the network
    5. Displays network information
    6. Launches the CLI for user interaction
    7. Cleanly stops the network on exit
    
    Returns:
        None
    
    Raises:
        Exception: If network initialization or startup fails
    """
    
    # --- STEP 1: CLEANUP PREVIOUS SESSION ---
    # Equivalent to running 'sudo mn -c' in terminal.
    # Removes leftover network namespaces, virtual interfaces, and processes
    # from crashed or improperly terminated Mininet sessions.
    print("--- Cleaning up previous session (sudo mn -c) ---")
    cleanup()

    # --- STEP 2: INSTANTIATE TOPOLOGY ---
    # Creates MyTopo object which internally calls build() method.
    # After this, topo contains all switch, host, and link definitions.
    topo = MyTopo()
    
    # --- STEP 3: CONFIGURE REMOTE CONTROLLER ---
    # RemoteController connects Mininet switches to an external SDN controller.
    # The controller (Ryu) must be running and listening on this IP:port.
    # Port 6633 is the standard OpenFlow control channel port.
    c0 = RemoteController(
        'c0',              # Controller name/identifier
        ip='127.0.0.1',    # Controller IP (localhost - same machine)
        port=6633          # OpenFlow control port (default: 6633 or 6653)
    )
    
    # --- STEP 4: CREATE MININET NETWORK ---
    # Mininet() instantiates the network with specified components.
    net = Mininet(
        topo=topo,                    # Topology definition (MyTopo instance)
        link=TCLink,                  # Link type with traffic control support
        controller=c0,                # Remote controller instance
        switch=OVSKernelSwitch        # Default switch type for the network
    )
    
    # --- STEP 5: START NETWORK AND HANDLE LIFECYCLE ---
    try:
        # net.start() performs:
        #   1. Creates network namespaces for hosts
        #   2. Creates virtual ethernet pairs for links
        #   3. Starts OVS switches and connects them to controller
        #   4. Configures host IP addresses
        net.start()
        
        # ==========================================
        # SECTION: DISPLAY NETWORK INFORMATION
        # ==========================================
        # Formatted output showing topology structure and host details
        
        W = 70  # Display width in characters
        
        print()
        print("=" * W)
        print("  SDN MININET TOPOLOGY - OpenFlow 1.3  ".center(W))
        print("=" * W)
        
        # --- Display Controller Information ---
        # c0.name: Controller identifier
        # c0.ip: Controller IP address
        # c0.port: OpenFlow control port
        print(f"│ Controller: {c0.name:<10} IP: {c0.ip:<15} Port: {c0.port:<6} │")
        print("-" * W)
        
        # --- Display Switch List ---
        # net.switches: List of all switch objects in the network
        # s.name: Name of each switch (s1, s2, etc.)
        print(f"│ Switches ({len(net.switches)}): {', '.join([s.name for s in net.switches]):<50} │")
        print("-" * W)
        
        # --- Display Topology Structure ---
        print("│ TOPOLOGY STRUCTURE:".ljust(W-1) + "│")
        print("│" + " " * (W-2) + "│")
        
        # Build switch-to-hosts mapping by iterating through all links
        # net.links: List of all Link objects in the network
        # link.intf1.node: First node connected to the link
        # link.intf2.node: Second node connected to the link
        switch_hosts = {}  # Dictionary: {switch_name: [host_names]}
        for link in net.links:
            n1, n2 = link.intf1.node.name, link.intf2.node.name
            # Check if link is host-to-switch (not switch-to-switch)
            if n1.startswith('h') and n2.startswith('s'):
                switch_hosts.setdefault(n2, []).append(n1)
            elif n2.startswith('h') and n1.startswith('s'):
                switch_hosts.setdefault(n1, []).append(n2)
        
        # Print each switch with its connected hosts
        for sw in sorted(switch_hosts.keys(), key=lambda x: int(x[1:])):
            hosts = sorted(switch_hosts[sw], key=lambda x: int(x[1:]))
            hosts_str = ", ".join(hosts)
            line = f"│   [{sw}] ── {hosts_str}"
            print(line.ljust(W-1) + "│")
        
        print("│" + " " * (W-2) + "│")
        print("│   Switch Links: s1──s2──s3──s4──s5──s6".ljust(W-1) + "│")
        print("-" * W)
        
        # --- Display Host Details Table ---
        # net.hosts: List of all host objects in the network
        # h.name: Host identifier (h1, h2, etc.)
        # h.IP(): Returns host's IP address
        # h.MAC(): Returns host's MAC address
        print("│ HOST DETAILS:".ljust(W-1) + "│")
        print(f"│   {'Name':<6} {'IP Address':<16} {'MAC Address':<20} │")
        print("│   " + "-" * 44 + " │")
        
        # Sort hosts numerically by extracting number from name (h1=1, h2=2, etc.)
        for h in sorted(net.hosts, key=lambda x: int(x.name[1:])):
            print(f"│   {h.name:<6} {h.IP():<16} {h.MAC():<20} │")
        
        print("=" * W)
        print("Run 'pingall' before using mininet.".center(W))
        print("=" * W)
        print()
        
        # --- STEP 6: LAUNCH INTERACTIVE CLI ---
        # CLI() provides command-line interface for interacting with the network.
        # Common commands: pingall, iperf, h1 ping h2, xterm h1, etc.
        # Blocks until user types 'exit' or presses Ctrl+D.
        CLI(net)

    except Exception as e:
        # Handle any errors during network startup or operation
        print(f"Error occurred: {e}")
        
    finally:
        # --- STEP 7: CLEANUP ON EXIT ---
        # net.stop() performs:
        #   1. Stops all host processes
        #   2. Removes virtual interfaces
        #   3. Stops OVS switches
        #   4. Removes network namespaces
        # This block always executes, even if an exception occurred.
        print("--- Stopping network ---")
        net.stop()


# --- MAIN ENTRY POINT ---
if __name__ == '__main__':
    # setLogLevel() controls verbosity of Mininet logging.
    # Options: 'debug', 'info', 'warning', 'error', 'critical'
    # 'info' provides useful startup messages without excessive detail.
    setLogLevel('info')
    
    # Start the network - this is the main execution function
    startNetwork()