from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController

class MyTopo( Topo ):
    def build( self ):
        # --- TẠO SWITCH (QUAN TRỌNG: OpenFlow13) ---
        # Phải dùng OVSKernelSwitch và khai báo protocols='OpenFlow13' 
        # để Controller V15/V16/V17 có thể cài đặt Flow đúng chuẩn.
        s1 = self.addSwitch( 's1', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s2 = self.addSwitch( 's2', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s3 = self.addSwitch( 's3', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s4 = self.addSwitch( 's4', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s5 = self.addSwitch( 's5', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s6 = self.addSwitch( 's6', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        # --- TẠO HOST (Với IP và MAC tĩnh) ---
        # CPU limited (1.0/20 = 5%) để tránh việc flood làm treo máy thật
        # MAC addresses sử dụng OUI thực tế từ các nhà sản xuất khác nhau
        h1 = self.addHost( 'h1', cpu=0.05, mac="3c:52:82:a1:7b:04", ip="10.0.0.1/24" )   # Dell
        h2 = self.addHost( 'h2', cpu=0.05, mac="00:1a:2b:3c:4d:5e", ip="10.0.0.2/24" )   # Ayecom
        h3 = self.addHost( 'h3', cpu=0.05, mac="f4:8e:38:9d:2c:11", ip="10.0.0.3/24" )   # Apple    

        h4 = self.addHost( 'h4', cpu=0.05, mac="50:eb:f6:c8:a3:72", ip="10.0.0.4/24" )   # ASUSTek
        h5 = self.addHost( 'h5', cpu=0.05, mac="d4:3d:7e:b5:91:f8", ip="10.0.0.5/24" )   # Micro-Star
        h6 = self.addHost( 'h6', cpu=0.05, mac="88:d7:f6:42:1e:c9", ip="10.0.0.6/24" )   # ASUSTek

        h7 = self.addHost( 'h7', cpu=0.05, mac="a4:c3:f0:73:dc:85", ip="10.0.0.7/24" )   # Intel
        h8 = self.addHost( 'h8', cpu=0.05, mac="00:25:90:e4:5a:3f", ip="10.0.0.8/24" )   # Super Micro
        h9 = self.addHost( 'h9', cpu=0.05, mac="ec:f4:bb:d6:17:ae", ip="10.0.0.9/24" )   # Dell

        h10 = self.addHost( 'h10', cpu=0.05, mac="2c:4d:54:f9:28:b6", ip="10.0.0.10/24" )  # ASUSTek
        h11 = self.addHost( 'h11', cpu=0.05, mac="78:2b:cb:a7:e3:94", ip="10.0.0.11/24" )  # Dell
        h12 = self.addHost( 'h12', cpu=0.05, mac="b4:2e:99:51:d4:0c", ip="10.0.0.12/24" )  # Giga-Byte

        h13 = self.addHost( 'h13', cpu=0.05, mac="00:50:56:8f:1c:7a", ip="10.0.0.13/24" )  # VMware
        h14 = self.addHost( 'h14', cpu=0.05, mac="ac:1f:6b:2e:86:d3", ip="10.0.0.14/24" )  # Super Micro
        h15 = self.addHost( 'h15', cpu=0.05, mac="1c:69:7a:63:f5:21", ip="10.0.0.15/24" )  # EliteGroup

        h16 = self.addHost( 'h16', cpu=0.05, mac="70:85:c2:ba:49:e7", ip="10.0.0.16/24" )  # ASRock
        h17 = self.addHost( 'h17', cpu=0.05, mac="54:bf:64:c0:8d:52", ip="10.0.0.17/24" )  # Dell
        h18 = self.addHost( 'h18', cpu=0.05, mac="e8:40:f2:19:ac:6b", ip="10.0.0.18/24" )  # Pegatron

        # --- TẠO LIÊN KẾT (LINKS) ---
        # Host nối vào Switch
        self.addLink( h1, s1 ); self.addLink( h2, s1 ); self.addLink( h3, s1 )
        self.addLink( h4, s2 ); self.addLink( h5, s2 ); self.addLink( h6, s2 )
        self.addLink( h7, s3 ); self.addLink( h8, s3 ); self.addLink( h9, s3 )
        self.addLink( h10, s4 ); self.addLink( h11, s4 ); self.addLink( h12, s4 )
        self.addLink( h13, s5 ); self.addLink( h14, s5 ); self.addLink( h15, s5 )
        self.addLink( h16, s6 ); self.addLink( h17, s6 ); self.addLink( h18, s6 )

        # Switch nối Switch (Mô hình tuyến tính Linear)
        self.addLink( s1, s2 )
        self.addLink( s2, s3 )
        self.addLink( s3, s4 )
        self.addLink( s4, s5 )
        self.addLink( s5, s6 )

def startNetwork():
    topo = MyTopo()
    
    # Cấu hình Controller trỏ về Localhost (127.0.0.1)
    # Port 6633 là port mặc định chuẩn của OpenFlow (Ryu cũng lắng nghe ở đây)
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    
    # Khởi tạo mạng với Switch OVSKernelSwitch
    net = Mininet(topo=topo, link=TCLink, controller=c0, switch=OVSKernelSwitch)

    net.start()
    print("--- Mininet đã khởi động với OpenFlow 1.3 và Controller Localhost ---")
    print("--- Đừng quên chạy lệnh 'pingall' trước khi tấn công! ---")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    startNetwork()