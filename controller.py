from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from ospf import OSPF, OSPF_hello, OSPF_LSU, LSU, TYPE_OSPF
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
HELLO_INT = 30
LSU_INT = 30

class PWOSPFInterface():
    def __init__(self, int_ip, mask, helloint):
        self.neighbors = []
        self.int_ip = int_ip
        self.mask = mask
        self.helloint = helloint
        # indexed by ip and holds id and last hello time
        self.neighbors = {}

    def get_hello_pkt(self, id, ip):
        if ip in self.neighbors: self.neighbors[ip] = [id,0]
        else:
            self.neighbors[ip] = [id,0]

    def check_helloint(self):
        remove = []
        for key, value in self.neighbors.items():
            if value[1] > (self.helloint * 3): remove.append(key)
            else:
                self.neighbors[key] = [value[0],value[1] + self.helloint]

        for i in remove:
            del self.neighbors[i]

class MacLearningController(Thread):
    def __init__(self, sw, router_id, area_id, lsu_int = 30, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.router_id = router_id
        self.area_id = area_id
        self.lsu_int = lsu_int
        self.interfaces = {}
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}
        self.stop_event = Event()

    def addMacAddr(self, mac, ip, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac not in self.port_for_mac:
            self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                    match_fields={'hdr.ethernet.dstAddr': [mac]},
                    action_name='MyIngress.set_egr',
                    action_params={'port': port})
            self.port_for_mac[mac] = port
        if ip not in self.mac_for_ip:
            self.sw.insertTableEntry(table_name='MyIngress.arp_exact',
                    match_fields={'hdr.arp.dstIP': [ip]},
                    action_name='MyIngress.response_to_arp',
                    action_params={'dstAddr': mac})
            self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                    match_fields={'hdr.ipv4.dstAddr': [ip,32]},
                    action_name='MyIngress.ipv4_forward',
                    action_params={'dstAddr': mac, 'port': port})
            self.mac_for_ip[ip] = mac

    def addInterface(self,int_ip, mask, helloint):
        self.interfaces[int_ip] = PWOSPFInterface(int_ip,mask,helloint)

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[ARP].psrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[ARP].psrc, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def handleIPv4Ttl(self, pkt):
        pkt = pkt[Ether]/pkt[IP]/ICMP()/pkt[IP] # /pkt[IP].payload
        temp = pkt[Ether].dst
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = temp
        temp = pkt[IP].dst
        pkt[IP].dst = pkt[IP].src
        pkt[IP].src = temp
        pkt[IP].len = 52
        pkt[ICMP].type = 11
        pkt[ICMP].code = 0
        pkt[IP].ttl = 64
        del pkt[ICMP].chksum
        del pkt[IP].chksum
        pkt.show2()
        self.send(pkt)

    def handleUnknownPacket(self, pkt):
        print("UNKNOWN PACKET TYPE")
        pkt.show2()

    def handlePkt(self, pkt):
        # pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        elif IP in pkt:
            if pkt[IP].ttl == 1:
                self.handleIPv4Ttl(pkt)
        else:
            self.handleUnknownPacket(pkt)
        
    def getOspfPkt(self):
        pkt = Ether()/CPUMetadata()/IP()/OSPF()
        pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
        pkt[CPUMetadata].srcPort = 1
        pkt[IP].src = self.router_id
        pkt[IP].dst = "224.0.0.5"
        pkt[IP].proto = TYPE_OSPF

        pkt[OSPF].router_id = self.router_id
        pkt[OSPF].type = 0
        pkt[OSPF].area_id = self.area_id

        return pkt

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        hello_cont = Hello_controller(self.send, HELLO_INT, self.router_id, self.getOspfPkt)
        hello_cont.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)

class Hello_controller(Thread):
    def __init__(self, send, hello_wait, ip, get_ospf_packet, start_wait=0.3):
        super(Hello_controller, self).__init__()
        self.start_wait = start_wait
        self.send = send
        self.hello_wait = hello_wait
        self.ip = ip
        self.get_ospf_packet = get_ospf_packet
        self.stop_event = Event()

    def start(self, *args, **kwargs):
        super(Hello_controller, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def send_hello(self):
        pkt = self.get_ospf_packet()/OSPF_hello()
        pkt[OSPF].type = 1
        pkt[OSPF].len = 32
        pkt[OSPF_hello].net_mask = "255.255.255.0"
        pkt[OSPF_hello].hello_int = self.hello_wait
        pkt.show()
        pkt.show2()

        self.send(pkt)


    def run(self):
        # while True:
        self.send_hello()
        # time.sleep(self.hello_wait)
        # self.send_hello()
            

        # sniff(iface=self.iface, prn=self.handleOSPFPkt, stop_event=self.stop_event)