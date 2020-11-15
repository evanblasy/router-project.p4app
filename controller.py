from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from ospf import OSPF, OSPF_hello, OSPF_LSU, LSU, TYPE_OSPF
from router_database import RouterDatabase
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
HELLO_INT = 15
LSU_INT = 15
TYPE_IPV4 = 0x0800

INTERFACES = dict()

class PWOSPFInterface():
    def __init__(self, int_ip, mask, helloint):
        self.int_ip = int_ip
        self.mask = mask
        self.helloint = helloint
        # indexed by ip and holds id and last hello time
        self.neighbors = {}

    def __str__(self):
        return "Interface IP: " + str(self.int_ip) + " Mask: " + str(self.mask) + " HelloInt: " + str(self.helloint) + " Neighbors: " + str(self.neighbors)

    def add_hello_pkt_time(self, id, ip):
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
    def __init__(self, sw, router_id, area_id, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.router_id = router_id
        self.area_id = area_id
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}
        self.stop_event = Event()
        self.hello_cont = Hello_controller(self.send, HELLO_INT, self.router_id, self.getOspfPkt)
        self.lsu_cont = LSU_controller(LSU_INT,self.send,self.getOspfPkt)
        self.lsu_sequences = dict()
        self.router_database = RouterDatabase(router_id)

        INTERFACES[router_id] = dict()

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
        INTERFACES[self.router_id][int_ip] = PWOSPFInterface(int_ip,mask,helloint)

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

    def handleOspfHello(self, pkt):
        self.addMacAddr(pkt[Ether].src,pkt[IP].src,pkt[CPUMetadata].srcPort)
        # print("PACKET SOURCE: " + str(pkt[IP].src))
        interface_ip = self.router_id[:-1] + str(pkt[CPUMetadata].srcPort)
        if interface_ip not in (INTERFACES[self.router_id]):
            self.addInterface(interface_ip, pkt[OSPF_hello].net_mask, pkt[OSPF_hello].hello_int)
            (INTERFACES[self.router_id][interface_ip]).add_hello_pkt_time(pkt[OSPF].router_id, pkt[IP].src)
        # print("CURRENT ROUTER: " + str(self.router_id))
        # print(INTERFACES[self.router_id])
        # for key,value in INTERFACES[self.router_id].items():
        #     print(value)
        
    def handleOspfLSU(self, pkt):
        if pkt[OSPF].router_id == self.router_id: return
        # check seq or add if first
        if pkt[IP].src not in self.lsu_sequences: self.lsu_sequences[pkt[IP].src] = pkt[OSPF_LSU].seq
        elif self.lsu_sequences[pkt[IP].src] < pkt[OSPF_LSU].seq: self.lsu_sequences[pkt[IP].src] = pkt[OSPF_LSU].seq
        else: return


        pkt.show2()

    def handleUnknownPacket(self, pkt):
        print("UNKNOWN PACKET TYPE")
        pkt.show2()

    def handlePkt(self, pkt):
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
            elif OSPF_hello in pkt:
                self.handleOspfHello(pkt)
            elif OSPF_LSU in pkt:
                self.handleOspfLSU(pkt)
        else:
            self.handleUnknownPacket(pkt)
        
    def getOspfPkt(self):
        pkt = Ether()/CPUMetadata()/IP()/OSPF()
        pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
        pkt[CPUMetadata].srcPort = 1
        pkt[CPUMetadata].origEtherType = TYPE_IPV4
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
        self.hello_cont.start()
        self.lsu_cont.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        self.hello_cont.stop_event.set()
        self.lsu_cont.stop_event.set()
        # self.hello_cont.join()
        # self.lsu_cont.join()
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

        self.send(pkt)

    # def join(self, *args, **kwargs):
    #     self.stop_event.set()
    #     super(Hello_controller, self).join(*args, **kwargs)


    def run(self):
        while not self.stop_event.isSet():
            time.sleep(self.hello_wait)
            self.send_hello()
        # time.sleep(1)
        # self.send_hello()
        # time.sleep(self.hello_wait)
        # self.send_hello()

class LSU_controller(Thread):
    def __init__(self, lsu_int, send, get_ospf_packet, start_wait=0.3):
        super(LSU_controller, self).__init__()
        self.start_wait = start_wait
        self.lsu_int = lsu_int
        self.lsu_seq = 0
        self.send = send
        self.get_ospf_packet = get_ospf_packet
        self.stop_event = Event()

    def start(self, *args, **kwargs):
        super(LSU_controller, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def send_lsu(self):
        pkt_bare = self.get_ospf_packet()
        lsu_list = []
        pkt_bare[OSPF].type = 4
        pkt_bare[OSPF].len = 32
        neighbors_ip = set()
        for key, value in INTERFACES[pkt_bare[OSPF].router_id].items():
            for key2, value2 in value.neighbors.items():
                lsu_list.append(LSU(subnet=pkt_bare[OSPF].router_id,mask=value.mask,router_id=value2[0]))
                neighbors_ip.add(value2[0])
        
        pkt_bare[OSPF].len = 32 + len(lsu_list)*12
        lsu_pkt = pkt_bare/OSPF_LSU(seq=self.lsu_seq, adverts=len(lsu_list), lsu_ads=lsu_list)
        # (pkt_bare/OSPF_LSU(seq=self.lsu_seq, adverts=0, lsu_ads=[])).show2()
        # lsu_pkt.show2()
        # lsu_pkt.show()
        for ip in neighbors_ip:
            lsu_pkt[IP].dst = ip
            self.send(lsu_pkt)
            # lsu_pkt.show2()
        self.lsu_seq += 1

    
    # def join(self, *args, **kwargs):
    #     self.stop_event.set()
    #     super(LSU_controller, self).join(*args, **kwargs)
    
    def run(self):
        while not self.stop_event.isSet():
            time.sleep(self.lsu_int)
            self.send_lsu()
        # time.sleep(self.hello_wait)
        # self.send_hello()
