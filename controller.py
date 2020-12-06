from __future__ import print_function
from threading import Thread, Event, Lock
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP, Raw
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from ospf import OSPF, OSPF_hello, OSPF_LSU, LSU, TYPE_OSPF
from router_database import RouterDatabase
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
HELLO_INT = 4
LSU_INT = 8
TYPE_IPV4 = 0x0800

LOCKS = dict()
INTERFACES = dict()

DEBUG_LOCK = Lock()

def ip2hex(ip):
    ip1 =  ''.join([hex(int(x)+256)[3:] for x in ip.split('.')])
    return int(ip1,16)

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

        return 1 if remove else 0

class MacLearningController(Thread):
    def __init__(self, sw, router_id, area_id, mac, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.router_id = router_id
        self.mac = mac
        self.area_id = area_id
        self.sw = sw
        self.mask = ip2hex('255.255.255.0')
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}
        self.stop_event = Event()
        self.lsu_cont = LSU_controller(LSU_INT,self.send,self.getOspfPkt,self.getNeighborsFromInterface)
        self.hello_cont = Hello_controller(self.send, HELLO_INT, self.router_id, self.getOspfPkt, self.lsu_cont.send_lsu)
        self.lsu_sequences = dict()
        self.router_database = RouterDatabase(router_id)
        self.prev_lsu = dict()
        self.database_adds = set()

        LOCKS[router_id] = Lock()
        INTERFACES[router_id] = dict()

    def addMacAddr(self, mac, ip, port):
        # Don't re-add the mac-port mapping if we already have it:
        # print(mac,ip,port)
        if mac not in self.port_for_mac:
            self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                    match_fields={'hdr.ethernet.dstAddr': [mac]},
                    action_name='MyIngress.set_egr',
                    action_params={'port': port})
            self.port_for_mac[mac] = port
        if ip not in self.mac_for_ip:
            self.sw.insertTableEntry(table_name='MyIngress.arp_exact',
                    match_fields={'hdr.arp.dstIP': [ip, 32]},
                    action_name='MyIngress.response_to_arp',
                    action_params={'dstAddr': mac})
            self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                    match_fields={'hdr.ipv4.dstAddr': [ip,32]},
                    action_name='MyIngress.ipv4_forward',
                    action_params={'dstAddr': mac, 'port': port})
            self.mac_for_ip[ip] = mac

    def getNeighborsFromLsu(self, pkt):
        list_of_ads = pkt[OSPF_LSU].lsu_ads
        list_of_routers = []
        for i in list_of_ads:
            list_of_routers.append(i.router_id)
        list_of_routers.sort()
        return list_of_routers

    def addInterface(self,int_ip, mask, helloint):
        LOCKS[self.router_id].acquire()
        INTERFACES[self.router_id][int_ip] = PWOSPFInterface(int_ip,mask,helloint)
        LOCKS[self.router_id].release()

    def handleArpReply(self, pkt):
        # print("hi")
        # pkt.show2()
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
        print("Evan got a Hello!")
        self.mac_for_ip[pkt[IP].src] = pkt[Ether].src
        self.port_for_mac[pkt[Ether].src] = pkt[CPUMetadata].srcPort
        # self.addMacAddr(pkt[Ether].src,pkt[IP].src,pkt[CPUMetadata].srcPort)
        # print("PACKET SOURCE: " + str(pkt[IP].src))
        interface_ip = self.router_id[:-1] + str(pkt[CPUMetadata].srcPort)
        if interface_ip not in (INTERFACES[self.router_id]):
            self.addInterface(interface_ip, pkt[OSPF_hello].net_mask, pkt[OSPF_hello].hello_int)
        
        LOCKS[self.router_id].acquire()
        (INTERFACES[self.router_id][interface_ip]).add_hello_pkt_time(pkt[OSPF].router_id, pkt[IP].src)
        LOCKS[self.router_id].release()

        # LOCKS[self.router_id].acquire()
        # changed = False
        # for interface in INTERFACES[self.router_id]:
        #     if interface.check_helloint():
        #         changed = True
        # LOCKS[self.router_id].release()
        # print("CURRENT ROUTER: " + str(self.router_id))
        # print(INTERFACES[self.router_id])
        # for key,value in INTERFACES[self.router_id].items():
        #     print(value)

        own_interface_list = list(self.getNeighborsFromInterface())
        self.handleNeighborList(self.router_id, own_interface_list)

    def addRulesFromDatabase(self,ip):
        # if self.router_id == '10.0.0.0': self.router_database.dump()
        self.router_database.remove_all_links(ip)
        for i in self.prev_lsu[ip]:
            if (i in self.prev_lsu and (ip in self.prev_lsu[i]) ) or (i in self.getNeighborsFromInterface()):
                self.router_database.add_link(ip, i)
                # if self.router_id == '10.0.0.0':
                #     print(ip,i)
                # if ip == '10.0.0.0' and i == '10.0.2.0':
                #     print("WRONG")

        first_jumps = self.router_database.compute_first_jumps()

        for dst, jump in first_jumps.items():
            if dst not in self.database_adds:
                # DEBUG_LOCK.acquire()
                # print(self.router_id, first_jumps)
                # DEBUG_LOCK.release()
                mac = self.mac_for_ip[jump[1]]
                port = self.port_for_mac[mac]
                self.sw.insertTableEntry(table_name='MyIngress.arp_exact',
                    match_fields={'hdr.arp.dstIP': [dst, 24]},
                    action_name='MyIngress.response_to_arp',
                    action_params={'dstAddr': mac})
                self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                    match_fields={'hdr.ipv4.dstAddr': [dst,24]},
                    action_name='MyIngress.ipv4_forward',
                    action_params={'dstAddr': mac, 'port': port})
                self.database_adds.add(dst)
        # if self.router_id == '10.0.0.0': self.router_database.dump()

    def removeRulesFromDatabase(self,removed_entries):
        if removed_entries:
            for i in removed_entries:
                self.router_database.remove_router(i)
            print("Router " + self.router_id + ", REMOVING ROUTER - " + i)

    def handleNeighborList(self, ip, list_of_neighbors):
        # LOCKS[self.router_id].acquire()
        different = False
        removed_entries = []
        if (ip in self.prev_lsu and self.prev_lsu[ip] != list_of_neighbors):
            removed_entries = list(set(self.prev_lsu[ip])- set(list_of_neighbors))
            self.prev_lsu[ip] = list_of_neighbors
            different = True
        elif ip not in self.prev_lsu:
            self.prev_lsu[ip] = list_of_neighbors
            different = True

        if different:
            # DEBUG_LOCK.acquire()
            # print(self.router_id, self.prev_lsu)
            # DEBUG_LOCK.release()
            self.removeRulesFromDatabase(removed_entries)
            self.addRulesFromDatabase(ip)
        # LOCKS[self.router_id].release()

        
    def handleOspfLSU(self, pkt):
        if pkt[OSPF].router_id == self.router_id:
            # print("rejected because same id") 
            # print(pkt[OSPF].router_id, self.router_id)
            return
        # check seq or add if first
        if pkt[IP].src not in self.lsu_sequences: self.lsu_sequences[pkt[IP].src] = pkt[OSPF_LSU].seq
        elif self.lsu_sequences[pkt[IP].src] < pkt[OSPF_LSU].seq: self.lsu_sequences[pkt[IP].src] = pkt[OSPF_LSU].seq
        else: 
            # print("rejected because of seq")
            return

        list_of_neighbors = self.getNeighborsFromLsu(pkt)

        self.handleNeighborList(pkt[IP].src, list_of_neighbors)

        for ip in self.getNeighborsFromInterface():
            pkt[IP].dst = ip
            self.send(pkt)


    def handleUnknownPacket(self, pkt):
        print("UNKNOWN PACKET TYPE")
        pkt.show2()

    def packetInNetwork(self, ip):
        return (ip2hex(ip) & self.mask) == ip2hex(self.router_id)

    def getICMPResponse(self, pkt):
        new_pkt = Ether()/CPUMetadata()/IP()/ICMP()

        new_pkt[Ether].src = self.mac
        new_pkt[Ether].dst = "00:00:00:00:00:00"
        new_pkt[CPUMetadata].srcPort = 1
        new_pkt[CPUMetadata].origEtherType = TYPE_IPV4
        new_pkt[IP].src = self.router_id
        new_pkt[IP].dst = pkt[IP].src
        new_pkt[IP].id = pkt[IP].id
        new_pkt[IP].proto = 1
        
        del new_pkt[IP].chksum
        del new_pkt[ICMP].chksum

        new_pkt.add_payload(pkt[IP])

        return new_pkt

    def handleBadIP(self, pkt):
        new_pkt = self.getICMPResponse(pkt)

        if pkt[IP].ttl == 0:
            print("TTL RESPONSE")
            new_pkt[ICMP].type = 11
            new_pkt[ICMP].code = 0
            # new_pkt.show2()
        elif self.packetInNetwork(pkt[IP].dst):
            print("IN NETWORK")
            new_pkt[ICMP].type = 3
            new_pkt[ICMP].code = 7
        else:
            print("OUT NETWORK")
            new_pkt[ICMP].type = 3
            new_pkt[ICMP].code = 6

        self.send(new_pkt)

    def handlePkt(self, pkt):
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"
        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                if not self.packetInNetwork(pkt[ARP].psrc): # (ip2hex(pkt[ARP].psrc) & self.mask) != ip2hex(self.router_id):
                    return 

                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        elif IP in pkt:
            if pkt[IP].proto == TYPE_OSPF:
                try:
                    pwospf_pkt = OSPF(pkt[Raw])
                except Exception:
                    print("cannot parse this PWOSPF correctly")
                    # lg.debug('%s cannot parse this PWOSPF packet correctly\n' % self.sw.name)
                    return
                if OSPF_hello in pwospf_pkt:
                    print("Entered OSPF Hello!")
                    self.handleOspfHello(pkt[Ether]/pkt[CPUMetadata]/pkt[IP]/pwospf_pkt)
                elif OSPF_LSU in pwospf_pkt:
                    self.handleOspfLSU(pkt[Ether]/pkt[CPUMetadata]/pkt[IP]/pwospf_pkt)
            else:
                self.handleBadIP(pkt)

            
        else:
            self.handleUnknownPacket(pkt)
        
    def getOspfPkt(self):
        pkt = Ether()/CPUMetadata()/IP()/OSPF()
        pkt[Ether].dst = "00:00:00:00:00:00"
        pkt[Ether].src = self.mac
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

    def getNeighborsFromInterface(self):
        neighbors_ip = set()
        LOCKS[self.router_id].acquire()
        for key, value in INTERFACES[self.router_id].items():
            for key2, value2 in value.neighbors.items():
                neighbors_ip.add(value2[0])
        LOCKS[self.router_id].release()

        return neighbors_ip

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
    def __init__(self, send, hello_wait, ip, get_ospf_packet, trigger_lsu, start_wait=0.3):
        super(Hello_controller, self).__init__()
        self.start_wait = start_wait
        self.send = send
        self.hello_wait = hello_wait
        self.ip = ip
        self.get_ospf_packet = get_ospf_packet
        self.stop_event = Event()
        self.trigger_lsu = trigger_lsu

    def start(self, *args, **kwargs):
        super(Hello_controller, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def check_interfaces(self, router_id):
        LOCKS[router_id].acquire()
        # if router_id == '10.0.1.0':
        #     for key, interface in INTERFACES[router_id].items():
        #         print(interface)

        changed = False
        for key, interface in INTERFACES[router_id].items():
            if interface.check_helloint():
                changed = True
        LOCKS[router_id].release()

        return changed

    def send_hello(self):
        pkt = self.get_ospf_packet()/OSPF_hello()
        pkt[OSPF].type = 1
        pkt[OSPF].len = 32
        pkt[OSPF_hello].net_mask = "255.255.255.0"
        pkt[OSPF_hello].hello_int = self.hello_wait

        self.send(pkt)

        if self.check_interfaces(pkt[OSPF].router_id):
            print("Flooding LSU because of loss of router")
            self.trigger_lsu


    def run(self):
        while not self.stop_event.isSet():
            time.sleep(self.hello_wait)
            self.send_hello()

class LSU_controller(Thread):
    def __init__(self, lsu_int, send, get_ospf_packet, get_neighbors, start_wait=0.3):
        super(LSU_controller, self).__init__()
        self.start_wait = start_wait
        self.lsu_int = lsu_int
        self.lsu_seq = 0
        self.send = send
        self.get_ospf_packet = get_ospf_packet
        self.get_neighbors = get_neighbors
        self.stop_event = Event()

    def start(self, *args, **kwargs):
        super(LSU_controller, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def send_lsu(self):
        pkt_bare = self.get_ospf_packet()
        lsu_list = []
        pkt_bare[OSPF].type = 4
        pkt_bare[OSPF].len = 32
        neighbors_ip = self.get_neighbors()
        LOCKS[pkt_bare[OSPF].router_id].acquire()
        for key, value in INTERFACES[pkt_bare[OSPF].router_id].items():
            for key2, value2 in value.neighbors.items():
                lsu_list.append(LSU(subnet=pkt_bare[OSPF].router_id,mask=value.mask,router_id=value2[0]))
                # neighbors_ip.add(value2[0])
        LOCKS[pkt_bare[OSPF].router_id].release()
        
        pkt_bare[OSPF].len = 32 + len(lsu_list)*12
        lsu_pkt = pkt_bare/OSPF_LSU(seq=self.lsu_seq, adverts=len(lsu_list), lsu_ads=lsu_list)
        # (pkt_bare/OSPF_LSU(seq=self.lsu_seq, adverts=0, lsu_ads=[])).show2()
        for ip in neighbors_ip:
            lsu_pkt[IP].dst = ip
            self.send(lsu_pkt)
            # lsu_pkt.show2()
        self.lsu_seq += 1

    
    def run(self):
        while not self.stop_event.isSet():
            time.sleep(self.lsu_int)
            self.send_lsu()
