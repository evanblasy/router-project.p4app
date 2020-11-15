from p4app import P4Mininet
from my_topo import SingleSwitchTopo, DoubleSwitchTopo
from controller import MacLearningController
import time

def hostIP(i):
    return "10.0.0.%d" % (i)

def hostMac(i):
	return '00:00:00:00:00:%02x' % (i)

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3
TIME_TO_RUN = 10

# topo = SingleSwitchTopo(N)
topo = DoubleSwitchTopo(N)
net = P4Mininet(program='switch.p4', topo=topo, auto_arp=False)
# net = P4Mininet(program='switch.p4', topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
sw1 = net.get('s1a')
sw2 = net.get('s2a')
sw3 = net.get('s3a')
sw1.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))
sw2.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))
sw3.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))



# Send MAC bcast packets to the bcast multicast group
sw1.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
sw2.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
sw3.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
# Adding boradcast for PWOSPF
sw1.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                    match_fields={'hdr.ipv4.dstAddr': ["224.0.0.5",32]},
                    action_name='MyIngress.set_mgid',
                    action_params={'mgid': bcast_mgid})

sw2.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                    match_fields={'hdr.ipv4.dstAddr': ["224.0.0.5",32]},
                    action_name='MyIngress.set_mgid',
                    action_params={'mgid': bcast_mgid})
sw3.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                    match_fields={'hdr.ipv4.dstAddr': ["224.0.0.5",32]},
                    action_name='MyIngress.set_mgid',
                    action_params={'mgid': bcast_mgid})

# Start the MAC learning controller
cpu1 = MacLearningController(sw1, "10.0.0.0","192.168.0.0")
cpu2 = MacLearningController(sw2, "10.0.1.0","192.168.0.0")
cpu3 = MacLearningController(sw3, "10.0.2.0","192.168.0.0")
cpu1.start()
cpu2.start()
cpu3.start()

h2, h3, h4, h5 = net.get('h2'), net.get('h3'), net.get('h4'), net.get('h5')

# time.sleep(1)
# print h2.cmd('arping -c1 10.0.0.3')
# print h3.cmd('arping -c1 10.0.1.2')

time.sleep(TIME_TO_RUN)
cpu1.join()
cpu2.join()
cpu3.join()


# print h2.cmd('arping -c1 10.0.0.3')
# print h2.cmd('arping -c1 10.0.0.3')
# print h3.cmd('arping -c1 10.0.1.2')

# print h3.cmd('ping -t 1 -c1 10.0.0.2')
# print h2.cmd('ping -c1 10.0.0.3')

# These table entries were added by the CPU:
sw1.printTableEntries()
sw2.printTableEntries()
sw3.printTableEntries()
print("Packet Counts")
packet1,byte = sw1.readCounter("packet_counter", 0)
packet2,byte = sw2.readCounter("packet_counter", 0)
packet3,byte = sw3.readCounter("packet_counter", 0)
print("IP = SW1: %d , SW2: %d , SW3: %d" % (packet1,packet2,packet3))
packet1,byte = sw1.readCounter("packet_counter", 1)
packet2,byte = sw2.readCounter("packet_counter", 1)
packet3,byte = sw3.readCounter("packet_counter", 1)
print("ARP = SW1: %d , SW2: %d , SW3: %d" % (packet1,packet2,packet3))
packet1,byte = sw1.readCounter("packet_counter", 2)
packet2,byte = sw2.readCounter("packet_counter", 2)
packet3,byte = sw3.readCounter("packet_counter", 2)
print("CPU = SW1: %d , SW2: %d , SW3: %d" % (packet1,packet2,packet3))
