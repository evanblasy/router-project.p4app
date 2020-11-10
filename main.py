from p4app import P4Mininet
from my_topo import SingleSwitchTopo, DoubleSwitchTopo
from controller import MacLearningController

def hostIP(i):
    return "10.0.0.%d" % (i)

def hostMac(i):
	return '00:00:00:00:00:%02x' % (i)

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

# topo = SingleSwitchTopo(N)
topo = DoubleSwitchTopo(N)
net = P4Mininet(program='switch.p4', topo=topo, auto_arp=False)
# net = P4Mininet(program='switch.p4', topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
sw1 = net.get('s1')
sw2 = net.get('s2')
sw1.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))
sw2.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))


# Send MAC bcast packets to the bcast multicast group
sw1.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
sw2.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})

# Start the MAC learning controller
cpu1 = MacLearningController(sw1)
cpu2 = MacLearningController(sw2)
cpu1.start()
cpu2.start()

h2, h3 = net.get('h2'), net.get('h3')

print h2.cmd('arping -c1 10.0.0.3')
print h2.cmd('arping -c1 10.0.0.3')
# print h3.cmd('arping -c1 10.0.0.2')

# print h3.cmd('ping -c1 10.0.0.2')
# print h2.cmd('ping -c1 10.0.0.3')

# These table entries were added by the CPU:
sw1.printTableEntries()
sw2.printTableEntries()
