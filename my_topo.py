from mininet.topo import Topo

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1')

        for i in xrange(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)

class DoubleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch1 = self.addSwitch('s1a')
        switch2 = self.addSwitch('s2a')
        switch3 = self.addSwitch('s3a')

        cpu1 = self.addHost('cpu1')
        cpu2 = self.addHost('cpu2')
        cpu3 = self.addHost('cpu3')

        host1 = self.addHost('h2',
                                ip = "10.0.0.2",
                                mac = '00:00:00:00:00:02')
        host3 = self.addHost('h4',
                                ip = "10.0.0.3",
                                mac = '00:00:00:00:00:03')
        host2 = self.addHost('h3',
                                ip = "10.0.1.3",
                                mac = '00:00:00:00:01:03')
        host4 = self.addHost('h5',
                                ip = "10.0.1.2",
                                mac = '00:00:00:00:01:02') 

        self.addLink(host1, switch1, port2=4)
        self.addLink(host3, switch1, port2=5)
        self.addLink(host2, switch2, port2=4)
        self.addLink(host4, switch2, port2=5)
        self.addLink(cpu1, switch1, port2=1)
        self.addLink(cpu2, switch2, port2=1) 
        self.addLink(cpu3, switch3, port2=1)
        self.addLink(switch1,switch3, port1=2, port2=2)
        self.addLink(switch3,switch2, port1=3, port2=3)
        # self.addLink(switch1,switch2,port1=2,port2=2)


class FiveSwitchTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self,**opts)

        switch1 = self.addSwitch('s1a')
        switch2 = self.addSwitch('s2a')
        switch3 = self.addSwitch('s3a')
        switch4 = self.addSwitch('s4a')
        switch5 = self.addSwitch('s5a')

        cpu1 = self.addHost('cpu1')
        cpu2 = self.addHost('cpu2')
        cpu3 = self.addHost('cpu3')
        cpu4 = self.addHost('cpu4')
        cpu5 = self.addHost('cpu5')

        self.addLink(cpu1, switch1, port2=1)
        self.addLink(cpu2, switch2, port2=1)
        self.addLink(cpu3, switch3, port2=1)
        self.addLink(cpu4, switch4, port2=1)
        self.addLink(cpu5, switch5, port2=1)

        self.addLink(switch1, switch2, port1=2,port2=2)
        self.addLink(switch2, switch3, port1=3,port2=3)
        self.addLink(switch3, switch4, port1=2,port2=2)
        self.addLink(switch4, switch5, port1=3,port2=3)
        self.addLink(switch2, switch5, port1=4,port2=2)

        host1 = self.addHost('h1', ip="10.0.0.1", mac='00:00:00:00:00:01')
        host2 = self.addHost('h2', ip="10.0.0.2", mac='00:00:00:00:00:02')
        host3 = self.addHost('h3', ip="10.0.1.3", mac='00:00:00:00:00:03')
        host4 = self.addHost('h4', ip="10.0.1.4", mac='00:00:00:00:00:04')
        host5 = self.addHost('h5', ip="10.0.2.5", mac='00:00:00:00:00:05')
        host6 = self.addHost('h6', ip="10.0.2.6", mac='00:00:00:00:00:06')
        host7 = self.addHost('h7', ip="10.0.3.7", mac='00:00:00:00:00:07')
        host8 = self.addHost('h8', ip="10.0.3.8", mac='00:00:00:00:00:08')
        host9 = self.addHost('h9', ip="10.0.4.9", mac='00:00:00:00:00:09')
        host10 = self.addHost('h10', ip="10.0.4.10", mac='00:00:00:00:00:10')

        self.addLink(host1, switch1, port2=3)
        self.addLink(host2, switch1, port2=4)
        self.addLink(host3, switch2, port2=5)
        self.addLink(host4, switch2, port2=6)
        self.addLink(host5, switch3, port2=4)
        self.addLink(host6, switch3, port2=5)
        self.addLink(host7, switch4, port2=4)
        self.addLink(host8, switch4, port2=5)
        self.addLink(host9, switch5, port2=4)
        self.addLink(host10, switch5, port2=5)
        