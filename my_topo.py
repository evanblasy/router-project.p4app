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