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

        cpu1 = self.addHost('cpu1')
        cpu2 = self.addHost('cpu2')

        host1 = self.addHost('h2',
                                ip = "10.0.0.2",
                                mac = '00:00:00:00:00:02')
        host2 = self.addHost('h3',
                                ip = "10.0.0.3",
                                mac = '00:00:00:00:00:03')

        self.addLink(host1, switch1, port2=3)
        self.addLink(host2, switch2, port2=3)
        self.addLink(cpu1, switch1, port2=1)
        self.addLink(cpu2, switch2, port2=1) 
        self.addLink(switch1,switch2, port1=2, port2=2)