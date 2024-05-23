from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel

'''
Tutorial
- I prefer to use Method 1, which is to build the Fat-Tree topology via "Mininet Python API" and use CLI to run
- pwd:  ~/mininet/custom/lab1_fattree.py
- When you run the script, you should use the orders below:
    > cd ~/sdn/mininet/custom
    > sudo mn --custom lab1_fattree.py --topo fattreetopo --controller=none

'''

class FatTree(Topo):
    # offer the configuration of Fat-Tree
    def build(self, k=4):
        # total number in this topology
        self.k = k
        self.pods = k
        self.aggrSw = self.pods * (k // 2)
        self.edgeSw = self.pods * (k // 2)
        self.coreSw = (k // 2) ** 2
        # host number in each pod
        self.PodHost = (k // 2) ** 2

        # utilize the arguments above to build topo
        self.addCoreSw()
        self.addAggrSw()
        self.addEdgeSw()
        self.addHosts()
        self.setLink()

    def addCoreSw(self):
        for sw in range(self.coreSw):
            self.addSwitch('core{}'.format(sw + 1), 
                         failMode='standalone', stp=True)
        # coreSw is identified by its own ID, which means it can be presented as 1 element turple

    def addAggrSw(self):
        for pod in range(self.pods):
            for sw in range(self.k // 2):
                self.addSwitch('aggr{}{}'.format(pod + 1, sw + 1), 
                             failMode='standalone', stp=True)
        # aggrSw have to be presented as (pod, sw) in turple

    def addEdgeSw(self):
        for pod in range(self.pods):
            for sw in range(self.k // 2):
                self.addSwitch('edge{}{}'.format(pod + 1, sw + 1), 
                             failMode='standalone', stp=True)
        # edgeSw have to be presented as (pod, sw) in turple

    def addHosts(self):
        for pod in range(self.pods):
            for sw in range(self.k // 2):
                for hst in range(self.k // 2):
                    self.addHost('host{}{}{}'.format(pod + 1, sw + 1, hst + 1), 
                               failMode='standalone', stp=True)
        # host have to be presented as (pod, sw, hst) in turple
    
    def setLink(self):
        for pod in range(self.pods):
            # aggrSw -> coreSw
            for aggr in range(self.k // 2):
                for core in range(self.k // 2):
                    self.addLink('aggr{}{}'.format(pod + 1, aggr + 1), 
                               'core{}'.format(core + aggr * (self.k // 2) + 1))
                    # For coreSw is identified by its own ID
            
            # aggrSw -> edgeSw
            for aggr in range(self.k // 2):
                for edge in range(self.k // 2):
                    self.addLink('aggr{}{}'.format(pod + 1, aggr + 1), 
                               'edge{}{}'.format(pod + 1, edge + 1))
            
            # edgeSw -> host
            for edge in range(self.k // 2):
                for hst in range(self.k // 2):
                    self.addLink('edge{}{}'.format(pod + 1, edge + 1), 
                               'host{}{}{}'.format(pod + 1, edge + 1, hst + 1))



topos = { 'fattreetopo': ( lambda: FatTree() ) }