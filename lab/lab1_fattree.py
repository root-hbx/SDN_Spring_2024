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
    def build(ft, k=4):
        # total number in this topology
        ft.k = k
        ft.pods = k
        ft.aggrSw = ft.pods * (k // 2)
        ft.edgeSw = ft.pods * (k // 2)
        ft.coreSw = (k // 2) ** 2
        # host number in each pod
        ft.PodHost = (k // 2) ** 2

        # utilize the arguments above to build topo
        ft.addCoreSw()
        ft.addAggrSw()
        ft.addEdgeSw()
        ft.addHosts()
        ft.setLink()

    def addCoreSw(ft):
        for sw in range(ft.coreSw):
            ft.addSwitch('core{}'.format(sw + 1), 
                         failMode='standalone', stp=True)
        # coreSw is identified by its own ID, which means it can be presented as 1 element turple

    def addAggrSw(ft):
        for pod in range(ft.pods):
            for sw in range(ft.k // 2):
                ft.addSwitch('aggr{}{}'.format(pod + 1, sw + 1), 
                             failMode='standalone', stp=True)
        # aggrSw have to be presented as (pod, sw) in turple

    def addEdgeSw(ft):
        for pod in range(ft.pods):
            for sw in range(ft.k // 2):
                ft.addSwitch('edge{}{}'.format(pod + 1, sw + 1), 
                             failMode='standalone', stp=True)
        # edgeSw have to be presented as (pod, sw) in turple

    def addHosts(ft):
        for pod in range(ft.pods):
            for sw in range(ft.k // 2):
                for hst in range(ft.k // 2):
                    ft.addHost('host{}{}{}'.format(pod + 1, sw + 1, hst + 1), 
                               failMode='standalone', stp=True)
        # host have to be presented as (pod, sw, hst) in turple
    
    def setLink(ft):
        for pod in range(ft.pods):
            # aggrSw -> coreSw
            for aggr in range(ft.k // 2):
                for core in range(ft.k // 2):
                    ft.addLink('aggr{}{}'.format(pod + 1, aggr + 1), 
                               'core{}'.format(core + aggr * (ft.k // 2) + 1))
                    # For coreSw is identified by its own ID
            
            # aggrSw -> edgeSw
            for aggr in range(ft.k // 2):
                for edge in range(ft.k // 2):
                    ft.addLink('aggr{}{}'.format(pod + 1, aggr + 1), 
                               'edge{}{}'.format(pod + 1, edge + 1))
            
            # edgeSw -> host
            for edge in range(ft.k // 2):
                for hst in range(ft.k // 2):
                    ft.addLink('edge{}{}'.format(pod + 1, edge + 1), 
                               'host{}{}{}'.format(pod + 1, edge + 1, hst + 1))



topos = { 'fattreetopo': ( lambda: FatTree() ) }