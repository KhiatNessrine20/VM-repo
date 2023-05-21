"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink
class MyTopo( Topo ):
  

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' , mac="00:00:00:00:00:01",  ip="10.0.0.1/24")
        h2 = self.addHost( 'h2' , mac="00:00:00:00:00:02", ip = "10.0.0.2/24")
        s1 = self.addSwitch ('s1')
        s2 = self.addSwitch ('s2')
        s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )
        

        # Add links
        self.addLink( h1, s1 )
        self.addLink( s1, s2 , bw = 1000)
        #self.addLink( s2, s3)
        self.addLink( s1, s3, bw = 1000 )
        self.addLink( s2, s4, bw = 1000)
        self.addLink( s3, s4, bw = 1000)
        self.addLink( s4, h2 )


topos = { 'mytopo': ( lambda: MyTopo() ) }
