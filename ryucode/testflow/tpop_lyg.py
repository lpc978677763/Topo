#!/usr/bin/python
"""
This is the most simple example to showcase Containernet.
"""
from mininet.net import Containernet
from mininet.node import CPULimitedHost
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
setLogLevel('info')

net = Containernet(host=CPULimitedHost,link=TCLink,controller=Controller)
info('*** Adding controller\n')
net.addController(name='c0', controller=RemoteController, ip='127.0.0.1', port=6633)
info('*** Adding docker containers\n')
h1 = net.addDocker('h1', mac='00:00:00:00:00:01',dimage="ubuntu:trusty")
h2 = net.addDocker('h2', mac='00:00:00:00:00:02',dimage="ubuntu:trusty")
h3 = net.addDocker('h3', mac='00:00:00:00:00:03',dimage="ubuntu:trusty")
h4 = net.addDocker('h4', mac='00:00:00:00:00:04',dimage="ubuntu:trusty")
h5 = net.addDocker('h5', mac='00:00:00:00:00:05',dimage="ubuntu:trusty")
h6 = net.addDocker('h6', mac='00:00:00:00:00:06',dimage="ubuntu:trusty")
h7 = net.addDocker('h7', mac='00:00:00:00:00:07',dimage="ubuntu:trusty")
h8 = net.addDocker('h8', mac='00:00:00:00:00:01',dimage="ubuntu:trusty")
info('*** Adding switches\n')
s1 = net.addSwitch( 's1', dpid='0000000000000001', protocols=["OpenFlow13"])
s2 = net.addSwitch( 's2', dpid='0000000000000002', protocols=["OpenFlow13"])
s3 = net.addSwitch( 's3', dpid='0000000000000003', protocols=["OpenFlow13"])
s4 = net.addSwitch( 's4', dpid='0000000000000004', protocols=["OpenFlow13"])
s5 = net.addSwitch( 's5', dpid='0000000000000005', protocols=["OpenFlow13"])
s6 = net.addSwitch( 's6', dpid='0000000000000006', protocols=["OpenFlow13"])
s7 = net.addSwitch( 's7', dpid='0000000000000007', protocols=["OpenFlow13"])
s8 = net.addSwitch( 's8', dpid='0000000000000008', protocols=["OpenFlow13"])
s9 = net.addSwitch( 's9', dpid='0000000000000009', protocols=["OpenFlow13"])
s10 = net.addSwitch( 's10', dpid='000000000000000A', protocols=["OpenFlow13"])
info('*** Creating links\n')
net.addLink( s1, h1, 1 )
net.addLink( s1, h2, 2 )
net.addLink( s2, h3, 1 )
net.addLink( s2, h4, 2 )
net.addLink( s3, h5, 1 )
net.addLink( s3, h6, 2 )
net.addLink( s4, h7, 1 )
net.addLink( s4, h8, 2 )

net.addLink( s1, s5, 3, 1 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s1, s6, 4, 1 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s1, s7, 5, 1 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s1, s8, 6, 1 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)

net.addLink( s2, s5, 3, 2 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s2, s6, 4, 2 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s2, s7, 5, 2 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s2, s8, 6, 2 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)

net.addLink( s3, s5, 3, 3 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s3, s6, 4, 3 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s3, s7, 5, 3 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s3, s8, 6, 3 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)

net.addLink( s4, s5, 3, 4 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s4, s6, 4, 4 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s4, s7, 5, 4 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s4, s8, 6, 4 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)

net.addLink( s9, s5, 1, 5 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s9, s6, 2, 5 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s9, s7, 3, 5 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s9, s8, 4, 5 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)

net.addLink( s10, s5, 1, 6 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s10, s6, 2, 6 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s10, s7, 3, 6 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
net.addLink( s10, s8, 4, 6 ,bw=1,delay='2ms',max_queue_size=100,loss=0,use_htb=True)
info('*** Starting network\n')
net.start()
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()

