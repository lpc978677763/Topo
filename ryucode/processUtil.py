from ryu.base import app_manager
from ryu.controller import ofp_event
#from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types as ether
from ryu.lib.packet import arp
from ryu.lib.packet.arp import arp,arp_ip
from ryu.lib.packet.arp import ARP_REQUEST,ARP_REV_REQUEST,ARP_REPLY,ARP_REV_REPLY
import csv
import time
import datetime
from operator import attrgetter
from threading import Thread,Lock
from math import exp,log,log10
import random

#32*4=128             128/(310+128)=28.6%
stableEnergyNode=310
sleepEnergyNode=240
stableEnergyLink=2
maxDynamicEnergy=2
a=0.5#now is useless
c0=0.01# denominator is not 0
m=3#3 times to sleep

maxValue=0x3fffffff
cookieid=0x01#start cookie id meaningful
checkpoint=0
i_timeout=5
h_timeout=100
minInterval=1
maxInterval=20

lowThreshold=0.05
highThreshold=0.8

varThreshold=0.2#sighop parameter

# best parameters
lowTimeout=4
highTimeout=2
life=5

mpath=4
alpha=0.5
beta=0.5

itK=4

#adaptive change  poll interval
def getNewInterval(oldbw,newbw,oldInterval):
	#return 2
	dtbw=abs(oldbw-newbw)
	interval=oldInterval
	if(dtbw<=0.001):
		interval=min(oldInterval+1,maxInterval)
	elif(oldbw<=0.001):
		interval=max(int(oldInterval/2),minInterval)
	elif(dtbw*1.0/oldbw<=0.03):
		interval=min(oldInterval+1,maxInterval)
	elif(0.03<dtbw*1.0/oldbw<=0.1):
		pass
	elif(0.1<dtbw*1.0/oldbw<=1):#if variable ratio is 0.3, new_interval=old_interval/3
		interval=max(int(oldInterval/(10.0*dtbw/oldbw)),minInterval)
	else:
		interval=max(int(oldInterval/10.0),minInterval)
	#print oldbw,' ',newbw,' ',dtbw,' ',oldInterval,' ',interval
	return interval
#arp reply message sent
def receiveARP(hosts,datapath,pkt,eth_pkt,in_port):
	arpPKT=pkt.get_protocol(arp)
	if(arpPKT.opcode==ARP_REQUEST or arpPKT.opcode==ARP_REV_REQUEST):
		dst=arpPKT.src_ip
		dstMAC=hosts[dst].mac
		src=arpPKT.dst_ip
		srcMAC=hosts[src].mac
		opcode=0
		if(arpPKT.opcode==ARP_REQUEST):
			opcode=ARP_REPLY
		else:
			opcode=ARP_REV_REPLY
		e=ethernet.ethernet(dstMAC,srcMAC,ether.ETH_TYPE_ARP)
		a=arp_ip(opcode,srcMAC,src,dstMAC,dst)
		p=packet.Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()
		actions=[datapath.ofproto_parser.OFPActionOutput(in_port)]
		out=datapath.ofproto_parser.OFPPacketOut(datapath=datapath,\
			buffer_id=datapath.ofproto.OFP_NO_BUFFER,\
			in_port=datapath.ofproto.OFPP_CONTROLLER,\
			actions=actions,data=p.data)
		return out
	else:return None

class CoreEdge():
	def __init__(self,line,ID,direct):
		self.id=ID
		#direct==1 a--->b    ,direct==-1 b----->a
		if(direct==1):
			self.sdpid=int(line[1])
			self.tdpid=int(line[2])
			self.sport=int(line[3])
			self.tport=int(line[4])
		else:
			self.sdpid=int(line[2])
			self.tdpid=int(line[1])
			self.sport=int(line[4])
			self.tport=int(line[3])
		self.ratio=int(line[7])
		self.bw=int(line[5])
		self.rw=int(line[6])
		self.capacity=int(line[11])
		self.delay=int(line[8])
		self.favor=float(line[10])
		#-1 sleep,  1  active,   
		self.state=int(line[9])
		self.lowcount=0
		self.highcount=0
		self.attr='core'
		self.llife=-1
		self.hlife=-1
		self.flowset=set()
		self.other=0
class Edge():
	def __init__(self,line,ID):
		self.id=ID
		self.sdpid=int(line[1])
		self.hostIP=line[2]
		self.sport=int(line[3])
		self.ratio=int(line[6])
		self.bw=int(line[4])
		self.rw=int(line[5])
		self.favor=1.0
		self.capacity=int(line[10])
		self.delay=int(line[7])
		#-1 sleep,  1  active,   
		self.state=-1
		self.life=lowTimeout
		self.attr='edge'
		self.other=0
class Host():
	def __init__(self,line):
		self.ip=line[1]
		self.mac=line[2]
		self.tport=int(line[4])
		self.tdpid=int(line[3])
		self.other=0
class Node():
	def __init__(self,dpid,datapath):
		self.dpid=dpid
		self.datapath=datapath
		#-1 sleep,  1  active,   
		self.state=-1
		#core    edge
		#self.attr='core'
		#all links from node
		self.linkset=set()
class Flow():
	def __init__(self,cookie,_flow):
		self.cookie=cookie
		self.path=_flow['path']
		self.edge=_flow['edge']
		self.lastdpid=_flow['lastDpid']
		self.check=_flow['check']
		self.src=_flow['src']
		self.dst=_flow['dst']
		self.fbytes=_flow['fbytes']
		self.mstimes=_flow['mstimes']
		self.interval=_flow['interval']
		self.bw=_flow['bw']
		self.match=_flow['match']
		self.lowmax=_flow['lowmax']
		self.highmax=_flow['highmax']
		self.other=0
		#lowmax means link ratio less than 5% max times