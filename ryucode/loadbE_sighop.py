# -*- coding: utf-8 -*-
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
import copy
import time
import datetime
from operator import attrgetter
from threading import Thread,Lock
from math import exp,log,log10,sqrt
import random
from processUtil import *
import md5

class ExampleSwitch13(app_manager.RyuApp):
	OFP_VERSION=[ofproto_v1_3.OFP_VERSION]
#	_CONTEXTS={'dpset':dpset.DPSet}

	def __init__(self,*args,**kwargs):
		super(ExampleSwitch13,self).__init__(*args,**kwargs)
		self.datapaths={}
		self.core_links={}
		self.edge_links={}
		self.edgeNum={'active':0,'all':0}
		#self.nodes{}
		self.hosts={}
		self.flows={}
		self.checks={}
		self.path=[]
		self.subpaths={}
		self.energyTotal=0.0
		self.topoFile='/home/luyg/ryucode/topo/topo-10sw-dc.csv'
#		self.dpset=kwargs['dpset']
		self.readTopo(self.topoFile)
		self.initPath()
		self.monitor_thread=hub.spawn(self._monitor)
		self.draw_thread=hub.spawn(self._record)
		self.ftime=time.strftime('%Y-%m-%d %X',time.localtime())
	@set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
	def _state_change_handler(self, ev):
		datapath=ev.datapath
		if(ev.state==MAIN_DISPATCHER):
			if(self.datapaths[datapath.id].datapath == None):
				self.logger.info('register datapath:%016x', datapath.id)
				self.datapaths[datapath.id].datapath=datapath
		elif(ev.state==DEAD_DISPATCHER):
			if(datapath.id in self.datapaths):
				self.logger.info('unregister datapath:%016x',datapath.id)
				del self.datapaths[datapath.id]
#			hub.kill(self.monitor_thread)
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, \
				ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
	#---------------------------------------------bandwidth error---------------------------
	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def _flow_stats_reply_handler(self, ev):
		body = ev.msg.body
		print 'flow_stats_reply'
		datapath=ev.msg.datapath	
		for stat in sorted([flow for flow in body if flow.priority == 1],\
				key=lambda flow: (flow.match['eth_src'],flow.match['eth_dst'])):
			f=self.flows[stat.cookie]
			if(f.lastdpid==datapath.id):
#				calc bandwidth(kbit/s)   millis = time.time() * 1000
				millis=stat.duration_sec*1000.0+stat.duration_nsec/1000000.0
				oldbw=f.bw
				newbw=oldbw
				if(millis!=f.mstimes):
					newbw=(stat.byte_count-f.fbytes)*8.0/(millis-f.mstimes)
#				print stat.byte_count,'-',self.flows[stat.cookie]['fbytes'],'=',bw
				f.bw=newbw
				self.updateLinksRate(stat.cookie,True)
				f.interval=getNewInterval(oldbw,newbw,f.interval)
				f.fbytes=stat.byte_count#mutex
				f.mstimes=millis
				self.logger.info('%08x %17s %17s %8d %8d %6.2fkbit/s %d',\
					stat.cookie,stat.match['eth_src'], \
					stat.match['eth_dst'],stat.packet_count, stat.byte_count,newbw,millis)
				check=checkpoint+f.interval
				self._add_check(check,stat.cookie,f.lastdpid)
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		print 'packet in'
		msg = ev.msg
#		print dir(msg)
		datapath = msg.datapath
		inport=msg.match['in_port']
		dpid=datapath.id
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)
		_ipv4 = pkt.get_protocol(ipv4.ipv4)
		_icmp= pkt.get_protocol(icmp.icmp)
		if(eth):
			if(eth.ethertype==ether.ETH_TYPE_ARP):
				out=receiveARP(self.hosts,datapath,pkt,eth,inport)
				if(out!=None):datapath.send_msg(out)
				return
		src=''
		dst=''
		if(_ipv4):src,dst=_ipv4.src,_ipv4.dst
		if(src=='' or dst==''):return
		path=self.getPath(src,dst)
		path=tuple(path)
		print 'initial path:' ,src,dst,str(path)
		flow=self.addPathFlow(path,src,dst)
		outport=self.getOutport(datapath.id,flow)
		data=None
		actions = [parser.OFPActionOutput(outport)]
		if(msg.buffer_id == ofproto.OFP_NO_BUFFER):
			data=msg.data
		out= parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id,\
				in_port=inport, actions=actions, data=data)
		datapath.send_msg(out)
	@set_ev_cls(ofp_event.EventOFPFlowRemoved,MAIN_DISPATCHER)
	def flow_removed_handler(self,ev):
		#{check:[(cookie1,dpid),(cookie,dpid)]}
		msg=ev.msg
		datapath=msg.datapath
		cookie=msg.cookie
		print '--------------------------------flow remove:',cookie
		if(cookie not in self.flows.keys()):return
		lastdpid=self.flows[cookie].lastdpid
		for key in self.checks:
			if (cookie,lastdpid) in self.checks[key]:
				self.checks[key].remove((cookie,lastdpid))
				#break;
		if(cookie in self.flows.keys()):
			self.del_path(cookie,self.flows[cookie].path,newpath=None,flag=False)
			self.flows[cookie].bw=0.0
			self.updateLinksRate(cookie,False)
			flowtime=(msg.duration_sec-i_timeout)*1000+msg.duration_nsec/1000000.0
			obj=open('./ryucode/path/'+self.ftime+'.txt','a+')
			obj.writelines("del-flow:%08x %s %s %s %s  %s  %s %s\n" % (cookie,checkpoint,self.flows[cookie].src,self.flows[cookie].dst,self.flows[cookie].path,\
				msg.packet_count,flowtime,flowtime/msg.packet_count))
			obj.close()
			del self.flows[cookie]

	def readTopo(self, fileName):
		'''
			read topology file
		'''
		print 'readTopo'
		reader=csv.reader(file(fileName,'r'))
		for line in reader:
			#core links
			if(line[0]=='core'):
				dpid1,dpid2=int(line[1]),int(line[2])
				edgeID=line[1]+'>'+line[2]
				ce1=CoreEdge(line,edgeID,direct=1)
				if(edgeID not in self.core_links.keys()):
					self.core_links[edgeID]=ce1
				else:
					print 'ID has exist'
				if(dpid1 not in self.datapaths.keys()):
					self.datapaths[dpid1]=Node(dpid1,None)
					self.energyTotal+=stableEnergyNode
				self.datapaths[dpid1].linkset.add(edgeID)
				self.edgeNum['all']+=1

				edgeID=line[2]+'>'+line[1]
				ce2=CoreEdge(line,edgeID,direct=-1)
				if(edgeID not in self.core_links.keys()):
					self.core_links[edgeID]=ce2
				else:
					print 'ID has exist'
				if(dpid2 not in self.datapaths.keys()):
					self.datapaths[dpid2]=Node(dpid2,None)
					self.energyTotal+=stableEnergyNode
				self.datapaths[dpid2].linkset.add(edgeID)
				self.edgeNum['all']+=1
				self.energyTotal+=2*(maxDynamicEnergy)#max activelink
				self.energyTotal+=2*(stableEnergyLink)#
			#edge links
			elif(line[0]=='edge'):
				edgeID=line[1]+'>'+line[2]
				e1=Edge(line,edgeID)
				dpid3=int(line[1])
				if(edgeID not in self.edge_links.keys()):
					self.edge_links[edgeID]=e1
				else:
					print 'ID has exist'
				if(dpid3 not in self.datapaths.keys()):
					self.datapaths[dpid3]=Node(dpid3,None)
				self.datapaths[dpid3].linkset.add(edgeID)
			#host
			elif('host' in line[0]):
				h1=Host(line)
				if(h1.ip not in self.hosts.keys()):
					self.hosts[h1.ip]=h1
				else:
					print 'host'+h1.ip+' has exist!'
	def initPath(self):
		print 'initPath'
		'''
		paths=[[1,3,7],
		[1,2,5,7],
		[1,2,3,7],
		[1,3,5,7],
		[1,4,3,7],
		[1,4,6,7],
		[1,2,5,3,7],
		[1,2,3,5,7],
		[1,3,2,5,7],
		[1,3,4,6,7],
		[1,4,3,5,7],
		[1,2,3,4,6,7],
		[1,4,3,2,5,7]
		]
		subpaths={'1-2':[[1,3,2]],
		'1-3':[[1,2,3],[1,4,3],[1,2,5,3]],
		'1-4':[[1,3,4]],
		'2-3':[[2,5,3]],
		'2-5':[[2,3,5]],
		'3-5':[[3,2,5]],
		'3-7':[[3,5,7],[3,2,5,7],[3,4,6,7]]
		}
		'''
		paths={
		'1-2':[(1,5,2),(1,6,2),(1,7,2),(1,8,2),(1,5,9,6,2),(1,5,9,7,2),(1,5,9,8,2),(1,5,10,6,2),(1,5,10,7,2),(1,5,10,8,2),(1,6,9,7,2),(1,6,9,8,2),(1,7,9,8,2),(1,6,10,7,2),(1,6,10,8,2),(1,7,10,8,2)
		],
		'1-3':[(1,5,3),(1,6,3),(1,7,3),(1,8,3),(1,5,9,6,3),(1,5,9,7,3),(1,5,9,8,3),(1,5,10,6,3),(1,5,10,7,3),(1,5,10,8,3),(1,6,9,7,3),(1,6,9,8,3),(1,7,9,8,3),(1,6,10,7,3),(1,6,10,8,3),(1,7,10,8,3)
		],
		'1-4':[(1,5,4),(1,6,4),(1,7,4),(1,8,4),(1,5,9,6,4),(1,5,9,7,4),(1,5,9,8,4),(1,5,10,6,4),(1,5,10,7,4),(1,5,10,8,4),(1,6,9,7,4),(1,6,9,8,4),(1,7,9,8,4),(1,6,10,7,4),(1,6,10,8,4),(1,7,10,8,4)
		],
		'2-3':[(2,5,3),(2,6,3),(2,7,3),(2,8,3),(2,5,9,6,3),(2,5,9,7,3),(2,5,9,8,3),(2,5,10,6,3),(2,5,10,7,3),(2,5,10,8,3),(2,6,9,7,3),(2,6,9,8,3),(2,7,9,8,3),(2,6,10,7,3),(2,6,10,8,3),(2,7,10,8,3)
		],
		'2-4':[(2,5,4),(2,6,4),(2,7,4),(2,8,4),(2,5,9,6,4),(2,5,9,7,4),(2,5,9,8,4),(2,5,10,6,4),(2,5,10,7,4),(2,5,10,8,4),(2,6,9,7,4),(2,6,9,8,4),(2,7,9,8,4),(2,6,10,7,4),(2,6,10,8,4),(2,7,10,8,4)
		],
		'3-4':[(3,5,4),(3,6,4),(3,7,4),(3,8,4),(3,5,9,6,4),(3,5,9,7,4),(3,5,9,8,4),(3,5,10,6,4),(3,5,10,7,4),(3,5,10,8,4),(3,6,9,7,4),(3,6,9,8,4),(3,7,9,8,4),(3,6,10,7,4),(3,6,10,8,4),(3,7,10,8,4)
		]
		}
		subpaths={
		'1-5':[(1,6,2,5),(1,6,3,5),(1,6,4,5),(1,6,9,5),(1,6,10,5),(1,7,2,5),(1,7,3,5),(1,7,4,5),(1,7,9,5),(1,7,10,5),(1,8,2,5),(1,8,3,5),(1,8,4,5),(1,8,9,5),(1,8,10,5)
		],
		'1-6':[(1,5,2,6),(1,5,3,6),(1,5,4,6),(1,5,9,6),(1,5,10,6),(1,7,2,6),(1,7,3,6),(1,7,4,6),(1,7,9,6),(1,7,10,6),(1,8,2,6),(1,8,3,6),(1,8,4,6),(1,8,9,6),(1,8,10,6)
		],
		'1-7':[(1,5,2,7),(1,5,3,7),(1,5,4,7),(1,5,9,7),(1,5,10,7),(1,6,2,7),(1,6,3,7),(1,6,4,7),(1,6,9,7),(1,6,10,7),(1,8,2,7),(1,8,3,7),(1,8,4,7),(1,8,9,7),(1,8,10,7)
		],
		'1-8':[(1,5,2,8),(1,5,3,8),(1,5,4,8),(1,5,9,8),(1,5,10,8),(1,6,2,8),(1,6,3,8),(1,6,4,8),(1,6,9,8),(1,6,10,8),(1,7,2,8),(1,7,3,8),(1,7,4,8),(1,7,9,8),(1,7,10,8)
		],
		#
		'2-5':[(2,6,1,5),(2,6,3,5),(2,6,4,5),(2,6,9,5),(2,6,10,5),(2,7,1,5),(2,7,3,5),(2,7,4,5),(2,7,9,5),(2,7,10,5),(2,8,1,5),(2,8,3,5),(2,8,4,5),(2,8,9,5),(2,8,10,5)
		],
		'2-6':[(2,5,1,6),(2,5,3,6),(2,5,4,6),(2,5,9,6),(2,5,10,6),(2,7,1,6),(2,7,3,6),(2,7,4,6),(2,7,9,6),(2,7,10,6),(2,8,1,6),(2,8,3,6),(2,8,4,6),(2,8,9,6),(2,8,10,6)
		],
		'2-7':[(2,5,1,7),(2,5,3,7),(2,5,4,7),(2,5,9,7),(2,5,10,7),(2,6,1,7),(2,6,3,7),(2,6,4,7),(2,6,9,7),(2,6,10,7),(2,8,1,7),(2,8,3,7),(2,8,4,7),(2,8,9,7),(2,8,10,7)
		],
		'2-8':[(2,5,1,8),(2,5,3,8),(2,5,4,8),(2,5,9,8),(2,5,10,8),(2,6,1,8),(2,6,3,8),(2,6,4,8),(2,6,9,8),(2,6,10,8),(2,7,1,8),(2,7,3,8),(2,7,4,8),(2,7,9,8),(2,7,10,8)
		],
		#
		'3-5':[(3,6,1,5),(3,6,2,5),(3,6,4,5),(3,6,9,5),(3,6,10,5),(3,7,1,5),(3,7,2,5),(3,7,4,5),(3,7,9,5),(3,7,10,5),(3,8,1,5),(3,8,2,5),(3,8,4,5),(3,8,9,5),(3,8,10,5)
		],
		'3-6':[(3,5,1,6),(3,5,2,6),(3,5,4,6),(3,5,9,6),(3,5,10,6),(3,7,1,6),(3,7,2,6),(3,7,4,6),(3,7,9,6),(3,7,10,6),(3,8,1,6),(3,8,2,6),(3,8,4,6),(3,8,9,6),(3,8,10,6)
		],
		'3-7':[(3,5,1,7),(3,5,2,7),(3,5,4,7),(3,5,9,7),(3,5,10,7),(3,6,1,7),(3,6,2,7),(3,6,4,7),(3,6,9,7),(3,6,10,7),(3,8,1,7),(3,8,2,7),(3,8,4,7),(3,8,9,7),(3,8,10,7)
		],
		'3-8':[(3,5,1,8),(3,5,2,8),(3,5,4,8),(3,5,9,8),(3,5,10,8),(3,6,1,8),(3,6,2,8),(3,6,4,8),(3,6,9,8),(3,6,10,8),(3,7,1,8),(3,7,2,8),(3,7,4,8),(3,7,9,8),(3,7,10,8)
		],
		#
		'4-5':[(4,6,1,5),(4,6,2,5),(4,6,3,5),(4,6,9,5),(4,6,10,5),(4,7,1,5),(4,7,2,5),(4,7,3,5),(4,7,9,5),(4,7,10,5),(4,8,1,5),(4,8,2,5),(4,8,3,5),(4,8,9,5),(4,8,10,5)
		],
		'4-6':[(4,5,1,6),(4,5,2,6),(4,5,3,6),(4,5,9,6),(4,5,10,6),(4,7,1,6),(4,7,2,6),(4,7,3,6),(4,7,9,6),(4,7,10,6),(4,8,1,6),(4,8,2,6),(4,8,3,6),(4,8,9,6),(4,8,10,6)
		],
		'4-7':[(4,5,1,7),(4,5,2,7),(4,5,3,7),(4,5,9,7),(4,5,10,7),(4,6,1,7),(4,6,2,7),(4,6,3,7),(4,6,9,7),(4,6,10,7),(4,8,1,7),(4,8,2,7),(4,8,3,7),(4,8,9,7),(4,8,10,7)
		],
		'4-8':[(4,5,1,8),(4,5,2,8),(4,5,3,8),(4,5,9,8),(4,5,10,8),(4,6,1,8),(4,6,2,8),(4,6,3,8),(4,6,9,8),(4,6,10,8),(4,7,1,8),(4,7,2,8),(4,7,3,8),(4,7,9,8),(4,7,10,8)
		],
		#
		'5-9':[(5,1,6,9),(5,2,6,9),(5,3,6,9),(5,4,6,9),(5,10,6,9),(5,1,7,9),(5,2,7,9),(5,3,7,9),(5,4,7,9),(5,10,7,9),(5,1,8,9),(5,2,8,9),(5,3,8,9),(5,4,8,9),(5,10,8,9)
		],
		'6-9':[(6,1,5,9),(6,2,5,9),(6,3,5,9),(6,4,5,9),(6,10,5,9),(6,1,7,9),(6,2,7,9),(6,3,7,9),(6,4,7,9),(6,10,7,9),(6,1,8,9),(6,2,8,9),(6,3,8,9),(6,4,8,9),(6,10,8,9)
		],
		'7-9':[(7,1,5,9),(7,2,5,9),(7,3,5,9),(7,4,5,9),(7,10,5,9),(7,1,6,9),(7,2,6,9),(7,3,6,9),(7,4,6,9),(7,10,6,9),(7,1,8,9),(7,2,8,9),(7,3,8,9),(7,4,8,9),(7,10,8,9)
		],
		'8-9':[(8,1,5,9),(8,2,5,9),(8,3,5,9),(8,4,5,9),(8,10,5,9),(8,1,6,9),(8,2,6,9),(8,3,6,9),(8,4,6,9),(8,10,6,9),(8,1,7,9),(8,2,7,9),(8,3,7,9),(8,4,7,9),(8,10,7,9)
		],
		#
		'5-10':[(5,1,6,10),(5,2,6,10),(5,3,6,10),(5,4,6,10),(5,9,6,10),(5,1,7,10),(5,2,7,10),(5,3,7,10),(5,4,7,10),(5,9,7,10),(5,1,8,10),(5,2,8,10),(5,3,8,10),(5,4,8,10),(5,9,8,10)
		],
		'6-10':[(6,1,5,10),(6,2,5,10),(6,3,5,10),(6,4,5,10),(6,9,5,10),(6,1,7,10),(6,2,7,10),(6,3,7,10),(6,4,7,10),(6,9,7,10),(6,1,8,10),(6,2,8,10),(6,3,8,10),(6,4,8,10),(6,9,8,10)
		],
		'7-10':[(7,1,5,10),(7,2,5,10),(7,3,5,10),(7,4,5,10),(7,9,5,10),(7,1,6,10),(7,2,6,10),(7,3,6,10),(7,4,6,10),(7,9,6,10),(7,1,8,10),(7,2,8,10),(7,3,8,10),(7,4,8,10),(7,9,8,10)
		],
		'8-10':[(8,1,5,10),(8,2,5,10),(8,3,5,10),(8,4,5,10),(8,9,5,10),(8,1,6,10),(8,2,6,10),(8,3,6,10),(8,4,6,10),(8,9,6,10),(8,1,7,10),(8,2,7,10),(8,3,7,10),(8,4,7,10),(8,9,7,10)
		]
		}
		self.paths=paths
		self.subpaths=subpaths
		print self.paths
	def _monitor(self):
		global checkpoint
		while(True):
			#hub.sleep(10)
			hub.sleep(1)
			checkpoint+=1
			print checkpoint,':',self.checks
			if(len(self.checks)==0):
				self.flows.clear()
				self.updateLinksRate0()
				continue
			if(checkpoint in self.checks.keys()):
				for flow in self.checks[checkpoint]:
					#flow(cookie,lastDpid)
					self._request_stats(datapath=self.datapaths[flow[1]].datapath,\
							cookie=flow[0])
#					print int(round(time.time() * 1000))
				del self.checks[checkpoint]
	def _record(self):
		obj=open('./ryucode/log/'+self.ftime+'.txt','w+')
		cnt=checkpoint
		while(True):
			y0_new,y1_new,y2_new,y3_new=self.get_load_energy()
			y4_new=0.0
			y5_new=0.0
			if(abs(y0_new-0)<0.0001):y0_new=0
			if(abs(y1_new-0)<0.0001):y1_new=0
			if(abs(y2_new-0)<0.0001):y2_new=0
			if(abs(y3_new-0)<0.0001):y3_new=0
			if(y2_new>0):y4_new=y3_new/y2_new*1.0
			y5_new=1.0-y2_new/self.energyTotal
			obj.writelines("%s %s %s %s %s %s %s\n" % (cnt,y0_new,y1_new,y2_new,y3_new,y4_new,y5_new))
			hub.sleep(1)
			cnt+=1
		obj.close()
	def _request_stats(self, datapath,cookie=0x00):
		#self.logger.debug('send stats request: %016x', datapath.id)
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match=self.flows[cookie].match
		req = parser.OFPFlowStatsRequest(datapath=datapath,match=match,cookie=cookie)
		datapath.send_msg(req)
	def _add_check(self,check,cookie,lastdpid):
		if(check not in self.checks.keys()):
			self.checks[check]=[]
		if((cookie,lastdpid) not in self.checks[check]):
			self.checks[check].append((cookie,lastdpid))

	def add_flow(self, datapath, priority, match, actions,cookie=0x00,\
			i_timeout=0,h_timeout=0,flags=0,buffer_id=None):
		#print "add-flows:",datapath.id
		#cookie_mask=cookie_mask,
		cookie_mask=0xffffffff
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		if(buffer_id):
			mod = parser.OFPFlowMod(cookie=cookie,cookie_mask=cookie_mask,datapath =datapath,\
					idle_timeout=i_timeout,hard_timeout=h_timeout,\
					flags=flags,buffer_id=buffer_id,priority=priority,\
					match = match, instructions = inst)
		else:
			mod = parser.OFPFlowMod(cookie=cookie,cookie_mask=cookie_mask,datapath=datapath,\
					idle_timeout=i_timeout,hard_timeout=h_timeout,\
					flags=flags,priority=priority, match=match, instructions=inst)
		#print mod
		datapath.send_msg(mod)
	def del_flow(self, cookie,dpid):
		print 'del_flow'
		#del flow entry in every switch
		print '*********ryu remove flow***********'
		path=self.flows[cookie].path
		match=self.flows[cookie].match
		datapath=self.datapaths[dpid].datapath
		parser = datapath.ofproto_parser
		ofproto = datapath.ofproto
		mod = parser.OFPFlowMod(datapath=datapath,
				cookie=cookie,
				cookie_mask=0xffffffff,
				command=ofproto.OFPFC_DELETE,
				out_port=ofproto.OFPP_ANY,
				#out_port=outport,
				out_group=ofproto.OFPG_ANY,
				match=match)
		datapath.send_msg(mod)
	def modify_flow(self,cookie,dpid,actions):
		print 'modify_flow'
		#del flow entry in every switch
		print '*********ryu modify flow***********'
		datapath=self.datapaths[dpid].datapath
		match=self.flows[cookie].match
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=datapath,
			cookie=cookie,
			cookie_mask=0xffffffff,
			command=ofproto.OFPFC_MODIFY,
			out_port=ofproto.OFPP_ANY,
			#out_port=outport,
			out_group=ofproto.OFPG_ANY,
			match=match,
			instructions = inst)
		datapath.send_msg(mod)
	#------------------------------------------------------------remove oldbw newbw------------------
	def updateLinksRate(self,cookie,eventFlag):
		print 'updateLinksRate',cookie,self.flows[cookie].path
		f=self.flows[cookie]
		print '++++++++++++++++',self.flows.keys(),'+++++++++++++++++++++'
		if(len(f.path)<1):return None
		lowFlows=[]
		highFlows=[]
		for key in f.edge:
			if(key not in self.core_links.keys()):continue
			edge=self.core_links[key]
			edge.bw=0
			for flowkey in edge.flowset:
				if(flowkey in self.flows.keys()):edge.bw+=self.flows[flowkey].bw
				else:edge.flowset.remove(flowkey)
			if(edge.bw>edge.capacity):edge.bw=edge.capacity
			if(edge.bw<0.0):edge.bw=0.0
			edge.rw=edge.capacity-edge.bw
			edge.ratio=edge.bw*1.0/edge.capacity
			print 'link %s   bw:%.2f  rw:%.2f   ratio:%.2f%%	state:%d  	llife:%d   	hlife:%d' \
					% (edge.id,edge.bw,edge.rw,100*edge.ratio,edge.state,edge.llife,edge.hlife)
			
			
		for key in self.core_links.keys():
			edge=self.core_links[key]
			if(edge.ratio>=highThreshold):
				edge.hlife-=1
			else:edge.hlife=highTimeout
			if(edge.hlife<0):
				#schedule high flow
				self.scheduleFlows(edge.ratio,varhigh=False)
				break
		var=0
		mean=0.0
		activelink=0
		for key in self.core_links.keys():
			if(self.core_links[key].state>-1):
				mean+=self.core_links[key].ratio
				if(self.core_links[key].ratio>0.0):
					activelink+=1
		if(activelink>0):
			mean/=activelink
			for key in self.core_links.keys():
				if(self.core_links[key].state>-1 and self.core_links[key].ratio>0.0):
					var+=(self.core_links[key].ratio-mean)*(self.core_links[key].ratio-mean)
			var/=activelink
			var=sqrt(var)
			if(var>varThreshold):
				self.scheduleFlows(var)
		for key in self.core_links.keys():
			edge=self.core_links[key]
			cokey=str(edge.tdpid)+'>'+str(edge.sdpid)
			coedge=self.core_links[cokey]
			#close link node
			if(edge.ratio<0.00001):
				edge.llife-=1
			else:edge.llife=lowTimeout
			
			if(coedge.ratio<0.00001):
				coedge.llife-=1
			else:coedge.llife=lowTimeout
			
			if(edge.llife<0 and coedge.llife<0):
				lowFlows+=list(edge.flowset)
				lowFlows+=list(coedge.flowset)
				if(cookie in edge.flowset):edge.flowset.remove(cookie)
			if(len(edge.flowset)==0 and len(coedge.flowset)==0):
				#close link
				edge.state=-1
				edge.favor=0.5
				edge.rw=edge.capacity
				edge.bw=0
				edge.ratio=0.0
				edge.llife=-1
				edge.hlife=-1
				edge.flowset=set()

				coedge.state=-1
				coedge.favor=0.5
				coedge.rw=edge.capacity
				coedge.bw=0
				coedge.ratio=0.0
				coedge.llife=-1
				coedge.hlife=-1
				coedge.flowset=set()

				u=edge.sdpid
				v=edge.tdpid
				#close node u
				flag=True
				for linkid in self.datapaths[u].linkset:
					if((linkid in self.core_links.keys()) and  (self.core_links[linkid].state==1)):
						flag=False
						break
				if(flag==True):self.datapaths[u].state=-1
				#close node v
				flag=True
				for linkid in self.datapaths[v].linkset:
					if((linkid in self.core_links.keys()) and  (self.core_links[linkid].state==1)):
						flag=False
						break
				if(flag==True):self.datapaths[v].state=-1
		for nd in self.datapaths.keys():
			print nd,':',self.datapaths[nd].state,',' ,
		print '\n'
		
	def updateLinksRate0(self):
		print 'updateLinksRate0'
		print '++++++++++++++++',0000,'+++++++++++++++++++++'
		for key in self.core_links.keys():
			#if(self.core_links[key].state!=1):continue
			edge=self.core_links[key]
			cokey=str(edge.tdpid)+'>'+str(edge.sdpid)
			coedge=self.core_links[cokey]
			#print edge.id,edge.state,edge.llife
			#print coedge.id,coedge.state,coedge.llife
			if(self.core_links[key].state==1):
				edge.llife-=1
			if(self.core_links[cokey].state==1):
				coedge.llife-=1
			if(edge.llife<0 and coedge.llife<0):
				#close link
				edge.state=-1
				edge.favor=0.5
				edge.rw=edge.capacity
				edge.bw=0
				edge.ratio=0.0
				edge.llife=-1
				edge.hlife=-1
				edge.flowset=set()

				coedge.state=-1
				coedge.favor=0.5
				coedge.rw=edge.capacity
				coedge.bw=0
				coedge.ratio=0.0
				coedge.llife=-1
				coedge.hlife=-1
				coedge.flowset=set()
			if(edge.state<0 and coedge.state<0):
				u=edge.sdpid
				v=edge.tdpid
				#close node u
				flag=True
				for linkid in self.datapaths[u].linkset:
					if((linkid in self.core_links.keys()) and  (self.core_links[linkid].state==1)):
						flag=False
						break
				if(flag==True):self.datapaths[u].state=-1
				#close node v
				flag=True
				for linkid in self.datapaths[v].linkset:
					if((linkid in self.core_links.keys()) and  (self.core_links[linkid].state==1)):
						flag=False
						break
				if(flag==True):self.datapaths[v].state=-1
		for nd in self.datapaths.keys():
			print nd,':',self.datapaths[nd].state,',' ,
		print '\n'
	#------------------------------------------------------------------flow.path  addPathFlow------------------------------
	def change_path(self,cookie,oldpath,newpath,src,dst):
		print 'change path:',cookie,oldpath,newpath
		if(oldpath==newpath):return
		i=len(newpath)-2
		flowedge=set()
		while(i>=0):
			u=newpath[i]
			v=newpath[i+1]
			key=str(u)+'>'+str(v)
			flowedge.add(key)
			edge=self.core_links[key]
			edge.flowset.add(cookie)
			edge.llife=lowTimeout
			edge.hlife=highTimeout
			edge.bw+=self.flows[cookie].bw
			if(edge.bw>edge.capacity):edge.bw=edge.capacity
			if(edge.bw<0.0):edge.bw=0.0
			edge.rw=edge.capacity-edge.bw
			edge.ratio=edge.bw*1.0/edge.capacity
			if(edge.state==-1):edge.state=1
			cokey=str(v)+'>'+str(u)
			if(self.core_links[cokey].state==-1):
				self.core_links[cokey].state=1
				self.core_links[cokey].llife=lowTimeout
				self.core_links[cokey].hlife=highTimeout
			self.datapaths[u].state=1
			out_port=self.core_links[key].sport
			parser=self.datapaths[u].datapath.ofproto_parser
			actions=[parser.OFPActionOutput(out_port,0)]
			match = self.flows[cookie].match
			flags=0
			if(u not in oldpath):
				print 'add_flow:',key
				self.add_flow(self.datapaths[u].datapath,1,match,actions,cookie,i_timeout,h_timeout,flags)
			else:
				j=oldpath.index(u)
				if(j>=len(oldpath)-1 or oldpath[j+1]!=v):
					self.modify_flow(cookie,u,actions)
					mkey=str(oldpath[j])+'>'+str(oldpath[j+1])
					medge=self.core_links[mkey]
					medge.bw-=self.flows[cookie].bw
					if(medge.bw>medge.capacity):medge.bw=medge.capacity
					if(medge.bw<0.0):medge.bw=0.0
					medge.rw=medge.capacity-medge.bw
					medge.ratio=medge.bw*1.0/medge.capacity
			i-=1
		self.del_path(cookie,oldpath,newpath,True)
		self.flows[cookie].path=newpath
		self.flows[cookie].edge=flowedge
		obj=open('./ryucode/path/'+self.ftime+'.txt','a+')
		obj.writelines("change-flow:%08x %s %s %s %s %s\n" % (cookie,checkpoint,src,dst,oldpath,newpath))
		obj.close()
		pass
	#-------------------------------------------------------------------------------------------------------
	def del_path(self,cookie,oldpath,newpath=None,flag=True):
		print 'del path'
		for i in range(0,len(oldpath)-1):
			u=oldpath[i]
			v=oldpath[i+1]
			key=str(u)+'>'+str(v)
			edge=self.core_links[key]
			if(cookie in edge.flowset):edge.flowset.remove(cookie)
			if(flag==True and u not in newpath):
				print 'del_flow:',key
				self.del_flow(cookie,u)
				edge.bw-=self.flows[cookie].bw
				if(edge.bw>edge.capacity):edge.bw=edge.capacity
				if(edge.bw<0.0):edge.bw=0.0
				edge.rw=edge.capacity-edge.bw
				edge.ratio=edge.bw*1.0/edge.capacity
		pass
	def get_load_energy(self):
		load_sum=0
		cnt=0
		mean=0
		load_var=0
		energy=0
		throughput=0
		for dpid in self.datapaths.keys():
			#print dpid,self.datapaths[dpid].state
			if(self.datapaths[dpid].state>-1):
				energy+=stableEnergyNode
			else:
				energy+=sleepEnergyNode
		for key in self.core_links.keys():
			#print key,self.core_links[key].state,self.core_links[key].llife
			if(self.core_links[key].state>-1):
				energy+=stableEnergyLink
				energy+=self.core_links[key].ratio*maxDynamicEnergy
				load_sum+=self.core_links[key].ratio
				if(self.core_links[key].ratio>0.0):cnt+=1
		if(cnt==0):
			load_sum=0
			load_var=0
			return mean,load_var,energy,throughput
		mean=load_sum*1.0/cnt
		load_sum=0
		for key in self.core_links.keys():
			if(self.core_links[key].state>-1 and self.core_links[key].ratio>0.0):
				load_sum+=(self.core_links[key].ratio-mean)*(self.core_links[key].ratio-mean)
		load_var=sqrt(load_sum*1.0/cnt)
		for cookie in self.flows.keys():
			throughput+=self.flows[cookie].bw
		return mean,load_var,energy,throughput
	
	def scheduleFlows(self,value,varhigh=True):
		print 'scheduleFlows'
		maxit=8#max iterator 8 times
		k=0
		threshold=0
		cur=value
		if(varhigh==True):
			threshold=varThreshold
		else:
			threshold=highThreshold
		while(k<maxit and cur>threshold):
			maxkey=''
			maxratio=0
			#find the busiest link
			for key in self.core_links.keys():
				if(self.core_links[key].state>-1 and self.core_links[key].ratio>maxratio):
					maxratio=self.core_links[key].ratio
					maxkey=key
			edge=self.core_links[maxkey]
			#find the max flow
			maxbw=0
			maxflow=''
			for cookie in edge.flowset:
				if(self.flows[cookie].bw>maxbw):
					maxbw=self.flows[cookie].bw
					maxflow=cookie
			#find the light substitute path
			src=self.flows[maxflow].src
			dst=self.flows[maxflow].dst
			subpaths=copy.deepcopy(self.subpaths)
			s=self.hosts[src].tdpid
			t=self.hosts[dst].tdpid
			items=maxkey.split('>')
			comaxkey=str(items[1])+'>'+str(items[0])
			path=[]
			if(maxkey in subpaths.keys() or comaxkey in subpaths.keys()):
				p1=self.flows[maxflow].path
				paths=[]
				maxremin=0.0
				maxrepath=[]
				if(maxkey in subpaths.keys()):paths=subpaths[maxkey]
				else:paths=subpaths[comaxkey]
				for p2 in paths:
					if(maxkey not in subpaths.keys()):
						p2.reverse()
					p3=[]
					for i in range(len(p1)):
						if(p1[i]==items[0]):break
						p3+=p1[i]
						i+=1
					p3+=p2
					idx=p1.index(items[1])
					for i in range(idx+1,len(p1)):
						p3+=p1[i]
						i+=1
					#check the path
					for i in range(1,len(p3)):
						if(p3[i] in p3[0:i]):
							p3=[]
							break
					if(len(p3)!=0):#p2 is right subpath
						remin=maxValue
						for j in range(1,len(p2)):
							u=p2[j-1]
							v=p2[j]
							lkey=str(u)+'>'+str(v)
							if(self.core_links[lkey].rw<remin):remin=self.core_links[lkey].rw
						if(remin>maxremin):
							maxremin=remin
							maxrepath=p3
				path=maxrepath
			if(len(path)==0):
				path=self.getPath(src,dst)
			oldpath=list(self.flows[maxflow].path)
			self.change_path(maxflow,oldpath,path,src,dst)
			cur=self.getmaxvar(varhigh)
			k+=1
			#update cur
	
	def getmaxvar(self,varhigh):
		print 'getmaxvar'
		ratio=0.0
		mean=0.0
		var=0.0
		activelink=0
		rmax=0.0
		for key in self.core_links.keys():
			edge=self.core_links[key]
			if(edge.state>-1 and edge.ratio>0.0):
				if(rmax<edge.ratio):rmax=edge.ratio
				mean+=edge.ratio
				activelink+=1
		if(varhigh!=True):return rmax
		if(activelink==0):return 0
		mean/=activelink
		for key in self.core_links.keys():
			edge=self.core_links[key]
			if(edge.state>-1 and edge.ratio>0.0):
				var+=(edge.ratio-mean)**2
		var/=activelink
		var=sqrt(var)
		return var
	
	def getPath(self,src,dst):
		print 'getPath',src,dst
		#global maxValue,m
		#print 'path computing:'
		s=self.hosts[src].tdpid
		t=self.hosts[dst].tdpid
		if(s==t):return [s]
		print s,t
		paths=[]
		key=str(s)+'-'+str(t)
		if(s>t):
			key=str(t)+'-'+str(s)
		paths=copy.deepcopy(self.paths[key])
		maxpath=[]
		maxremin=0
		for p in paths:
			if(s>t):
				ls=list(p)
				ls.reverse()
				p=tuple(ls)
			remin=maxValue
			for i in range(1,len(p)):
				u=p[i-1]		
				v=p[i]
				key=str(u)+'>'+str(v)
				if(self.core_links[key].rw<remin):
					remin=self.core_links[key].rw
			if(maxremin<remin):
				maxremin=remin
				maxpath=p
		print maxpath,'\n'
		return maxpath
	def getOutport(self,dpid,flow):
		print 'getOutport'
		path=flow.path
		dst=flow.dst
		lenPath=len(path)
		if(lenPath==1):
			return self.hosts[dst].tport
		#print path
		i=path.index(dpid)
		outport=-1
		if(i<lenPath-1):
			u=path[i]
			v=path[i+1]
			key=str(u)+'>'+str(v)
			outport=self.core_links[key].sport
		elif(i==lenPath-1):
			outport=self.hosts[dst].tport
		return outport
	def addPathFlow(self,path,src,dst):
		print 'addPathFlow'
		global cookieid,checkpoint
		cookie=cookieid
		cookieid=cookieid+1
		#print 'addPathFlow:' 
		srcMAC=self.hosts[src].mac
		dstMAC=self.hosts[dst].mac
		lenPath=len(path)
		match=None
		if(lenPath==0):
			print 'path len is 0,Good Luck!'
			return
		for i in range(lenPath):
			u=path[i]
			outport=-1
			if(i<lenPath-1):
				key=str(u)+'>'+str(path[i+1])
				#change link and node state
				self.core_links[key].llife=lowTimeout
				self.core_links[key].hlife=highTimeout
				if(self.core_links[key].state==-1):self.core_links[key].state=1
				cokey=str(path[i+1])+'>'+str(u)
				if(self.core_links[cokey].state==-1):
					self.core_links[cokey].state=1
					self.core_links[cokey].llife=lowTimeout
					self.core_links[cokey].hlife=highTimeout
				out_port=self.core_links[key].sport
			else:
				key=str(u)+'>'+dst
				#change link and node state
				self.edge_links[key].state=1
				self.edge_links[key].life=lowTimeout
				out_port=self.edge_links[key].sport
			self.datapaths[u].state=1
			parser=self.datapaths[u].datapath.ofproto_parser
			actions=[parser.OFPActionOutput(out_port,0)]
			match = parser.OFPMatch(eth_src=srcMAC,eth_dst=dstMAC)
			flags=0
			if(i==lenPath-1):flags=self.datapaths[u].datapath.ofproto.OFPFF_SEND_FLOW_REM
			self.add_flow(self.datapaths[u].datapath,1,match,actions,cookie,i_timeout,h_timeout,flags)
		flow=self.recordFlows(cookie=cookie,path=path,check=checkpoint+1,match=match,src=src,dst=dst)
		obj=open('./ryucode/path/'+self.ftime+'.txt','a+')
		obj.writelines("add-flow:%08x %s %s %s %s\n" % (cookie,checkpoint,src,dst,path))
		obj.close()
		for nd in self.datapaths.keys():
			print nd,':',self.datapaths[nd].state,',' ,
		print '\n'
		return flow
	def recordFlows(self,cookie,path,check,match,src,dst):
		print 'recordFlows'
		lastdpid=path[-1]
		#record edge of flow
		edge=set()
		#key=str(path[0])+'>'+str(src)
		#edge.add(key)
		for i in range(len(path)-1):
			key=str(path[i])+'>'+str(path[i+1])
			self.core_links[key].flowset.add(cookie)
			edge.add(key)
		#key=str(path[-1])+'>'+str(dst)
		#edge.add(key)
		_flow={'lastDpid':lastdpid,'path':path,'edge':edge,'check':check,'src':src,'dst':dst,'fbytes':0,'mstimes':0,\
			'interval':1,'bw':0,'match':match,'lowmax':3,'highmax':3}
		flow=Flow(cookie,_flow)
		self.flows[cookie]=flow
		#print cookie,':',_flow
		#{check:[(cookie1,dpid),(cookie,dpid)]}
		self._add_check(check,cookie,lastdpid)
		return flow