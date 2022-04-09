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
		self.topoFile='/home/luyg/ryucode/topo/topo-10sw-dc.csv'
		self.energyTotal=0.0
		self.readTopo(self.topoFile)
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
				self.getWeight1(stat.cookie)
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
		if(len(self.checks)==0):
			path=self.getFirstPath(src,dst)
		else:
			#PbRR
			s=self.hosts[src].tdpid
			t=self.hosts[dst].tdpid
			typeTopo='active'
			favorNet=self.getInitMatrix(typeTopo)
			path=self.PbRR(s,t,favorNet)
			if(len(path)==0):
				typeTopo='global'
				favorNet=self.getInitMatrix(typeTopo)
				path=self.PbRR(s,t,favorNet)
				if(len(path)==0):path=self.getPath(src,dst)
		print 'initial path:' ,src,dst,str(path)
		path=tuple(path)#path is a tuple
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
			self.getWeight1(cookie)
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
		print 'readtopo'
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
				self.energyTotal+=3*(stableEnergyLink)#
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



			cokey=str(edge.tdpid)+'>'+str(edge.sdpid)
			coedge=self.core_links[cokey]
			if(edge.bw>edge.capacity):edge.bw=edge.capacity
			if(edge.bw<0.0):edge.bw=0.0
			edge.rw=edge.capacity-edge.bw
			edge.ratio=edge.bw*1.0/edge.capacity
			print 'link %s   bw:%.2f  rw:%.2f   ratio:%.2f%%	state:%d  	llife:%d   	hlife:%d' \
					% (edge.id,edge.bw,edge.rw,100*edge.ratio,edge.state,edge.llife,edge.hlife)
			if(edge.ratio<=lowThreshold):
				edge.llife-=1
			else:edge.llife=lowTimeout
			
			if(coedge.ratio<=lowThreshold):
				coedge.llife-=1
			else:coedge.llife=lowTimeout
			
			if(edge.llife<0 and coedge.llife<0):
				#schedule low flow
				lowFlows+=list(edge.flowset)
				lowFlows+=list(coedge.flowset)
				if(cookie in edge.flowset):edge.flowset.remove(cookie)
			if(edge.ratio>=highThreshold):
				edge.hlife-=1
			else:edge.hlife=highTimeout
			
			if(coedge.ratio>=highThreshold):
				coedge.hlife-=1
			else:coedge.hlife=highTimeout
			
			if(edge.hlife<0 or coedge.hlife<0):
				#schedule high flow
				highFlows+=list(edge.flowset)
				highFlows+=list(coedge.flowset)
				#if(cookie in edge.flowset):edge.flowset.remove(cookie)
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
		'''
		if(eventFlag==True and (len(lowFlows)>0 or len(highFlows)>0) and (cookie in self.flows.keys())):
			self.scheduleFlows(cookie)
		else:return None
		'''
		#newschedule_it
		if(eventFlag==True and (len(lowFlows)>0 or len(highFlows)>0)):
			self.getNewSchedule_it()
		else:return None
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
		'''
		for key in self.core_links.keys():
			edge=self.core_links[key]
			print edge.id,':',edge.state,
		print '\n'
		'''
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
	def getWeight1(self,cookie):
		print 'getWeight1'
		ratio=0.0
		activeLink=0
		for key in self.core_links.keys():
			if(key not in self.core_links.keys()):continue
			edge=self.core_links[key]
			if(edge.state>-1 and edge.ratio>0):
				ratio+=edge.ratio
				activeLink+=1
		if(activeLink==0):return
		#mean of ratio
		mean=ratio/activeLink
		var=0.0
		for key in self.core_links.keys():
			if(key not in self.core_links.keys()):continue
			edge=self.core_links[key]
			if(edge.state>-1 and edge.ratio>0.0):
				var+=((edge.ratio-mean)**2)
		var/=activeLink
		#print 'means=%f var=%f' % (mean,var)
		for key in self.core_links.keys():
			if(key not in self.core_links.keys()):continue
			edge=self.core_links[key]
			if(edge.state>-1):
				if(edge.ratio>=highThreshold):
					edge.favor=min(exp(-((edge.ratio-mean)**2)/(2.0*var+0.00001)),log10(1.0/edge.ratio))
				else:
					edge.favor=exp(-((edge.ratio-mean)**2)/(2.0*var+0.00001))
			else:
				edge.favor=0.5
	def getWeight2(self,cookie):
		print 'getWeight2'
		for key in self.core_links.keys():
			if(key not in self.core_links.keys()):continue
			edge=self.core_links[key]
			ratio=edge.ratio
			if(edge.state>-1):
				if(-0.001<=ratio<=0.001 or ratio>=1.0):
					edge.favor=0.0
				else:
					edge.favor=ratio*log(ratio,2)-(1-ratio)*log(1-ratio,2)
			print edge.id,edge.ratio,edge.favor

	def getInitMatrix(self,typeTopo):
		print 'getInitMatrix'
		favorNet=[]
		nodes=len(self.datapaths)
		for i in range(0,nodes+1):
			line=[]
			for j in range(0,nodes+1):
				line+=[-1]
			favorNet.append(line)
		for key in self.core_links.keys():
			if(self.core_links[key].state==1):
				items=key.split('>')
				i=int(items[0])
				j=int(items[1])
				edge=self.core_links[key]
				favorNet[i][j]=edge.favor
			else:
				if(typeTopo=='active'):continue
				items=key.split('>')
				i=int(items[0])
				j=int(items[1])
				edge=self.core_links[key]
				favorNet[i][j]=0.5
		print favorNet
		return favorNet
	
	#-----------------------------------------------------------------------------------
	def getRerouteMatrix(self,typeTopo,cookie):
		print 'getRerouteMatrix'
		favorNet=[]
		nodes=len(self.datapaths)
		for i in range(0,nodes+1):
			line=[]
			for j in range(0,nodes+1):
				line+=[-1]
			favorNet.append(line)
		bwNet=copy.deepcopy(favorNet)
		ratioNet=copy.deepcopy(favorNet)
		activeLink=0
		sumRatio=0
		meanRatio=0
		for key in self.core_links.keys():
			items=key.split('>')
			i=int(items[0])
			j=int(items[1])
			if(self.core_links[key].state==-1):
				if(typeTopo=='active'):continue
				else:
					bwNet[i][j]=self.core_links[key].bw
					ratioNet[i][j]=self.core_links[key].ratio
					favorNet[i][j]=self.core_links[key].favor
			else:
				edge=self.core_links[key]
				linkbw=0.0
				for flowid in edge.flowset:
					if(flowid!=cookie):
						linkbw+=self.flows[flowid].bw
				bwNet[i][j]=min(linkbw,self.core_links[key].capacity)
				ratioNet[i][j]=bwNet[i][j]*1.0/self.core_links[key].capacity
				if(ratioNet[i][j]>0.0):
					activeLink+=1
					sumRatio+=ratioNet[i][j]
		if(activeLink==0):
			return bwNet,ratioNet,None
		meanRatio=sumRatio/activeLink
		varRatio=0.0
		for i in range(1,nodes+1):
			for j in range(1,nodes+1):
				if(ratioNet[i][j]>0.0):
					varRatio+=(ratioNet[i][j]-meanRatio)*(ratioNet[i][j]-meanRatio)
		varRatio/=activeLink
		for i in range(1,nodes+1):
			for j in range(1,nodes+1):
				if(ratioNet[i][j]<=0.0 or favorNet[i][j]>0.0):continue
				if(ratioNet[i][j]>=highThreshold):
					favorNet[i][j]=min(exp(-((ratioNet[i][j]-meanRatio)**2)/(2.0*varRatio+0.00001)),log10(1.0/meanRatio))
				else:
					favorNet[i][j]=exp(-((ratioNet[i][j]-meanRatio)**2)/(2.0*varRatio+0.00001))
		print meanRatio,varRatio
		print ratioNet
		print favorNet
		return bwNet,ratioNet,favorNet
	def getRerouteMatrix_it(self,typeTopo):
		print 'getRerouteMatrix_it'
		favorNet=[]
		nodes=len(self.datapaths)
		for i in range(0,nodes+1):
			line=[]
			for j in range(0,nodes+1):
				line+=[-1]
			favorNet.append(line)
		bwNet=copy.deepcopy(favorNet)
		ratioNet=copy.deepcopy(favorNet)
		activeLink=0
		sumRatio=0
		meanRatio=0
		for key in self.core_links.keys():
			items=key.split('>')
			i=int(items[0])
			j=int(items[1])
			if(self.core_links[key].state==-1):
				if(typeTopo=='active'):continue
				else:
					bwNet[i][j]=self.core_links[key].bw
					ratioNet[i][j]=self.core_links[key].ratio
					favorNet[i][j]=self.core_links[key].favor
			else:
				edge=self.core_links[key]
				linkbw=0.0
				for flowid in edge.flowset:
					linkbw+=self.flows[flowid].bw
				bwNet[i][j]=min(linkbw,self.core_links[key].capacity)
				ratioNet[i][j]=bwNet[i][j]*1.0/self.core_links[key].capacity
				if(ratioNet[i][j]>0.0):
					activeLink+=1
					sumRatio+=ratioNet[i][j]
		if(activeLink==0):
			return bwNet,ratioNet,None
		meanRatio=sumRatio/activeLink
		varRatio=0.0
		for i in range(1,nodes+1):
			for j in range(1,nodes+1):
				if(ratioNet[i][j]>0.0):
					varRatio+=(ratioNet[i][j]-meanRatio)*(ratioNet[i][j]-meanRatio)
		varRatio/=activeLink
		for i in range(1,nodes+1):
			for j in range(1,nodes+1):
				if(ratioNet[i][j]<=0.0 or favorNet[i][j]>0.0):continue
				if(ratioNet[i][j]>=highThreshold):
					favorNet[i][j]=min(exp(-((ratioNet[i][j]-meanRatio)**2)/(2.0*varRatio+0.00001)),log10(1.0/meanRatio))
				else:
					favorNet[i][j]=exp(-((ratioNet[i][j]-meanRatio)**2)/(2.0*varRatio+0.00001))
		return bwNet,ratioNet,favorNet
	
	def getNewSchedule_it(self):
		print 'getNewSchedule_it'
		k=0
		typeTopo='active'
		#iterator
		while(k<itK):
			if(k>=itK/2):typeTopo='global'

			nodeNum=len(self.datapaths)
			rmin=maxValue
			rmax=0.0
			mean=0.0
			sumRatio=0.0
			var=0.0
			activeLink=0
			bwNet,ratioNet,favorNet=self.getRerouteMatrix_it(typeTopo)

			if(favorNet!=None):
				#get rmin rmax mean
				for i in range(1,nodeNum+1):
					for j in range(1,nodeNum+1):
						if(ratioNet[i][j]>=0):
							if(rmin>ratioNet[i][j]):rmin=ratioNet[i][j]
							if(rmax<ratioNet[i][j]):rmax=ratioNet[i][j]
							sumRatio+=ratioNet[i][j]
							activeLink+=1
				
				mean=sumRatio/activeLink
				maxvar=0
				maxflow=-1
				
				for cookie in self.flows.keys():
					sumvar=0.0
					path=self.flows[cookie].path
					for i in range(1,len(path)):
						u=path[i-1]
						v=path[i]
						sumvar+=(ratioNet[u][v]-mean)*(ratioNet[u][v]-mean)
					sumvar/=(len(path)-1)
					if(sumvar>maxvar):
						maxvar=sumvar
						maxflow=cookie
				#schedule flow maxflow
				if(maxflow==-1):
					k+=1
					continue
				bwMat,ratioMat,favorMat=self.getRerouteMatrix(typeTopo,maxflow)
				if(favorMat==None):
					k+=1
					continue
				#get multi paths
				paths=self.getpaths_it(favorMat,maxflow)
				#selectpath
				path=self.selectpath_it(paths,typeTopo,bwMat,ratioMat,maxflow)
				flow=self.flows[maxflow]
				if(path!=() and tuple(path)!=tuple(flow.path)):
					self.change_path(maxflow,flow.path,path,flow.src,flow.dst)
					self.getWeight1(maxflow)
				#modify flow/link/rationet/bwnet/favornet/rmin/rmax/mean
				
			k+=1
	def getpaths_it(self,favorMat,cookie):
		print 'getpaths',self.flows[cookie].src,self.flows[cookie].dst
		oldpath=self.flows[cookie].path
		s=oldpath[0]
		t=oldpath[-1]
		paths=set()
		paths.add(tuple(oldpath))
		arrive,path=self.dijkstra(s,t,favorMat)
		if(arrive==True):
			paths.add(tuple(path))
			for i in range(1,len(path)):
				u=path[i-1]
				v=path[i]
				temp=favorMat[u][v]
				favorMat[u][v]=-1
				arrive,sp2path=self.dijkstra(s,t,favorMat)
				if(arrive==True and (tuple(sp2path) not in paths)):paths.add(tuple(sp2path))
				favorMat[u][v]=temp
			#pbrr
			pbrrpath=self.PbRR(s,t,favorMat)
			if(len(pbrrpath)>0 and (tuple(pbrrpath) not in paths)):paths.add(tuple(pbrrpath))
		return paths
	def selectpath_it(self,paths,typeTopo,bwMat,ratioMat,cookie):
		#select one path
		rmax=0.0
		gainmin=maxValue
		spath=()
		if(len(paths)==0):return spath
		nodeNum=len(self.datapaths)
		for p1 in paths:
			bwNet=copy.deepcopy(bwMat)
			ratioNet=copy.deepcopy(ratioMat)
			for i in range(1,len(p1)):
				u=p1[i-1]
				v=p1[i]
				key=str(u)+'>'+str(v)
				bwNet[u][v]+=self.flows[cookie].bw
				bwNet[u][v]=min(bwNet[u][v],self.core_links[key].capacity)
				ratioNet[u][v]=bwNet[u][v]/self.core_links[key].capacity
			mean=0.0
			var=0.0
			activeLink=0
			for i in range(1,nodeNum+1):
				for j in range(1,nodeNum+1):
					if(ratioNet[i][j]>0):
						mean+=ratioNet[i][j]
						if(ratioNet[i][j]>rmax):rmax=ratioNet[i][j]
						activeLink+=1
			if(activeLink==0):return ()
			mean/=activeLink
			for i in range(1,nodeNum+1):
				for j in range(1,nodeNum+1):
					if(ratioNet[i][j]>0):
						var+=(ratioNet[i][j]-mean)*(ratioNet[i][j]-mean)
			var/=activeLink
			if(typeTopo=='active'):
				if(var<gainmin):
					gainmin=var
					spath=p1
			else:
				#rmax*sqrt(var)+(1-rmax)*e1/etotal
				e1=0.0
				for dpid in self.datapaths.keys():
					if(self.datapaths[dpid].state>0):e1+=stableEnergyNode
					else:
						if(int(dpid) in p1):e1+=stableEnergyNode
				for key in self.core_links.keys():
					if(self.core_links[key].state>0):
						e1+=(stableEnergyLink+self.core_links[key].ratio*maxDynamicEnergy)
				for i in range(1,len(p1)):
					u=p1[i-1]
					v=p1[i]
					key=str(u)+'>'+str(v)
					if(self.core_links[key].state<0):
						e1+=2*stableEnergyLink
				gain=rmax*sqrt(var)+(1.0-rmax)*e1/self.energyTotal
				if(gain<gainmin):
					gainmin=gain
					spath=p1
		return spath
	
	
	def getPath(self,src,dst):
		print 'getPath',src,dst
		#global maxValue,m
		#print 'path computing:'
		s=self.hosts[src].tdpid
		t=self.hosts[dst].tdpid
		if(s==t):return [s]
		#typeTopo='active'
		#typeTopo='global'
		paths={}
		typeTopo='active'
		actFavorMat=self.getInitMatrix(typeTopo)
		arrive,path=self.dijkstra(s,t,actFavorMat)
		print '---------------11111---------------'
		if(arrive==True ):
			for i in range(mpath):
				path=self.PbRR(s,t,actFavorMat)
				if(len(path)>0):
					if((tuple(path) in paths.keys())):
						paths[tuple(path)]+=1
					else:
						paths[tuple(path)]=1
		typeTopo='global'
		gloFavorMat=self.getInitMatrix(typeTopo)
		arrive,dpath=self.dijkstra(s,t,gloFavorMat)
		print '---------------222222---------------'
		if(arrive==True):
			if(tuple(dpath) not in paths.keys()):
				paths[tuple(dpath)]=1
			for i in range(mpath):
				path=self.PbRR(s,t,gloFavorMat)
				if(len(path)>0):
					if((tuple(path) in paths.keys())):
						paths[tuple(path)]+=1
					else:
						paths[tuple(path)]=1
		return self.evalue(paths)

	#dijkstra
	def getFirstPath(self,src,dst):
		print 'getFirstPath'
		#global maxValue,m
		#print 'path computing:'
		s=self.hosts[src].tdpid
		t=self.hosts[dst].tdpid
		if(s==t):return [s]
		typeTopo='active'
		favorNet=self.getInitMatrix(typeTopo)
		arrive,path=self.dijkstra(s,t,favorNet)
		if(arrive==True):return path
		typeTopo='global'
		favorNet=self.getInitMatrix(typeTopo)
		arrive,path=self.dijkstra(s,t,favorNet)
		return path
	def dijkstra(self,s,t,favorNet):
		print 'dijkstra'
		nodeNum=len(self.datapaths)
		arrive=False
		path=[]
		u=s
		visit={}
		dist={}
		parent={}
		for i in range(1,nodeNum+1):
			dist[i]=maxValue
			parent[i]=-1
			visit[i]=0
		dist[u]=0
		for i in range(nodeNum):
			minValue=maxValue
			for j in dist.keys():
				if(visit[j]==0 and dist[j]<minValue):
					minValue=dist[j]
					u=j;
			if(minValue==maxValue):break;
			visit[u]=1
			for j in range(1,nodeNum+1):
				#distance=1-coreLinks[u][k]['favor']
				if(visit[j]==0 and favorNet[u][j]>0.0 and dist[u]+(1-favorNet[u][j])<dist[j]):
					dist[j]=dist[u]+(1-favorNet[u][j])
					parent[j]=u
		if(dist[t]!=maxValue):
			arrive=True
			v=t
			while(v!=-1):
				path.insert(0,v)
				v=parent[v]
		#print  typeTopo,arrive,path
		return arrive,path
	def BFS(self,s,t,gvisit,favorNet):
		print 'BFS'
		arrive=False
		if(s==t):
			return True
		queue=[];head=0;rear=0
		visit={}
		nodeNum=len(self.datapaths)
		for i in range(1,nodeNum+1):
			visit[i]=gvisit[i]
		nodeNum=len(self.datapaths)
		u=s
		visit[u]=1
		queue.append(u)
		rear+=1
		while(head<rear):
			u=queue[head]
			head+=1
			for j in range(1,nodeNum+1):
				if(visit[j]==0 and favorNet[u][j]>0.0):
					queue.append(j)
					rear+=1
					visit[j]=1
		if(visit[t]==1):
			arrive=True
		return arrive
	def PbRR(self,s,t,favorNet):
		print 'PbRR',s,t
		path=[]
		visit={}
		nodeNum=len(self.datapaths)
		for i in range(1,nodeNum+1):
			visit[i]=0
		u=s
		if(self.BFS(s,t,visit,favorNet)==False):
			print path
			return path
		path.append(u)
		visit[u]=1
		while(u!=t):
			selectNodeSum=0
			selectNodes=[]
			for j in range(1,nodeNum+1):
				if(visit[j]==0 and favorNet[u][j]>0.0 and self.BFS(j,t,visit,favorNet)==True):
					selectNodes.append(j)
					selectNodeSum+=exp(favorNet[u][j])
			selectNodeNum=len(selectNodes)
			if(selectNodeNum==0 or selectNodeSum<0.0000001):
				path=[]
				print path
				return path
			temp=0
			p=random.uniform(0,1)
			for k in selectNodes:
				temp+=(exp(favorNet[u][k])/selectNodeSum)
				#print temp,p
				if(temp>=p):
					path.append(k)
					u=k
					visit[u]=1
					break;
		print path
		return path
	def evalue(self,paths,bw=None):
		print 'evalue',paths
		debug=True
		selectpath=()
		if(len(paths)==0):return selectpath
		################evalue the new flow bandwidth####################
		if(bw==None):
			bw=0
			lastdpid=paths.keys()[0][-1]
			simiFlowsbw=[self.flows[cookie].bw for cookie in self.flows.keys() if self.flows[cookie].lastdpid==lastdpid]
			if(len(simiFlowsbw)==0):#first dpid flow
				simiFlowsbw=[self.flows[cookie].bw for cookie in self.flows.keys()]
			if(len(simiFlowsbw)!=0):#first  flow
				bw=sum(simiFlowsbw)/len(simiFlowsbw)
		###########find the mini reminder bandwidth ######
		pathRebandwidth={}
		prepath=None
		prerbw=0
		for path in paths.keys():
			minrbw=maxValue
			for i in range(len(path)-1):
				u=path[i]
				v=path[i+1]
				if(minrbw>self.core_links[str(u)+'>'+str(v)].rw):
					minrbw=self.core_links[str(u)+'>'+str(v)].rw
			pathRebandwidth[path]=minrbw
			if(minrbw>prerbw):
				prerbw=minrbw
				prepath=path
		###########compute new node and link energy #########################
		pathsNewEnergy={}
		pathsEnergy={}
		for path in paths.keys():
			newEnergy=0.0
			energy=0.0
			for i in range(len(path)):
				energy+=stableEnergyNode
				if(self.datapaths[path[i]].state==-1):
					newEnergy+=stableEnergyNode
				if(i<len(path)-1):
					u=path[i]
					v=path[i+1]
					energy+=(2*stableEnergyLink)
					if(self.core_links[str(u)+'>'+str(v)]==-1):
						newEnergy+=(2*stableEnergyLink)
			pathsNewEnergy[path]=newEnergy
			pathsEnergy[path]=energy
		#####exclude reminder bandwidth less than flow need bandwidth#######
		if(debug):
			#print 'evalue',pathRebandwidth,bw
			exPaths=[key for key in pathRebandwidth.keys() if pathRebandwidth[key]<bw]
			if(len(exPaths)>0):
				maxminRW=exPaths[0]
				for path in exPaths:
					if(pathRebandwidth[path]>pathRebandwidth[maxminRW]):maxminRW=path
					del paths[path]
					del pathsNewEnergy[path]
					del pathsEnergy[path]
			#return the max remainbw for rebw is not enough
			if(len(paths)==0):
				return maxminRW
				#return x=sorted(pathRebandwidth.items(),key=lambda item):item[1],reverse=True)[0][0]
		##########end################
		#selectpath=self.score1(bw,paths,prepath,pathsEnergy,pathsNewEnergy)
		#selectpath=self.score2(bw,paths,prepath,pathsEnergy,pathsNewEnergy)
		#selectpath=self.score3(paths,prepath,pathsNewEnergy)
		selectpath=self.score4(paths,prepath,pathsNewEnergy)
		return selectpath
	def score1(self,bw,paths,prepath,pathsEnergy,pathsNewEnergy):
		print 'score1'
		hops=[len(key)+1 for key in paths.keys()]
		maxHops=max(hops)
		maxScore=0.0
		pathsScore={}
		selectpath=prepath
		for path in paths.keys():
			rmin=1.0
			rmax=0.0
			for i in range(len(path)-1):
				u=path[i]
				v=path[i+1]
				edgeID=str(u)+'>'+str(v)
				if(self.core_links[edgeID].ratio>rmax):rmax=self.core_links[edgeID].ratio
				if(self.core_links[edgeID].ratio<rmin):rmin=self.core_links[edgeID].ratio
			bwEnergy=bw/1005.0*maxDynamicEnergy*(len(path)-1)
			linkbwEnergy=maxDynamicEnergy*(len(path)-1)
			numerator=rmin*(1-rmax)+c0
			denominator=max(c0, (pathsNewEnergy[path]+bwEnergy)/(pathsEnergy[path]+linkbwEnergy+c0)*((len(path)+1.0)/(1.0+maxHops)))
			pathsScore[path]=numerator/denominator
			print '%.6f/%.6f=%.6f;path:%s;energy:%.6f' % (numerator,denominator,pathsScore[path],str(path),pathsNewEnergy[path])
			if(maxScore<pathsScore[path]):
				maxScore=pathsScore[path]
				selectpath=path
		return selectpath
	def score2(self,bw,paths,prepath,pathsEnergy,pathsNewEnergy):
		print 'score2'
		hops=[len(key)+1 for key in paths.keys()]
		maxHops=max(hops)
		maxScore=0.0
		pathsScore={}
		selectpath=prepath
		for path in paths.keys():
			rmin=1.0
			rmax=0.0
			for i in range(len(path)-1):
				u=path[i]
				v=path[i+1]
				edgeID=str(u)+'>'+str(v)
				if(self.core_links[edgeID].ratio>rmax):rmax=self.core_links[edgeID].ratio
				if(self.core_links[edgeID].ratio<rmin):rmin=self.core_links[edgeID].ratio
			bwEnergy=bw/1005.0*maxDynamicEnergy*(len(path)-1)
			linkbwEnergy=maxDynamicEnergy*(len(path)-1)
			#add vote
			numerator=(rmin*(1-rmax)+c0)*paths[path]
			denominator=max(c0, (pathsNewEnergy[path]+bwEnergy)/(pathsEnergy[path]+linkbwEnergy+c0)*((len(path)+1.0)/(1.0+maxHops)))
			pathsScore[path]=numerator/denominator
			print '%.6f/%.6f=%.6f;path:%s;energy:%.6f' % (numerator,denominator,pathsScore[path],str(path),pathsNewEnergy[path])
			if(maxScore<pathsScore[path]):
				maxScore=pathsScore[path]
				selectpath=path
		return selectpath
	def score3(self,paths,prepath,pathsNewEnergy):
		print 'score3'
		hops=[len(key)+1 for key in paths.keys()]
		maxHops=max(hops)
		maxEnergy=max(pathsNewEnergy.values())
		minEnergy=min(pathsNewEnergy.values())
		maxScore=0.0
		pathsScore={}
		selectpath=prepath
		for path in paths.keys():
			rmin=1.0
			rmax=0.0
			for i in range(len(path)-1):
				u=path[i]
				v=path[i+1]
				edgeID=str(u)+'>'+str(v)
				if(self.core_links[edgeID].ratio>rmax):rmax=self.core_links[edgeID].ratio
				if(self.core_links[edgeID].ratio<rmin):rmin=self.core_links[edgeID].ratio
			numerator=(rmin*(1-rmax)+c0)*paths[path]
			denominator=exp(((pathsNewEnergy[path]-minEnergy)/(c0+maxEnergy-minEnergy))*((len(path)+1.0)/(1.0+maxHops)))
			pathsScore[path]=numerator/denominator
			print '%.6f/%.6f=%.6f;path:%s;energy:%.6f' % (numerator,denominator,pathsScore[path],str(path),pathsNewEnergy[path])
			if(maxScore<pathsScore[path]):
				maxScore=pathsScore[path]
				selectpath=path
		return selectpath
	def score4(self,paths,prepath,pathsNewEnergy):
		print 'score4'
		hops=[len(key)+1 for key in paths.keys()]
		maxHops=max(hops)
		maxEnergy=max(pathsNewEnergy.values())
		minEnergy=min(pathsNewEnergy.values())
		maxScore=0.0
		pathsScore={}
		selectpath=prepath
		for path in paths.keys():
			rmin=1.0
			rmax=0.0
			for i in range(len(path)-1):
				u=path[i]
				v=path[i+1]
				edgeID=str(u)+'>'+str(v)
				if(self.core_links[edgeID].ratio>rmax):rmax=self.core_links[edgeID].ratio
				if(self.core_links[edgeID].ratio<rmin):rmin=self.core_links[edgeID].ratio
			left=((rmax-rmin)+c0)*paths[path]/mpath
			rght=((maxEnergy-pathsNewEnergy[path])/(c0+maxEnergy-minEnergy))*((len(path)+1.0)/(1.0+maxHops))
			pathsScore[path]=alpha*left+beta*rght
			print rmax-rmin
			print '%.6f  %.6f=%.6f;path:%s;energy:%.6f' % (left,rght,pathsScore[path],str(path),pathsNewEnergy[path])
			if(maxScore<pathsScore[path]):
				maxScore=pathsScore[path]
				selectpath=path
		return selectpath
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