#-*_ coding: utf-8 _*_
import re
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

def file_name(file_dir):   
	for root, dirs, files in os.walk(file_dir):
		#print root
		#print dirs 
		fnames=sorted(files)
		return fnames[-1]
dname=r'/home/husp/ryucode/log/'
fname=''
if(len(sys.argv)==1):
	fname=file_name(dname)
else:
	fname=sys.argv[1]+' '+sys.argv[2]
#print fname
title=fname
fname=dname+fname
print 'attempt to read file...'
try:
	fobj=open(fname,'r')
except IOError,e:
	print '%s open error' % (fname),e
else:
	t=[]
	x=[]
	y=[]
	z=[]
	u=[]
	v=[]
	w=[]
	lines = fobj.readlines()
	for line in lines:
		line=line.strip('\n')
		items=line.split(' ')
		t.append(float(items[0]))
		x.append(float(items[1]))
		y.append(float(items[2]))
		z.append(float(items[3]))
		u.append(float(items[4]))
		v.append(float(items[5]))
		w.append(float(items[6]))
		print items
	fobj.close()
	xticks=[i*20 for i in range(20)]
	yticks=[i/5.0 for i in range(6)]
	plt.figure(1)
	plt.subplot(611)
	plt.plot(t,x,c='k')
	plt.xlabel("time(s)")
	plt.ylabel("MEAN-RATIO")
	plt.xticks(xticks)
	plt.yticks(yticks)

	plt.subplot(612)
	plt.plot(t,y)
	plt.xlabel("time(s)")
	plt.ylabel("MSE")
	plt.xticks(xticks)
	yticks=[i/10.0 for i in range(6)]
	plt.yticks(yticks)

	plt.subplot(613)
	plt.plot(t,z,c='g')
	plt.xlabel("time(s)")
	plt.ylabel("POWER(w)")
	plt.xticks(xticks)
	yticks=[1500+i*200 for i in range(5)]
	plt.yticks(yticks)

	plt.subplot(614)
	plt.plot(t,w,c='g')
	plt.xlabel("time(s)")
	plt.ylabel("E-Saving-Ratio")
	plt.xticks(xticks)
	yticks=[i/10.0 for i in range(6)]
	plt.yticks(yticks)

	plt.subplot(615)
	plt.plot(t,u,c='g')
	plt.xlabel("time(s)")
	plt.ylabel("throughtput(kbps)")#---
	plt.xticks(xticks)
	yticks=[i*300 for i in range(9)]
	plt.yticks(yticks)

	plt.subplot(616)
	plt.plot(t,v,c='g')
	plt.xlabel("time(s)")
	plt.ylabel("eta(kbps/J)")
	plt.xticks(xticks)
	yticks=[i/5.0 for i in range(8)]
	plt.yticks(yticks)
	plt.show()                                                                                                                                                                                                                                                                                                                                        
