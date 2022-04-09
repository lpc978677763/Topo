import re
import matplotlib.pyplot as plt
import numpy as np
import random
dirname='./ryucode/testflow/'
fname=raw_input('enter filename:')
print 'attempt to write file...'
fname=dirname+fname
ipindex=[0,1,2,3,4,5,6,7]
try:
	fobj=open(fname,'w+')
except IOError,e:
	print '%s open error' % (fname),e
else:
	'''
	#sw7
	cnt=0
	while(cnt<100):
		flow=''
		flow+=str(random.randint(2,10))+','#time interval
		s=random.randint(0,7)#source
		t=random.randint(0,7)#dest
		while(s/4==t/4):
			t=random.randint(0,7)
		flow+=str(s)+','
		flow+=str(t)+','
		flowtime=random.randint(5,100)#flow duration
		bw=random.randint(50,500)#bandwidth
		flow+=str(flowtime)+','
		flow+=str(bw)+'\n'
		print flow
		cnt+=1
		fobj.write(str(flow))

	'''
	#sw7-1
	cnt=0
	while(cnt<2):
		cntDay=0
		while(cntDay<60):
			flow=''
			flow+=str(random.randint(2,2))+','#time interval
			s=random.randint(0,7)#source
			t=random.randint(0,7)#dest
			while(s/4==t/4):
				t=random.randint(0,7)
			flow+=str(s)+','
			flow+=str(t)+','
			flowtime=random.randint(10,30)#flow duration
			bw=random.randint(20,200)#bandwidth
			flow+=str(flowtime)+','
			flow+=str(bw)+'\n'
			print flow
			cntDay+=1
			fobj.write(str(flow))
		cntDay=0
		while(cntDay<5):
			flow=''
			flow+=str(random.randint(10,30))+','#time interval
			s=random.randint(0,7)#source
			t=random.randint(0,7)#dest
			while(s/4==t/4):
				t=random.randint(0,7)
			flow+=str(s)+','
			flow+=str(t)+','
			flowtime=random.randint(10,30)#flow duration
			bw=random.randint(20,200)#bandwidth
			flow+=str(flowtime)+','
			flow+=str(bw)+'\n'
			print flow
			cntDay+=1
			fobj.write(str(flow))
		cnt+=1
	fobj.close()

try:
	fobj=open(fname,'r')
except IOError,e:
	print '%s open error' % (fname),e
else:
	data = fobj.readlines()
	print data[0]
	fobj.close()
