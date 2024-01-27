Download the Code here: 
https://drive.google.com/open?id=1OkV...

Comparison of MANET routing Protocols
1. AODV
2. DSDV
3. DSR
4. OLSR
using NS3 (Network Simulator 3)
B.Tech, M.Tech, PhD... 
1. Reactive Vs Proactive routing
2. PErformance comparison of MANET protocols
3. AODV Vs DSDV Comparison

https://www.nsnam.com
and also at my channel.

What Version: ns-3.29, ns-3.28,3.27,3.26,....
My Ubunut OS is: Ubuntu 18.04

This file we are going to use for our simulation:
/home/networks/ns-allinone-3.29/ns-3.29/examples/routing/manet-routing-compare.cc


Once you under stand the code, now lets run this example 



Step 1: Copy the above file in to ~ns-3.29/scratch/ folder

Step 2: Understand this code.
Step 3: Run this code
Open the terminal, Go to ns-3.29 and run the following command 

./waf --run scratch/manet-routing-compare

enable the following header file

#include "ns3/flow-monitor-helper.h"

four files got generated
AODV.csv
AODV.mob
AODV.flomon
temp.data

Parameters:
Number of nodes: 50 
No of sinks : 10
Mobility Model: 
Propagation Model: ConstantSpeedPropagationDelay
Propagation Loss Model: Friis
Position Allocator: RandomRectangularPositionAllocator
Mac: AdhocWifiMAC
Mac Standard: 802.11B
Bps: 2Kbps
Total Simulation Time: 200 seconds
Node speed: 20m/s
Node pause time: 0
Protocol: AODV


To run the flowmon file, use of temp.py is advised. 

to run the file, use the following

$] python flow.py AODV.flowmon

Find the python script here.
#beginning of Script
from xml.etree import ElementTree as ET
import sys
import matplotlib.pyplot as pylab
et=ET.parse(sys.argv[1])
bitrates=[]
losses=[]
delays=[]
for flow in et.findall("FlowStats/Flow"):
 for tpl in et.findall("Ipv4FlowClassifier/Flow"):
  if tpl.get('flowId')==flow.get('flowId'):
   break
 if tpl.get('destinationPort')=='654':
  continue
 losses.append(int(flow.get('lostPackets')))
 
 rxPackets=int(flow.get('rxPackets'))
 if rxPackets==0:
  bitrates.append(0)
 else:
  t0=float(flow.get('timeFirstRxPacket')[:-2])
  t1=float(flow.get("timeLastRxPacket")[:-2])
  duration=(t1-t0)*1e-9
  bitrates.append(8*long(flow.get("rxBytes"))/duration*1e-3)
  delays.append(float(flow.get('delaySum')[:-2])*1e-9/rxPackets)

pylab.subplot(311)
pylab.hist(bitrates,bins=40)
pylab.xlabel("Flow Bit Rates (b/s)")
pylab.ylabel("Number of Flows")


pylab.subplot(312)
pylab.hist(bitrates,bins=40)
pylab.xlabel("No of Lost Packets")
pylab.ylabel("Number of Flows")

pylab.subplot(313)
pylab.hist(bitrates,bins=10)
pylab.xlabel("Delay in Seconds")
pylab.ylabel("Number of Flows")

pylab.subplots_adjust(hspace=0.4)
pylab.savefig("results.pdf")

#End of Script

We can plot using gnuplot (through CSV File) and matplotlib(Flow monitor)
All these examples, runs for 50 nodes

whenever you compare protocols,have three different sets of node numbers

10 nodes, 50 nodes, 100 nodes and compare them with various metrics as mentioned above...

To analsyse .tr files, we need to use tracemetrics
its a jar file that can be run using 

$] java -jar tracemetrics.jar 


Hope you would have got an idea on how to simulate wireless protocols using ns3. 

Download the source code through my blog www.nsnam.com 
and also subscribe to my channel and share it to your friends/colleaques.
