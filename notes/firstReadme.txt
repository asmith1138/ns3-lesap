ns3
source code, API
python or C++

How to begin with? where do i start?
sensor networks, wireless networks, iot, p2p, csma, etc... 
ns3 adopted so many protocol from ns2

ns3 gives some examples to start with
first.cc second.cc third.cc fifth.cc sixth.cc and seventh.cc
examples/tutorial
in this work, I will go for first.cc 
peer to peer network 

0-------0

NetAnim (Netwok Animator)
Visualizer 
wireshark (packet analyser)
tracemetrics
flowmetrics

first.cc
usually the folder structure 
source examples location
~ns-allinone-3.27/ns-3.28/examples/tutorials

How to run
these .cc files have to be put inside the folder called as 
~ns-3.27/scratch/

$] cd ns-allinone-3.27/ns-3.27/
$] ./waf --run scratch/first (No extension of .cc here)
To run python files. 

$] ./waf --pyrun scratch/first.py

netanim is a folder comes along with ns3
$] cd ns-allinone-3.27/netanim-3.108/
$] sudo apt install qt4-default qt4-qmake
$] qmake NetAnim.pro
$] make

Tracemetrics - Ascii Trace Format
print logs in the ascii format. 

Tracemetrics 

$] sudo apt install default-jdk

download the tracemetrics from this location https://www.nsnam.com 
unzip into a folder called as tracemetrics 

$] cd tracemetrics
$] java -jar tracemetrics.jar

Thanks for watching my video. Dont forget to subscribe, more results/projects will be in pipelines

