mv *.tr ./trace/
mv *.log.csv ./packetLogs/
mv *.reports.txt ./reportLogs/
mv *.flowmon ./flowmon/
mv *.csv ./csv/
cd pcap
mergecap -w LESAP100Norm.pcap LESAP-AODV.100.normal*.pcap
mergecap -w LESAP100Mal.pcap LESAP-AODV.100.mal*.pcap
mergecap -w LESAP50Norm.pcap LESAP-AODV.50.normal*.pcap
mergecap -w LESAP50Mal.pcap LESAP-AODV.50.mal*.pcap
mergecap -w LESAP25Norm.pcap LESAP-AODV.25.normal*.pcap
mergecap -w LESAP25Mal.pcap LESAP-AODV.25.mal*.pcap
mergecap -w AODV100Norm.pcap AODV.100.normal*.pcap
mergecap -w AODV100Mal.pcap AODV.100.mal*.pcap
mergecap -w AODV50Norm.pcap AODV.50.normal*.pcap
mergecap -w AODV50Mal.pcap AODV.50.mal*.pcap
mergecap -w AODV25Norm.pcap AODV.25.normal*.pcap
mergecap -w AODV25Mal.pcap AODV.25.mal*.pcap
mv LESAP-AODV.100.normal*.pcap ./split/
mv LESAP-AODV.100.mal*.pcap ./split/
mv LESAP-AODV.50.normal*.pcap ./split/
mv LESAP-AODV.50.mal*.pcap ./split/
mv LESAP-AODV.25.normal*.pcap ./split/
mv LESAP-AODV.25.mal*.pcap ./split/
mv AODV.100.normal*.pcap ./split/
mv AODV.100.mal*.pcap ./split/
mv AODV.50.normal*.pcap ./split/
mv AODV.50.mal*.pcap ./split/
mv AODV.25.normal*.pcap ./split/
mv AODV.25.mal*.pcap ./split/
mv *.pcap ./Merged/
