cd ~
cd ns-3-dev
./ns3 run "scratch/lesap-compare/lesap-aodv-aodv-routing-compare-w-trace.cc --sims=aodv-all" &> aodv.all.log
./ns3 run "scratch/lesap-compare/lesap-aodv-aodv-routing-compare-w-trace.cc --sims=lesap-25-50-norm-mal" &> lesap.25.50.log
./ns3 run "scratch/lesap-compare/lesap-aodv-aodv-routing-compare-w-trace.cc --sims=lesap-100-norm" &> lesap.100.normal.log
./ns3 run "scratch/lesap-compare/lesap-aodv-aodv-routing-compare-w-trace.cc --sims=lesap-100-mal" &> lesap.100.mal.log
cd ~/Documents/thesis/resultsLogging/
./postrun.sh
