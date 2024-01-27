In this example, I use a mobility trace generated from SUMO in ns-3. The trace is in ns-2 simulation. The problem is the built-in Ns2MobilityHelper creates all simulation nodes at time 0, which is not realistic, and will create network congestion.

I share some code that help solve this problem. It parses the ns-2 mobility trace to determine the number of nodes, the simulation time, and their entry & exit times into the simulation. This helps by allowing us to not start radio broadcast on nodes until they enter the simulation, and we can turn the radio functionality off when the node leaves the simulation.

The source code for the example, and the ns2mobility.tcl file can be found in my github repository
https://github.com/addola/NS3-HelperS...

Copy the files in SUMOTraceExample to a directory under scratch. Call it SUMOTraceExample. The files should be
        $NS3_ROOT_DIR/scratch/SUMOTraceExample/main-program.cc
        $NS3_ROOT_DIR/scratch/SUMOTraceExample/ns2mobility.tcl
        ...
        $NS3_ROOT_DIR/scratch/SUMOTraceExample/ns2-node-utility.cc
        $NS3_ROOT_DIR/scratch/SUMOTraceExample/ns2-node-utility.h

Then you can run your program as follows:
        ./waf --run SUMOTraceExample
If you want to enable logging, you can run:
        NS_LOG=CustomApplication=info ./waf --run SUMOTraceExample

I hope everything works nicely for you! Good luck!

