/*
 * Copyright (c) 2011 University of Kansas
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Andrew Smith <asmith1138@gmail.com>, written after
 * manet-routing-compare.cc by Justin Rohrer <rohrej@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  https://resilinets.org/
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

/*
 * This example program allows one to run ns-3 DSDV, AODV, or OLSR under
 * a typical random waypoint mobility model.
 *
 * By default, the simulation runs for 200 simulated seconds, of which
 * the first 50 are used for start-up time.  The number of nodes is 50.
 * Nodes move according to RandomWaypointMobilityModel with a speed of
 * 20 m/s and no pause time within a 300x1500 m region.  The WiFi is
 * in ad hoc mode with a 2 Mb/s rate (802.11b) and a Friis loss model.
 * The transmit power is set to 7.5 dBm.
 *
 * It is possible to change the mobility and density of the network by
 * directly modifying the speed and the number of nodes.  It is also
 * possible to change the characteristics of the network by changing
 * the transmit power (as power increases, the impact of mobility
 * decreases and the effective density increases).
 *
 * By default, OLSR is used, but specifying a value of 2 for the protocol
 * will cause AODV to be used, and specifying a value of 3 will cause
 * DSDV to be used.
 *
 * By default, there are 10 source/sink data pairs sending UDP data
 * at an application rate of 2.048 Kb/s each.    This is typically done
 * at a rate of 4 64-byte packets per second.  Application data is
 * started at a random time between 50 and 51 seconds and continues
 * to the end of the simulation.
 *
 * The program outputs a few items:
 * - packet receptions are notified to stdout such as:
 *   <timestamp> <node-id> received one packet from <src-address>
 * - each second, the data reception statistics are tabulated and output
 *   to a comma-separated value (csv) file
 * - some tracing and flow monitor configuration that used to work is
 *   left commented inline in the program
 */

#include "ns2-node-start.h"
#include "bsm-app.h"

#include "ns3/aodv-module.h"
#include "ns3/lesap-aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/yans-wifi-helper.h"

#include <fstream>
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("manet-routing-compare");

/**
 * Routing experiment class.
 *
 * It handles the creation and run of an experiment.
 */
class RoutingExperiment
{
  public:
    RoutingExperiment();
    /**
     * Run the experiment.
     */
    void Run();

    /**
     * Handles the command-line parameters.
     * \param argc The argument count.
     * \param argv The argument vector.
     */
    void CommandSetup(int argc, char** argv);
    void SetProtocol(std::string protocolName);
    void SetMalicious(bool mal);
    void SetNNodeWTrace(std::string nNodes);
    void TurnOffFlowmon();
    /**
    * Congestion window change callback
    *
    * \param oldCwnd Old congestion window.
    * \param newCwnd New congestion window.
    */
    static void
    CwndChange(uint32_t oldCwnd, uint32_t newCwnd)
    {
        NS_LOG_UNCOND(Simulator::Now().GetSeconds() << "\t" << newCwnd);
    }

  private:
    /**
     * Setup the receiving socket in a Sink Node.
     * \param addr The address of the node.
     * \param node The node pointer.
     * \param start The start time.
     * \param end The end time.
     * \return the socket.
     */
    Ptr<Socket> SetupPacketReceive(Ipv4Address addr, Ptr<Node> node);
    Ptr<BsmApp> SetupPacketReceiveCustom(Ipv4Address addr, Ptr<Node> node);
    /**
     * Receive a packet.
     * \param socket The receiving socket.
     */
    void ReceivePacket(Ptr<Socket> socket);
    /**
     * Compute the throughput.
     */
    void CheckThroughput();

    uint32_t port{9};            //!< Receiving port number.
    uint32_t bytesTotal{0};      //!< Total received bytes.
    uint32_t packetsReceived{0}; //!< Total received packets.

    std::string m_CSVfileName{"manet-routing.output.csv"}; //!< CSV filename.
    //int m_nSinks{10};                                      //!< Number of sink nodes.
    int m_nWifis{50};                                      //!< Number of nodes.
    std::string m_protocolName{"AODV"};                    //!< Protocol name.
    double m_txp{7.5};                                     //!< Tx power.
    bool m_traceMobility{false};                           //!< Enable mobility tracing.
    bool m_netAnim{false};                           //!< Enable mobility tracing.
    bool m_enableMalicious{false};                           //!< Enable malicious nodes.
    std::string m_traceFile{"manet-trace.ns2"};                           //!< Trace file for mobility.
    std::string m_startFile{"manet-trace.init"};                           //!< Start file for mobility.
    std::string m_csvLogFile{"manet-routing.output.log.csv"};                           //!< Start file for mobility.
    std::string m_filePath{"/home/andrew/ns-3-dev/scratch/lesap-compare/"};                           //!< Start file for mobility.
    std::string m_filePathResults{"/home/andrew/Documents/thesis/resultsLogging/"};//"/home/andrew/ns-3-dev/results/lesap-compare/"};                           //!< Start file for mobility.
    std::string m_filePathResultsPcap{"/media/andrew/Secondary/thesis/pcap/"};//"/home/andrew/ns-3-dev/results/lesap-compare/"};                           //!< Start file for mobility.
    std::string m_simsToRun{"aodv-all"};                           //!< Start file for mobility.
    bool m_flowMonitor{true};                             //!< Enable FlowMonitor.
};

RoutingExperiment::RoutingExperiment()
{
}

// Prints actual position and velocity when a course change event occurs
static void
CourseChange(std::string foo, Ptr<const MobilityModel> mobility)
{
    std::ostringstream oss;
    Vector pos = mobility->GetPosition(); // Get position
    Vector vel = mobility->GetVelocity(); // Get velocity

    // Prints position and velocities
    oss << Simulator::Now() << " POS: x=" << pos.x << ", y=" << pos.y << ", z=" << pos.z
        << "; VEL:" << vel.x << ", y=" << vel.y << ", z=" << vel.z << std::endl;
}

static inline std::string
PrintReceivedPacket(Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress)
{
    std::ostringstream oss;

    oss << Simulator::Now().GetSeconds() << " " << socket->GetNode()->GetId();

    if (InetSocketAddress::IsMatchingType(senderAddress))
    {
        InetSocketAddress addr = InetSocketAddress::ConvertFrom(senderAddress);
        oss << " received one packet from " << addr.GetIpv4();
    }
    else
    {
        oss << " received one packet!";
    }
    return oss.str();
}

void
RoutingExperiment::SetProtocol(std::string protocol)
{
    m_protocolName = protocol;
    m_CSVfileName = m_protocolName + "." + std::to_string(m_nWifis) + "." + (m_enableMalicious ? "mal" : "normal") + ".csv";
    m_csvLogFile = m_protocolName + "." + std::to_string(m_nWifis) + "." + (m_enableMalicious ? "mal" : "normal") + ".log.csv";
}

void
RoutingExperiment::SetMalicious(bool mal)
{
    m_CSVfileName = m_protocolName + "." + std::to_string(m_nWifis) + "." + (m_enableMalicious ? "mal" : "normal") + ".csv";
    m_csvLogFile = m_protocolName + "." + std::to_string(m_nWifis) + "." + (m_enableMalicious ? "mal" : "normal") + ".log.csv";
    m_enableMalicious = mal;
}

void RoutingExperiment::SetNNodeWTrace(std::string nNodes){
    m_nWifis = stoi(nNodes);
    m_traceFile = nNodes + ".ns2";
    m_startFile = nNodes + ".init";
    m_CSVfileName = m_protocolName + "." + std::to_string(m_nWifis) + "." + (m_enableMalicious ? "mal" : "normal") + ".csv";
    m_csvLogFile = m_protocolName + "." + std::to_string(m_nWifis) + "." + (m_enableMalicious ? "mal" : "normal") + ".log.csv";
}

void 
RoutingExperiment::TurnOffFlowmon()
{
    m_flowMonitor = false;
}

void
RoutingExperiment::ReceivePacket(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address senderAddress;
    while ((packet = socket->RecvFrom(senderAddress)))
    {
        bytesTotal += packet->GetSize();
        packetsReceived += 1;
        NS_LOG_UNCOND(PrintReceivedPacket(socket, packet, senderAddress));
    }
}

void
RoutingExperiment::CheckThroughput()
{
    double kbs = (bytesTotal * 8.0) / 1000;
    bytesTotal = 0;

    std::ofstream out(m_filePathResults + m_CSVfileName, std::ios::app);

    out << (Simulator::Now()).GetSeconds() << "," << kbs << "," << packetsReceived << ","
        << m_protocolName << "," << m_txp << "" << std::endl;

    out.close();
    packetsReceived = 0;
    Simulator::Schedule(Seconds(1.0), &RoutingExperiment::CheckThroughput, this);
}

Ptr<Socket>
RoutingExperiment::SetupPacketReceive(Ipv4Address addr, Ptr<Node> node)
{
    InetSocketAddress local(InetSocketAddress(addr, port));

    Ptr<Socket> ns3UdpSocket = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    ns3UdpSocket->TraceConnectWithoutContext("CongestionWindow", MakeCallback(&CwndChange));


        //InetSocketAddress local = InetSocketAddress(addr, port);
        ns3UdpSocket->Bind(local);
        ns3UdpSocket->SetRecvCallback(MakeCallback(&RoutingExperiment::ReceivePacket, this));
    //Ptr<BsmApp> app = CreateObject<BsmApp>();
    //app->Setup(ns3UdpSocket, local, 64, 1000, DataRate("2048bps"));
    //ns3UdpSocket->SetRecvCallback(MakeCallback(&RoutingExperiment::ReceivePacket, this));
    //node->AddApplication(app);
    //app->SetStartTime(Seconds(start));
    //app->SetStopTime(Seconds(end));


    return ns3UdpSocket;
}

Ptr<BsmApp>
RoutingExperiment::SetupPacketReceiveCustom(Ipv4Address addr, Ptr<Node> node)
{
    InetSocketAddress local(InetSocketAddress(addr, port));

    Ptr<Socket> ns3UdpSocket = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
    ns3UdpSocket->TraceConnectWithoutContext("CongestionWindow", MakeCallback(&CwndChange));


        Ptr<BsmApp> app = CreateObject<BsmApp>();
        app->Setup(ns3UdpSocket, local, 64, 1000, DataRate("2048bps"));
        ns3UdpSocket->SetRecvCallback(MakeCallback(&RoutingExperiment::ReceivePacket, this));

    //Ptr<BsmApp> app = CreateObject<BsmApp>();
    //app->Setup(ns3UdpSocket, local, 64, 1000, DataRate("2048bps"));
    //ns3UdpSocket->SetRecvCallback(MakeCallback(&RoutingExperiment::ReceivePacket, this));
    //node->AddApplication(app);
    //app->SetStartTime(Seconds(start));
    //app->SetStopTime(Seconds(end));


    return app;
}

void
RoutingExperiment::CommandSetup(int argc, char** argv)
{
    CommandLine cmd(__FILE__);
    cmd.AddValue("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
    cmd.AddValue("traceMobility", "Enable mobility tracing", m_traceMobility);
    cmd.AddValue("netAnim", "Enable mobility tracing", m_netAnim);
    cmd.AddValue("protocol", "Routing protocol (AODV, LESAP-AODV)", m_protocolName);
    cmd.AddValue("flowMonitor", "enable FlowMonitor", m_flowMonitor);
    cmd.AddValue("tracefile", "Trace File to use", m_traceFile);
    cmd.AddValue("startfile", "start File to use", m_startFile);
    cmd.AddValue("nNodes", "Number of nodes to use", m_nWifis);
    cmd.AddValue("filedirectory", "Path to directory of files to use", m_filePath);
    cmd.AddValue("sims", "Simulations to run", m_simsToRun);
    cmd.Parse(argc, argv);

    std::vector<std::string> allowedProtocols{"AODV", "LESAP-AODV"};

    if (std::find(std::begin(allowedProtocols), std::end(allowedProtocols), m_protocolName) ==
        std::end(allowedProtocols))
    {
        NS_FATAL_ERROR("No such protocol:" << m_protocolName);
    }
}

int
main(int argc, char* argv[])
{
    std::string simsToRun;
    CommandLine cmd(__FILE__);
    cmd.AddValue("sims", "Simulations to run", simsToRun);
    cmd.Parse(argc, argv);

    if(simsToRun.find("aodv") != std::string::npos)
    {
        std::cout << "**AODV**" << std::endl;

        if(simsToRun.find("all") != std::string::npos || simsToRun.find("25") != std::string::npos)
        {
            std::cout << "**25 Nodes**" << std::endl;
            RoutingExperiment experimentAODV25;
            experimentAODV25.CommandSetup(argc, argv);
            experimentAODV25.SetProtocol("AODV");
            experimentAODV25.SetNNodeWTrace("25");
            experimentAODV25.SetMalicious(false);
            experimentAODV25.Run();

            std::cout << "**25 Nodes w/malicious**" << std::endl;
            RoutingExperiment experimentAODV25Mal;
            experimentAODV25Mal.CommandSetup(argc, argv);
            experimentAODV25Mal.SetProtocol("AODV");
            experimentAODV25Mal.SetNNodeWTrace("25");
            experimentAODV25Mal.SetMalicious(true);
            experimentAODV25Mal.Run();
        }
        if(simsToRun.find("all") != std::string::npos || simsToRun.find("50") != std::string::npos)
        {
            std::cout << "**50 Nodes**" << std::endl;
            RoutingExperiment experimentAODV50;
            experimentAODV50.CommandSetup(argc, argv);
            experimentAODV50.SetProtocol("AODV");
            experimentAODV50.SetNNodeWTrace("50");
            experimentAODV50.SetMalicious(false);
            experimentAODV50.Run();

            std::cout << "**50 Nodes w/malicious**" << std::endl;
            RoutingExperiment experimentAODV50Mal;
            experimentAODV50Mal.CommandSetup(argc, argv);
            experimentAODV50Mal.SetProtocol("AODV");
            experimentAODV50Mal.SetNNodeWTrace("50");
            experimentAODV50Mal.SetMalicious(true);
            experimentAODV50Mal.Run();
        }
        if(simsToRun.find("all") != std::string::npos || simsToRun.find("100") != std::string::npos)
        {
            std::cout << "**100 Nodes**" << std::endl;
            RoutingExperiment experimentAODV100;
            experimentAODV100.CommandSetup(argc, argv);
            experimentAODV100.SetProtocol("AODV");
            experimentAODV100.SetNNodeWTrace("100");
            experimentAODV100.SetMalicious(false);
            experimentAODV100.Run();

            std::cout << "**100 Nodes w/malicious**" << std::endl;
            RoutingExperiment experimentAODV100Mal;
            experimentAODV100Mal.CommandSetup(argc, argv);
            experimentAODV100Mal.SetProtocol("AODV");
            experimentAODV100Mal.SetNNodeWTrace("100");
            experimentAODV100Mal.SetMalicious(true);
            experimentAODV100Mal.Run();
        }
    }

    if(simsToRun.find("lesap") != std::string::npos)
    {
        std::cout << "**LESAP-AODV**" << std::endl;

        if (simsToRun.find("all") != std::string::npos || simsToRun.find("25") != std::string::npos)
        {
            if (simsToRun.find("norm") != std::string::npos)
            {
                std::cout << "**25 Nodes**" << std::endl;
                RoutingExperiment experimentLESAPAODV25;
                experimentLESAPAODV25.CommandSetup(argc, argv);
                experimentLESAPAODV25.SetProtocol("LESAP-AODV");
                experimentLESAPAODV25.SetNNodeWTrace("25");
                experimentLESAPAODV25.SetMalicious(false);
                experimentLESAPAODV25.Run();
            }
            if(simsToRun.find("mal") != std::string::npos){
                std::cout << "**25 Nodes w/malicious**" << std::endl;
                RoutingExperiment experimentLESAPAODV25Mal;
                experimentLESAPAODV25Mal.CommandSetup(argc, argv);
                experimentLESAPAODV25Mal.SetProtocol("LESAP-AODV");
                experimentLESAPAODV25Mal.SetNNodeWTrace("25");
                experimentLESAPAODV25Mal.SetMalicious(true);
                experimentLESAPAODV25Mal.Run();
            }
        }
        if (simsToRun.find("all") != std::string::npos || simsToRun.find("50") != std::string::npos)
        {
            if (simsToRun.find("norm") != std::string::npos)
            {
                std::cout << "**50 Nodes**" << std::endl;
                RoutingExperiment experimentLESAPAODV50;
                experimentLESAPAODV50.CommandSetup(argc, argv);
                experimentLESAPAODV50.SetProtocol("LESAP-AODV");
                experimentLESAPAODV50.SetNNodeWTrace("50");
                experimentLESAPAODV50.SetMalicious(false);
                experimentLESAPAODV50.Run();
            }
            if (simsToRun.find("mal") != std::string::npos)
            {
                std::cout << "**50 Nodes w/malicious**" << std::endl;
                RoutingExperiment experimentLESAPAODV50Mal;
                experimentLESAPAODV50Mal.CommandSetup(argc, argv);
                experimentLESAPAODV50Mal.SetProtocol("LESAP-AODV");
                experimentLESAPAODV50Mal.SetNNodeWTrace("50");
                experimentLESAPAODV50Mal.SetMalicious(true);
                experimentLESAPAODV50Mal.Run();
            }
        }
        if (simsToRun.find("all") != std::string::npos || simsToRun.find("100") != std::string::npos)
        {
            if (simsToRun.find("norm") != std::string::npos)
            {
                std::cout << "**100 Nodes**" << std::endl;
                RoutingExperiment experimentLESAPAODV100;
                experimentLESAPAODV100.CommandSetup(argc, argv);
                experimentLESAPAODV100.SetProtocol("LESAP-AODV");
                experimentLESAPAODV100.SetNNodeWTrace("100");
                experimentLESAPAODV100.SetMalicious(false);
                experimentLESAPAODV100.Run();
            }
            if (simsToRun.find("mal") != std::string::npos)
            {
                std::cout << "**100 Nodes w/malicious**" << std::endl;
                RoutingExperiment experimentLESAPAODV100Mal;
                experimentLESAPAODV100Mal.CommandSetup(argc, argv);
                experimentLESAPAODV100Mal.SetProtocol("LESAP-AODV");
                experimentLESAPAODV100Mal.SetNNodeWTrace("100");
                experimentLESAPAODV100Mal.SetMalicious(true);
                experimentLESAPAODV100Mal.Run();
            }
        }
    }

    return 0;
}

void
RoutingExperiment::Run()
{
    Packet::EnablePrinting();

    // blank out the last output file and write the column headers
    m_CSVfileName = m_protocolName + "." + std::to_string(m_nWifis) + "." + (m_enableMalicious ? "mal" : "normal") + ".csv";
    m_csvLogFile = m_protocolName + "." + std::to_string(m_nWifis) + "." + (m_enableMalicious ? "mal" : "normal") + ".log.csv";
    std::ofstream out(m_filePathResults + m_CSVfileName);
    out << "SimulationSecond,"
        << "ReceiveRate,"
        << "PacketsReceived,"
        << "RoutingProtocol,"
        << "TransmissionPower" << std::endl;
    out.close();

    std::ofstream finalOut(m_filePathResults + m_csvLogFile);
    finalOut << "SimulationTime,"
        << "PacketID,"
        << "PacketStatus,"
        << "PacketSize,"
        << "NodeIP,"
        << "SenderIP,"
        << "Reason" << std::endl;
    finalOut.close();

    int nWifis = m_nWifis;

    //double TotalTime = 200.0;
    std::string rate("2048bps");
    std::string phyMode("DsssRate11Mbps");

    std::string tr_name(m_CSVfileName);
    tr_name.erase(tr_name.find(".csv"));
    //int nodeSpeed = 20; // in m/s
    //int nodePause = 0;  // in s

    //Config::SetDefault("ns3::OnOffApplication::PacketSize", StringValue("64"));
    //Config::SetDefault("ns3::OnOffApplication::DataRate", StringValue(rate));

    // Set Non-unicastMode rate to unicast mode
    Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));

    NodeContainer adhocNodes;
    adhocNodes.Create(nWifis);

    // setting up wifi phy and channel using helpers
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper wifiPhy;
    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel");
    wifiPhy.SetChannel(wifiChannel.Create());

    // Add a mac and disable rate control
    WifiMacHelper wifiMac;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue(phyMode),
                                 "ControlMode",
                                 StringValue(phyMode));

    wifiPhy.Set("TxPowerStart", DoubleValue(m_txp));
    wifiPhy.Set("TxPowerEnd", DoubleValue(m_txp));

    wifiMac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer adhocDevices = wifi.Install(wifiPhy, wifiMac, adhocNodes);

    //NS2 Trace file mobility
    Ns2NodeStart ns2Start = Ns2NodeStart(m_filePath + m_startFile);
    Ns2MobilityHelper ns2 = Ns2MobilityHelper(m_filePath + m_traceFile);
    ns2.Install();
    // Configure callback for logging
    Config::Connect("/NodeList/*/$ns3::MobilityModel/CourseChange",
                    MakeBoundCallback(&CourseChange));
    /*//OLD Mobility
    MobilityHelper mobilityAdhoc;
    int64_t streamIndex = 0; // used to get consistent mobility across scenarios

    ObjectFactory pos;
    pos.SetTypeId("ns3::RandomRectanglePositionAllocator");
    pos.Set("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
    pos.Set("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"));

    Ptr<PositionAllocator> taPositionAlloc = pos.Create()->GetObject<PositionAllocator>();
    streamIndex += taPositionAlloc->AssignStreams(streamIndex);

    std::stringstream ssSpeed;
    ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
    std::stringstream ssPause;
    ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
    mobilityAdhoc.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                   "Speed",
                                   StringValue(ssSpeed.str()),
                                   "Pause",
                                   StringValue(ssPause.str()),
                                   "PositionAllocator",
                                   PointerValue(taPositionAlloc));
    mobilityAdhoc.SetPositionAllocator(taPositionAlloc);
    mobilityAdhoc.Install(adhocNodes);
    streamIndex += mobilityAdhoc.AssignStreams(adhocNodes, streamIndex);
    */

    AodvHelper aodv;
    LesapAodvHelper lesapAodv;
    Ipv4ListRoutingHelper list;
    InternetStackHelper internet;

    if (m_protocolName == "AODV")
    {
        list.Add(aodv, 100);
        internet.SetRoutingHelper(list);
        internet.Install(adhocNodes);
    }
    else if (m_protocolName == "LESAP-AODV")
    {
        list.Add(lesapAodv, 100);
        internet.SetRoutingHelper(list);
        internet.Install(adhocNodes);

    }
    else
    {
        NS_FATAL_ERROR("No such protocol:" << m_protocolName);
    }

    NS_LOG_INFO("assigning ip address");

    Ipv4AddressHelper addressAdhoc;
    addressAdhoc.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer adhocInterfaces;
    adhocInterfaces = addressAdhoc.Assign(adhocDevices);

    // Setting up Malicious nodes and starting reports
    if (m_protocolName == "AODV")
    {
        if(m_enableMalicious){
            for (int i = 0; i < m_nWifis; i++)
            {
                Ptr<aodv::RoutingProtocol> protocol = adhocNodes.Get(i)->GetObject<aodv::RoutingProtocol>();
                if (i % 5 == 0)
                {
                    if (i % 10 == 0)
                    {
                        protocol->SetNodeType(ns3::aodv::AODVSYBIL);
                    }
                    else
                    {
                        protocol->SetNodeType(ns3::aodv::AODVBLACKHOLE);
                    }
                }
            }
        }
    }
    else if (m_protocolName == "LESAP-AODV")
    {
        if(m_enableMalicious){
            bool addReport = false;
            for (int i = 0; i < m_nWifis; i++)
            {
                Ptr<lesapAodv::RoutingProtocol> protocol = adhocNodes.Get(i)->GetObject<lesapAodv::RoutingProtocol>();
                if (i % 5 == 0)
                {
                    if (i % 10 == 0)
                    {
                        protocol->SetNodeType(ns3::lesapAodv::LESAPAODVSYBIL);
                    }
                    else
                    {
                        protocol->SetNodeType(ns3::lesapAodv::LESAPAODVBLACKHOLE);
                    }
                    addReport = true;
                }
                if (addReport && (i % 5 == 1 || i % 5 == 2))
                {
                    // set starting reports

                    lesapAodv::ReportTableEntry newEntry(adhocInterfaces.GetAddress((i - (i % 5))),
                                              adhocInterfaces.GetAddress(i),
                                              Time(Seconds(ns2Start.GetSimTime())));
                    protocol->AddToBlacklist(newEntry);
                    addReport = i % 5 != 2;
                }
            }
        }
    }


    bool useCustomApp = false;

    //Add applications
    for (int i = 0; i < m_nWifis; i++)
    {
        int j = i + 5;
        int k = i + 10;
        j = (j >= m_nWifis) ? (j - m_nWifis) : j;
        k = (k >= m_nWifis) ? (k - m_nWifis) : k;
        NS_LOG_UNCOND("LESAP-AODV Node " << i << " is setting up apps for "  << k << " and " << j);

        if(useCustomApp){
            // Address should be the reciever not sender

            // Add multiple with new setuppacketrecieve
            Ptr<BsmApp> app1 = SetupPacketReceiveCustom(adhocInterfaces.GetAddress(i), adhocNodes.Get(i));
            Ptr<BsmApp> app2 = SetupPacketReceiveCustom(adhocInterfaces.GetAddress(i), adhocNodes.Get(i));

            //Address sinkAddress(InetSocketAddress(adhocInterfaces.GetAddress(i), port));

            //Ptr<Socket> ns3UdpSocket = Socket::CreateSocket(adhocNodes.Get(i), UdpSocketFactory::GetTypeId());
            //ns3UdpSocket->TraceConnectWithoutContext("CongestionWindow", MakeCallback(&CwndChange));

            //Ptr<BsmApp> app = CreateObject<BsmApp>();
            //app->Setup(ns3UdpSocket, sinkAddress, 1040, 1000, DataRate("1Mbps"));
            adhocNodes.Get(j)->AddApplication(app1);
            adhocNodes.Get(k)->AddApplication(app2);
            app1->SetStartTime(Seconds(ns2Start.GetStartTimeForNode(j)));
            app2->SetStartTime(Seconds(ns2Start.GetStartTimeForNode(k)));
            app1->SetStopTime(Seconds(ns2Start.GetEndTimeForNode(j)));
            app2->SetStopTime(Seconds(ns2Start.GetEndTimeForNode(k)));
        }else{
            OnOffHelper onoff1("ns3::UdpSocketFactory", Address());
            onoff1.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff1.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
            onoff1.SetConstantRate(DataRate("1280bps"),128);

            Ptr<Socket> ns3UdpSocket = SetupPacketReceive(adhocInterfaces.GetAddress(i), adhocNodes.Get(i));

            AddressValue remoteAddress(InetSocketAddress(adhocInterfaces.GetAddress(i), port));
            onoff1.SetAttribute("Remote", remoteAddress);

            ApplicationContainer temp = onoff1.Install(adhocNodes.Get(j));
            ApplicationContainer temp2 = onoff1.Install(adhocNodes.Get(k));
            temp.Start(Seconds(ns2Start.GetStartTimeForNode(j)));
            temp2.Start(Seconds(ns2Start.GetStartTimeForNode(k)));
            temp.Stop(Seconds(ns2Start.GetEndTimeForNode(j)));
            temp2.Stop(Seconds(ns2Start.GetEndTimeForNode(k)));
        }
    }

    if(m_protocolName == "AODV"){
        for (int i = 0; i < m_nWifis; i++)
        {
            Ptr<aodv::RoutingProtocol> protocol = adhocNodes.Get(i)->GetObject<aodv::RoutingProtocol>();
            protocol->SetCsvFileName(m_filePathResults + m_csvLogFile);
        }
    }else if (m_protocolName == "LESAP-AODV"){
        for (int i = 0; i < m_nWifis; i++)
        {
            Ptr<lesapAodv::RoutingProtocol> protocol = adhocNodes.Get(i)->GetObject<lesapAodv::RoutingProtocol>();
            protocol->SetCsvFileName(m_filePathResults + m_csvLogFile);
        }
    }

    std::stringstream ss;
    ss << nWifis;
    std::string nodes = ss.str();

    //std::stringstream ss2;
    //ss2 << nodeSpeed;
    //std::string sNodeSpeed = ss2.str();

    //std::stringstream ss3;
    //ss3 << nodePause;
    //std::string sNodePause = ss3.str();

    std::stringstream ss4;
    ss4 << rate;
    std::string sRate = ss4.str();

    // NS_LOG_INFO("Configure Tracing.");
    // tr_name = tr_name + "_" + m_protocolName +"_" + nodes + "nodes_" + sNodeSpeed + "speed_" +
    // sNodePause + "pause_" + sRate + "rate";

    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> osw = ascii.CreateFileStream(m_filePathResults + tr_name + ".tr");
    wifiPhy.EnableAsciiAll(osw);
    // AsciiTraceHelper ascii;
    //MobilityHelper::EnableAsciiAll(ascii.CreateFileStream(m_filePathResults + tr_name + ".mob"));

    //internet.EnableAsciiIpv4All(m_filePathResultsPcap + "ipv4pcap/" + tr_name + ".ipv4");
    //internet.EnablePcapIpv4All(m_filePathResultsPcap + "ipv4pcap/" + tr_name + ".ipv4");
    wifiPhy.EnablePcapAll(m_filePathResultsPcap + tr_name, true);

    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> flowmon;
    if (m_flowMonitor)
    {
        flowmon = flowmonHelper.InstallAll();
    }

    NS_LOG_INFO("Run Simulation.");

    CheckThroughput();

    Simulator::Stop(Seconds(ns2Start.GetSimTime()));
    Simulator::Run();

    if (m_flowMonitor)
    {
        flowmon->SerializeToXmlFile(m_filePathResults + tr_name + ".flowmon", false, false);
    }

    Simulator::Destroy();
}
