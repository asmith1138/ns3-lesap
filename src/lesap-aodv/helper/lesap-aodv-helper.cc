/*
 * Copyright (c) 2009 IITP RAS
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
 * Authors: Andrew Smith <asmith1138@gmail.com>, written after AodvHelper by Pavel Boyko
 * <boyko@iitp.ru>
 */
#include "lesap-aodv-helper.h"

#include "../../mobility/model/mobility-model.h"

#include "ns3/ipv4-list-routing.h"
#include "ns3/lesap-aodv-routing-protocol.h"
#include "ns3/names.h"
#include "ns3/node-list.h"
#include "ns3/ptr.h"

namespace ns3
{

LesapAodvHelper::LesapAodvHelper()
    : Ipv4RoutingHelper()
{
    m_agentFactory.SetTypeId("ns3::lesapAodv::RoutingProtocol");
}

LesapAodvHelper*
LesapAodvHelper::Copy() const
{
    return new LesapAodvHelper(*this);
}

Ptr<Ipv4RoutingProtocol>
LesapAodvHelper::Create(Ptr<Node> node) const
{
    Ptr<lesapAodv::RoutingProtocol> agent = m_agentFactory.Create<lesapAodv::RoutingProtocol>();
    agent->SetDistanceFunction(&LesapAodvHelper::DistanceFromNode);
    node->AggregateObject(agent);
    return agent;
}

void
LesapAodvHelper::Set(std::string name, const AttributeValue& value)
{
    m_agentFactory.Set(name, value);
}

int64_t
LesapAodvHelper::AssignStreams(NodeContainer c, int64_t stream)
{
    int64_t currentStream = stream;
    Ptr<Node> node;
    for (auto i = c.Begin(); i != c.End(); ++i)
    {
        node = (*i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        NS_ASSERT_MSG(ipv4, "Ipv4 not installed on node");
        Ptr<Ipv4RoutingProtocol> proto = ipv4->GetRoutingProtocol();
        NS_ASSERT_MSG(proto, "Ipv4 routing not installed on node");
        Ptr<lesapAodv::RoutingProtocol> lesapAodv = DynamicCast<lesapAodv::RoutingProtocol>(proto);
        if (lesapAodv)
        {
            currentStream += lesapAodv->AssignStreams(currentStream);
            continue;
        }
        // Lesap-Aodv may also be in a list
        Ptr<Ipv4ListRouting> list = DynamicCast<Ipv4ListRouting>(proto);
        if (list)
        {
            int16_t priority;
            Ptr<Ipv4RoutingProtocol> listProto;
            Ptr<lesapAodv::RoutingProtocol> listLesapAodv;
            for (uint32_t i = 0; i < list->GetNRoutingProtocols(); i++)
            {
                listProto = list->GetRoutingProtocol(i, priority);
                listLesapAodv = DynamicCast<lesapAodv::RoutingProtocol>(listProto);
                if (listLesapAodv)
                {
                    currentStream += listLesapAodv->AssignStreams(currentStream);
                    break;
                }
            }
        }
    }
    return (currentStream - stream);
}

double
LesapAodvHelper::DistanceFromNode(Ipv4Address dest, Ipv4Address own)
{
    //Interface design
    Ptr<Node> ownNode;
    Ptr<Node> destNode;
    for (auto i = interfaces.Begin(); i != interfaces.End(); ++i)
    {
        if((*i).first->GetInterfaceForAddress(dest) != -1){
            ownNode = (*i).first->GetObject<Node>();
        }
        if((*i).first->GetInterfaceForAddress(own) != -1){
            destNode = (*i).first->GetObject<Node>();
        }
    }
    //Node design
    Ptr<Node> node;
    for (auto i = nodes.Begin(); i != nodes.End(); ++i)
    {
        node = (*i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        NS_ASSERT_MSG(ipv4, "Ipv4 not installed on node");

        if(ipv4->GetInterfaceForAddress(own) != -1){
            ownNode = node;
        }

        if(ipv4->GetInterfaceForAddress(dest) != -1){
            destNode = node;
        }
    }
    // Maybe this should be in the helper class
    // and use the new method I created to get the nodecontainer
    // therefore I can inject this as a callback into the node/routingproto class
    // with the nodecontainer already specified in the class.
    //uint32_t interface = m_ipv4->GetInterfaceForAddress(ipv4);
    //Ptr<NetDevice> s_netdevice = m_ipv4->GetNetDevice(interface);
    //Ptr<NetDevice> m_netdevice = m_ipv4->GetNetDevice(1);

    //Ptr<Node> m_node = m_netdevice->GetNode();
    //Ptr<Node> s_node = s_netdevice->GetNode();

    Ptr<MobilityModel> m_Mobility = ownNode->GetObject<MobilityModel>();
    Ptr<MobilityModel> s_Mobility = destNode->GetObject<MobilityModel>();

    return m_Mobility->GetDistanceFrom(s_Mobility);
}

void
LesapAodvHelper::SetNodeContainer(ns3::NodeContainer container)
{
    nodes = container;
}

void
LesapAodvHelper::SetInterfaceContainer(ns3::Ipv4InterfaceContainer container){
    interfaces = container;
}

} // namespace ns3
