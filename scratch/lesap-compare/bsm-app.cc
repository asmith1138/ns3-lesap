/*
 * Author: Andrew Smith <asmith1138@gmail.com>, written after
 * tutorial-app.h
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
 */

#include "bsm-app.h"

#include "ns3/applications-module.h"

using namespace ns3;

BsmApp::BsmApp()
    : m_socket(nullptr),
      m_peer(),
      m_packetSize(0),
      m_nPackets(0),
      m_dataRate(0),
      m_sendEvent(),
      m_running(false),
      m_packetsSent(0)
{
}

BsmApp::~BsmApp()
{
    m_socket = nullptr;
}

/* static */
TypeId
BsmApp::GetTypeId()
{
    static TypeId tid = TypeId("BsmApp")
                            .SetParent<Application>()
                            .SetGroupName("lesap-compare")
                            .AddConstructor<BsmApp>();
    return tid;
}

void
BsmApp::Setup(Ptr<Socket> socket,
                   Address address,
                   uint32_t packetSize,
                   uint32_t nPackets,
                   DataRate dataRate)
{
    m_socket = socket;
    m_peer = address;
    m_packetSize = packetSize;
    m_nPackets = nPackets;
    m_dataRate = dataRate;
    m_socket->Bind(m_peer);
}

void
BsmApp::StartApplication()
{
    m_running = true;
    m_packetsSent = 0;
    //m_socket->Bind(m_peer);
    //m_socket->Connect(m_peer);
    SendPacket();
}

void
BsmApp::StopApplication()
{
    m_running = false;

    if (m_sendEvent.IsRunning())
    {
        Simulator::Cancel(m_sendEvent);
    }

    if (m_socket)
    {
        m_socket->Close();
    }
}

void
BsmApp::SendPacket()
{
    Ptr<Packet> packet = Create<Packet>(m_packetSize);
    NS_LOG_UNCOND(PrintSentPacket(packet));
    m_socket->Send(packet);

    if (++m_packetsSent < m_nPackets)
    {
        ScheduleTx();
    }
}

void
BsmApp::ScheduleTx()
{
    if (m_running)
    {
        Time tNext(Seconds(m_packetSize * 8 / static_cast<double>(m_dataRate.GetBitRate())));
        NS_LOG_UNCOND(PrintSchedulePacket(tNext));
        m_sendEvent = Simulator::Schedule(tNext, &BsmApp::SendPacket, this);
    }
}
