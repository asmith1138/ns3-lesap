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
 * Based on
 *      NS-2 AODV model developed by the CMU/MONARCH group and optimized and
 *      tuned by Samir Das and Mahesh Marina, University of Cincinnati;
 *
 *      AODV-UU implementation by Erik Nordström of Uppsala University
 *      https://web.archive.org/web/20100527072022/http://core.it.uu.se/core/index.php/AODV-UU
 *
 * Authors: Andrew Smith <asmith1138@gmail.com>, written after
 *          AODV::Neighbors by
 *          Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */

#include "lesap-aodv-lidar.h"

#include "ns3/log.h"
#include "ns3/wifi-mac-header.h"

#include <algorithm>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("LesapAodvNeighbors");

namespace lesapAodv
{
LidarNeighbors::LidarNeighbors(Time delay)
    : m_ntimer(Timer::CANCEL_ON_DESTROY)
{
    m_ntimer.SetDelay(delay);
    m_ntimer.SetFunction(&LidarNeighbors::Purge, this);
    m_txErrorCallback = MakeCallback(&LidarNeighbors::ProcessTxError, this);
}

bool
LidarNeighbors::IsNeighbor(Ipv4Address addr)
{
    Purge();
    for (auto i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_neighborAddress == addr)
        {
            return true;
        }
    }
    return false;
}

Time
LidarNeighbors::GetExpireTime(Ipv4Address addr)
{
    Purge();
    for (auto i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_neighborAddress == addr)
        {
            return (i->m_expireTime - Simulator::Now());
        }
    }
    return Seconds(0);
}

void
LidarNeighbors::Update(Ipv4Address addr, Time expire)
{
    for (auto i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_neighborAddress == addr)
        {
            i->m_expireTime = std::max(expire + Simulator::Now(), i->m_expireTime);
            if (i->m_hardwareAddress == Mac48Address())
            {
                i->m_hardwareAddress = LookupMacAddress(i->m_neighborAddress);
            }
            return;
        }
    }
}

void
LidarNeighbors::Update(Ipv4Address addr, Time expire,
                       uint64_t key1, uint64_t key2, uint64_t key3, uint64_t key4,
                       uint32_t xVel,uint32_t yVel,uint32_t zVel,
                       uint32_t xPos,uint32_t yPos,uint32_t zPos)
{
    for (auto i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_neighborAddress == addr)
        {
            i->m_expireTime = std::max(expire + Simulator::Now(), i->m_expireTime);
            if (i->m_hardwareAddress == Mac48Address())
            {
                i->m_hardwareAddress = LookupMacAddress(i->m_neighborAddress);
            }
            i->m_key1 = key1;
            i->m_key2 = key2;
            i->m_key3 = key3;
            i->m_key4 = key4;
            i->m_xVelocity = xVel;
            i->m_yVelocity = yVel;
            i->m_zVelocity = zVel;
            i->m_xPosition = xPos;
            i->m_yPosition = yPos;
            i->m_zPosition = zPos;
            return;
        }
    }

    NS_LOG_LOGIC("Open link to " << addr);
    LidarNeighbor neighbor(addr, LookupMacAddress(addr), expire + Simulator::Now(),
                           key1, key2, key3, key4,
                           xVel, yVel, zVel, xPos, yPos, zPos);
    m_nb.push_back(neighbor);
    Purge();
}

/**
 * \brief CloseNeighbor structure
 */
struct CloseLidarNeighbor
{
    /**
     * Check if the entry is expired
     *
     * \param nb Neighbors::Neighbor entry
     * \return true if expired, false otherwise
     */
    bool operator()(const LidarNeighbors::LidarNeighbor& nb) const
    {
        return ((nb.m_expireTime < Simulator::Now()) || nb.close);
    }
};

void
LidarNeighbors::Purge()
{
    if (m_nb.empty())
    {
        return;
    }

    CloseLidarNeighbor pred;
    if (!m_handleLinkFailure.IsNull())
    {
        for (auto j = m_nb.begin(); j != m_nb.end(); ++j)
        {
            if (pred(*j))
            {
                NS_LOG_LOGIC("Close link to " << j->m_neighborAddress);
                m_handleLinkFailure(j->m_neighborAddress);
            }
        }
    }
    m_nb.erase(std::remove_if(m_nb.begin(), m_nb.end(), pred), m_nb.end());
    m_ntimer.Cancel();
    m_ntimer.Schedule();
}

void
LidarNeighbors::ScheduleTimer()
{
    m_ntimer.Cancel();
    m_ntimer.Schedule();
}

void
LidarNeighbors::AddArpCache(Ptr<ArpCache> a)
{
    m_arp.push_back(a);
}

void
LidarNeighbors::DelArpCache(Ptr<ArpCache> a)
{
    m_arp.erase(std::remove(m_arp.begin(), m_arp.end(), a), m_arp.end());
}

Mac48Address
LidarNeighbors::LookupMacAddress(Ipv4Address addr)
{
    Mac48Address hwaddr;
    for (auto i = m_arp.begin(); i != m_arp.end(); ++i)
    {
        ArpCache::Entry* entry = (*i)->Lookup(addr);
        if (entry != nullptr && (entry->IsAlive() || entry->IsPermanent()) && !entry->IsExpired())
        {
            hwaddr = Mac48Address::ConvertFrom(entry->GetMacAddress());
            break;
        }
    }
    return hwaddr;
}

void
LidarNeighbors::ProcessTxError(const WifiMacHeader& hdr)
{
    Mac48Address addr = hdr.GetAddr1();

    for (auto i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_hardwareAddress == addr)
        {
            i->close = true;
        }
    }
    Purge();
}

} // namespace lesapAodv
} // namespace ns3
