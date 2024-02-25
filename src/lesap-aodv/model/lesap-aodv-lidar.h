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

#ifndef LESAP_AODVLIDAR_H
#define LESAP_AODVLIDAR_H

#include "ns3/arp-cache.h"
#include "ns3/callback.h"
#include "ns3/ipv4-address.h"
#include "ns3/simulator.h"
#include "ns3/timer.h"

#include <vector>

namespace ns3
{

class WifiMacHeader;

namespace lesapAodv
{

class RoutingProtocol;

/**
 * \ingroup lesapAodv
 * \brief maintain list of active neighbors
 */
class LidarNeighbors
{
  public:
    /**
     * constructor
     * \param delay the delay time for purging the list of neighbors
     */
    LidarNeighbors(Time delay);

    /// Lidar Neighbor description
    struct LidarNeighbor
    {
        /// Neighbor IPv4 address
        Ipv4Address m_neighborAddress;
        /// Neighbor MAC address
        Mac48Address m_hardwareAddress;
        /// Neighbor expire time
        Time m_expireTime;
        /// Neighbor close indicator
        bool close;

        uint64_t m_key1;   ///< 1st part of public key
        uint64_t m_key2;    ///< 2nd part of public key
        uint64_t m_key3;   ///< 3rd part of public key
        uint64_t m_key4;    ///< 4th part of public key
        uint32_t m_xVelocity;  ///< node velocity on x-axis
        uint32_t m_yVelocity;  ///< node velocity on y-axis
        uint32_t m_zVelocity;  ///< node velocity on z-axis
        uint32_t m_xPosition; ///< node position on x-axis
        uint32_t m_yPosition; ///< node position on y-axis
        uint32_t m_zPosition; ///< node position on z-axis
        Time m_timeSeen; ///< time node was seen on lidar
        /**
         * \brief Neighbor structure constructor
         *
         * \param ip Ipv4Address entry
         * \param mac Mac48Address entry
         * \param t Time expire time
         */
        LidarNeighbor(Ipv4Address ip, Mac48Address mac, Time t,
                      uint64_t key1, uint64_t key2, uint64_t key3, uint64_t key4,
                      uint32_t xv, uint32_t yv, uint32_t zv,
                      uint32_t x, uint32_t y, uint32_t z)
            : m_neighborAddress(ip),
              m_hardwareAddress(mac),
              m_expireTime(t),
              close(false),
              m_key1(key1),
              m_key2(key2),
              m_key3(key3),
              m_key4(key4),
              m_xVelocity(xv),
              m_yVelocity(yv),
              m_zVelocity(zv),
              m_xPosition(x),
              m_yPosition(y),
              m_zPosition(z)
        {
            m_timeSeen = Simulator::Now();
        }
    };

    /**
     * Return expire time for neighbor node with address addr, if exists, else return 0.
     * \param addr the IP address of the neighbor node
     * \returns the expire time for the neighbor node
     */
    Time GetExpireTime(Ipv4Address addr);
    /**
     * Check that node with address addr is neighbor
     * \param addr the IP address to check
     * \returns true if the node with IP address is a neighbor
     */
    bool IsNeighbor(Ipv4Address addr);
    /**
     * Update expire time for entry with address addr, if it exists, else add new entry
     * \param addr the IP address to check
     * \param expire the expire time for the address
     */
    void Update(Ipv4Address addr, Time expire);

    /**
     * Update entry with address addr, if it exists, else add new entry
     * \param addr the IP address to check
     * \param expire the expire time for the address
     * \param key1 the 1st part of the key
     * \param key2 the 2nd part of the key
     * \param key3 the 3rd part of the key
     * \param key4 the 4th part of the key
     * \param xVel the velocity of node on x-axis
     * \param yVel the velocity of node on y-axis
     * \param zVel the velocity of node on z-axis
     * \param xPos the position of node on x-axis
     * \param yPos the position of node on y-axis
     * \param zPos the position of node on z-axis
     */
    void Update(Ipv4Address addr, Time expire,
             uint64_t key1, uint64_t key2, uint64_t key3, uint64_t key4,
             uint32_t xVel,uint32_t yVel,uint32_t zVel,
             uint32_t xPos,uint32_t yPos,uint32_t zPos);

    /// Remove all expired entries
    void Purge();
    /// Schedule m_ntimer.
    void ScheduleTimer();

    /// Remove all entries
    void Clear()
    {
        m_nb.clear();
    }

    /**
     * Add ARP cache to be used to allow layer 2 notifications processing
     * \param a pointer to the ARP cache to add
     */
    void AddArpCache(Ptr<ArpCache> a);
    /**
     * Don't use given ARP cache any more (interface is down)
     * \param a pointer to the ARP cache to delete
     */
    void DelArpCache(Ptr<ArpCache> a);

    /**
     * Get callback to ProcessTxError
     * \returns the callback function
     */
    Callback<void, const WifiMacHeader&> GetTxErrorCallback() const
    {
        return m_txErrorCallback;
    }

    /**
     * Set link failure callback
     * \param cb the callback function
     */
    void SetCallback(Callback<void, Ipv4Address> cb)
    {
        m_handleLinkFailure = cb;
    }

    /**
     * Get link failure callback
     * \returns the link failure callback
     */
    Callback<void, Ipv4Address> GetCallback() const
    {
        return m_handleLinkFailure;
    }

  private:
    /// link failure callback
    Callback<void, Ipv4Address> m_handleLinkFailure;
    /// TX error callback
    Callback<void, const WifiMacHeader&> m_txErrorCallback;
    /// Timer for neighbor's list. Schedule Purge().
    Timer m_ntimer;
    /// vector of entries
    std::vector<LidarNeighbor> m_nb;
    /// list of ARP cached to be used for layer 2 notifications processing
    std::vector<Ptr<ArpCache>> m_arp;

    /**
     * Find MAC address by IP using list of ARP caches
     *
     * \param addr the IP address to lookup
     * \returns the MAC address for the IP address
     */
    Mac48Address LookupMacAddress(Ipv4Address addr);
    /**
     * Process layer 2 TX error notification
     * \param hdr header of the packet
     */
    void ProcessTxError(const WifiMacHeader& hdr);
};

} // namespace lesapAodv
} // namespace ns3

#endif /* LESAP_AODVLIDAR_H */
