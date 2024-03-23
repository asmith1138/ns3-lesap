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
 *          AODV::RoutingTableEntry by
 *          Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */
#ifndef LESAP_AODV_RPTTABLE_H
#define LESAP_AODV_RPTTABLE_H

#include "ns3/ipv4-route.h"
#include "ns3/ipv4.h"
#include "ns3/net-device.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/timer.h"

#include <cassert>
#include <map>
#include <stdint.h>
#include <sys/types.h>

namespace ns3
{
namespace lesapAodv
{

/**
 * \ingroup lesapAodv
 * \brief Route record states
 */
enum ReportFlags
{
    REPORT_VALID = 0,     //!< VALID
    REPORT_INVALID = 1,   //!< INVALID
    REPORT_IN_SEARCH = 2, //!< IN_SEARCH
};

/**
 * \ingroup lesapAodv
 * \brief Routing table entry
 */
class ReportTableEntry
{
  public:
    /**
     * constructor
     *
     * \param dst the destination IP address
     * \param origin the IP address of the next hop
     * \param lifetime the lifetime of the entry
     */
    ReportTableEntry(Ipv4Address mal = Ipv4Address(),
                      Ipv4Address origin = Ipv4Address(),
                      Time lifetime = Simulator::Now());

    ~ReportTableEntry();

    ///\name Precursors management
    //\{
    /**
     * Insert precursor in precursor list if it doesn't yet exist in the list
     * \param id precursor address
     * \return true on success
     */
    bool InsertPrecursor(Ipv4Address id, Time expires);
    /**
     * Update precursor in precursor list to a later expiration
     * \param id precursor address
     * \param expires time precursor expires
     * \return true on success
     */
    bool UpdatePrecursorTimeout(Ipv4Address id, Time expires);
    /**
     * Lookup precursor by address
     * \param id precursor address
     * \return true on success
     */
    bool LookupPrecursor(Ipv4Address id);
    /**
     * \brief Delete precursor
     * \param id precursor address
     * \return true on success
     */
    bool DeletePrecursor(Ipv4Address id);
    /// Delete all precursors
    void DeleteAllPrecursors();
    /// Purge expired precursors
    void PurgePrecursors();
    /**
     * Check that precursor list is empty
     * \return true if precursor list is empty
     */
    bool IsPrecursorListEmpty() const;
    /**
     * Inserts precursors in output parameter prec if they do not yet exist in vector
     * \param prec vector of precursor addresses
     */
    void GetPrecursors(std::map<Ipv4Address,Time>& prec) const;
    //\}


    /**
     * Mark entry as "down" (i.e. disable it)
     * \param badLinkLifetime duration to keep entry marked as invalid
     */
    void Invalidate(Time badLinkLifetime);

    // Fields
    /**
     * Get malicious node address function
     * \returns the IPv4 address of malicious
     */
    Ipv4Address GetMaliciousAddr() const
    {
        return m_maliciousNodeAddr;
    }

    /**
     * Get origin function
     * \returns The origin of accusation
     */
    Ipv4Address GetOrigin() const
    {
        return m_originAddress;
    }

    /**
     * Set route function
     * \param mal the IPv4address of accused
     */
    void SetMaliciousNodeAddr(Ipv4Address mal)
    {
        m_maliciousNodeAddr = mal;
    }

    /**
     * Set origin address
     * \param origin the origin address of accusation
     */
    void SetOrigin(Ipv4Address origin)
    {
        m_originAddress = origin;
    }

    /**
     * Set the lifetime
     * \param lt The lifetime
     */
    void SetLifeTime(Time lt)
    {
        m_lifeTime = lt + Simulator::Now();
    }

    /**
     * Get the lifetime
     * \returns the lifetime
     */
    Time GetLifeTime() const
    {
        return m_lifeTime - Simulator::Now();
    }

    /**
     * Set the route flags
     * \param flag the route flags
     */
    void SetFlag(ReportFlags flag)
    {
        m_flag = flag;
    }

    /**
     * Get the route flags
     * \returns the route flags
     */
    ReportFlags GetFlag() const
    {
        return m_flag;
    }

    /**
     * Set the Report count
     * \param n the Report count
     */
    void SetRepCnt(uint8_t n)
    {
        m_repCount = n;
    }

    /**
     * Get the Report count
     * \returns the Report count
     */
    uint8_t GetRepCnt() const
    {
        return m_repCount;
    }

    /**
     * Increment the Report count
     */
    void IncrementRepCnt()
    {
        m_repCount++;
    }

    /**
     * Decrement the Report count
     */
    void DecrementRepCnt()
    {
        m_repCount--;
    }

    /**
     * Set the unidirectional flag
     * \param u the uni directional flag
     */
    void SetBlacklisted(bool u)
    {
        m_blackListState = u;
    }

    /**
     * Get the blacklist flag
     * \returns the blacklist flag
     */
    bool IsBlacklisted() const
    {
        return m_blackListState;
    }

    /**
     * Set the blacklist timeout
     * \param t the blacklist timeout value
     */
    void SetBlacklistTimeout(Time t)
    {
        m_blackListTimeout = t;
    }

    /**
     * Get the blacklist timeout value
     * \returns the blacklist timeout value
     */
    Time GetBlacklistTimeout() const
    {
        return m_blackListTimeout;
    }

    /// RREP_ACK timer
    Timer m_ackTimer;

    /**
     * \brief Compare destination address
     * \param dst IP address to compare
     * \return true if equal
     */
    bool operator==(const Ipv4Address mal) const
    {
        return (m_maliciousNodeAddr == mal);
    }

    /**
     * Print packet to trace file
     * \param stream The output stream
     * \param unit The time unit to use (default Time::S)
     */
    void Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const;

  private:
    /**
     * \brief Expiration or deletion time of the route
     * Lifetime field in the routing table plays dual role:
     * for an active route it is the expiration time, and for an invalid route
     * it is the deletion time.
     */
    Time m_lifeTime;

    // address of malicious node
    Ipv4Address m_maliciousNodeAddr;
    // address of origin node
    Ipv4Address m_originAddress;

    /// Routing flags: valid, invalid or in search
    ReportFlags m_flag;

    /// List of precursors
    /// TODO: not implemented fully yet(list of other nodes that endorse this report)
    std::map<Ipv4Address, Time> m_precursorList;
    /// When I can send another report
    Time m_routeReportTimeout;
    /// Number of reports of this node
    uint8_t m_repCount;
    /// Indicate if this entry is in "blacklist"
    bool m_blackListState;
    /// Time for which the node is put into the blacklist
    Time m_blackListTimeout;
};

/**
 * \ingroup lesapAodv
 * \brief The Routing table used by LESAP-AODV protocol
 */
class ReportTable
{
  public:
    /**
     * constructor
     * \param t the routing table entry lifetime
     */
    ReportTable(Time t, uint8_t reportLimit);

    ///\name Handle lifetime of invalid route
    /**
     * Add routing table entry if it doesn't yet exist in routing table
     * \param r routing table entry
     * \return true in success
     */
    bool AddReport(ReportTableEntry& r);
    /**
     * Delete routing table entry with destination address dst, if it exists.
     * \param dst destination address
     * \return true on success
     */
    bool DeleteReport(Ipv4Address dst);
    /**
     * Lookup routing table entry with destination address dst
     * \param dst destination address
     * \param rt entry with destination address dst, if exists
     * \return true on success
     */
    bool LookupReport(Ipv4Address dst, ReportTableEntry& rt);
    /**
     * Lookup route in VALID state
     * \param dst destination address
     * \param rt entry with destination address dst, if exists
     * \return true on success
     */
    bool LookupValidReport(Ipv4Address dst, ReportTableEntry& rt);
    /**
     * Update routing table
     * \param rt entry with destination address dst, if exists
     * \return true on success
     */
    bool Update(ReportTableEntry& rt);
    /**
     * Set routing table entry flags
     * \param dst destination address
     * \param state the routing flags
     * \return true on success
     */
    bool SetEntryState(Ipv4Address dst, ReportFlags state);
    /**
     * Update routing entries with this destination as follows:
     * 1. The destination sequence number of this routing entry, if it
     *    exists and is valid, is incremented.
     * 2. The entry is invalidated by marking the route entry as invalid
     * 3. The Lifetime field is updated to current time plus DELETE_PERIOD.
     * \param unreachable routes to invalidate
     */
    void InvalidateReportsWithMal(const std::map<Ipv4Address, uint32_t>& unreachable);

    void ValidateReports();

    bool ValidateReports(Ipv4Address id);

    std::vector<ReportTableEntry> GetValidReports();

    /// Delete all entries from routing table
    void Clear()
    {
        m_ipv4AddressEntry.clear();
    }

    /// Delete all outdated entries and invalidate valid entry if Lifetime is expired
    void Purge();
    /**
     * Print routing table
     * \param stream the output stream
     * \param unit The time unit to use (default Time::S)
     */
    void Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const;

  private:
    /// The routing table
    std::map<Ipv4Address, ReportTableEntry> m_ipv4AddressEntry;
    /// Deletion time for invalid routes
    Time m_badLinkLifetime;
    uint8_t m_reportLimit;
    /**
     * const version of Purge, for use by Print() method
     * \param table the routing table entry to purge
     */
    void Purge(std::map<Ipv4Address, ReportTableEntry>& table) const;
};

} // namespace lesapAodv
} // namespace ns3

#endif /* LESAP_AODV_RPTTABLE_H */
