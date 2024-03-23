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

#include "lesap-aodv-rpttable.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <algorithm>
#include <iomanip>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("LesapAodvReportTable");

namespace lesapAodv
{

/*
 The Report Table
 */
ReportTableEntry::ReportTableEntry(Ipv4Address mal,
                                     Ipv4Address origin,
                                     Time lifetime)
    : m_ackTimer(Timer::CANCEL_ON_DESTROY),
      m_lifeTime(lifetime + Simulator::Now()),
      m_maliciousNodeAddr(mal),
      m_originAddress(origin),
      m_flag(REPORT_IN_SEARCH),
      m_repCount(0),
      m_blackListState(false),
      m_blackListTimeout(Simulator::Now())
{

}

ReportTableEntry::~ReportTableEntry()
{
}

bool
ReportTableEntry::InsertPrecursor(Ipv4Address id, Time expires)
{
    NS_LOG_FUNCTION(this << id);
    if (!LookupPrecursor(id))
    {
        //std::map<Ipv4Address, Time> precurser;
        m_precursorList.insert(std::make_pair(id,expires+Simulator::Now()));
        IncrementRepCnt();
        //m_precursorList.push_back(precurser);
        return true;
    }
    else
    {
        return false;
    }
}

bool
ReportTableEntry::UpdatePrecursorTimeout(Ipv4Address id, Time expires)
{
    NS_LOG_FUNCTION(this << id);
    auto i = m_precursorList.find(id);
    if (i == m_precursorList.end())
    {
        NS_LOG_LOGIC("Precursor " << id << " not found");
        return false;
    }
    i->second = expires + Simulator::Now();
    NS_LOG_LOGIC("Precursor " << id << " found and updated to expire at " << expires);
    return true;
}

bool
ReportTableEntry::LookupPrecursor(Ipv4Address id)
{
    NS_LOG_FUNCTION(this << id);
    auto i = m_precursorList.find(id);
    if (i == m_precursorList.end())
    {
        NS_LOG_LOGIC("Precursor " << id << " not found");
        return false;
    }
    NS_LOG_LOGIC("Precursor " << id << " found");
    return true;
}

bool
ReportTableEntry::DeletePrecursor(Ipv4Address id)
{
    NS_LOG_FUNCTION(this << id);
    if (m_precursorList.erase(id) != 0)
    {
        NS_LOG_LOGIC("Precurser deletion of " << id << " successful");
        return true;
    }
    NS_LOG_LOGIC("Precurser deletion of " << id << " not successful");
    return false;
}

void
ReportTableEntry::DeleteAllPrecursors()
{
    NS_LOG_FUNCTION(this);
    m_precursorList.clear();
}

void
ReportTableEntry::PurgePrecursors()
{
    NS_LOG_FUNCTION(this);
    if (IsPrecursorListEmpty() || GetFlag() == REPORT_VALID)
    {
        return;
    }
    for (auto i = m_precursorList.begin(); i != m_precursorList.end();)
    {
        if (i->second < Simulator::Now())
        {
            DeletePrecursor(i->first);
            DecrementRepCnt();

            if (IsPrecursorListEmpty())
            {
                Invalidate(Seconds(0));
            }
        }
        ++i;
    }

}

bool
ReportTableEntry::IsPrecursorListEmpty() const
{
    return m_precursorList.empty();
}

void
ReportTableEntry::GetPrecursors(std::map<Ipv4Address,Time>& prec) const
{
    NS_LOG_FUNCTION(this);
    if (IsPrecursorListEmpty())
    {
        return;
    }
    prec = m_precursorList;
}

void
ReportTableEntry::Invalidate(Time badLinkLifetime)
{
    NS_LOG_FUNCTION(this << badLinkLifetime.As(Time::S));
    if (m_flag == REPORT_INVALID)
    {
        return;
    }
    m_flag = REPORT_INVALID;
    m_repCount = 0;
    m_lifeTime = badLinkLifetime + Simulator::Now();
}

void
ReportTableEntry::Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit /* = Time::S */) const
{
    std::ostream* os = stream->GetStream();
    // Copy the current ostream state
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    *os << std::resetiosflags(std::ios::adjustfield) << std::setiosflags(std::ios::left);

    std::ostringstream mal;
    std::ostringstream origin;
    std::ostringstream expire;
    mal << m_maliciousNodeAddr;
    origin << m_originAddress;
    expire << std::setprecision(2) << (m_lifeTime - Simulator::Now()).As(unit);
    *os << std::setw(16) << mal.str();
    *os << std::setw(16) << origin.str();
    *os << std::setw(16);
    switch (m_flag)
    {
    case REPORT_VALID: {
        *os << "UP";
        break;
    }
    case REPORT_INVALID: {
        *os << "DOWN";
        break;
    }
    case REPORT_IN_SEARCH: {
        *os << "IN_SEARCH";
        break;
    }
    }

    *os << std::setw(16) << expire.str();
    *os << std::endl;
    // Restore the previous ostream state
    (*os).copyfmt(oldState);
}

/*
 The Routing Table
 */

ReportTable::ReportTable(Time t, uint8_t repLimit)
    : m_badLinkLifetime(t),
      m_reportLimit(repLimit)
{
}

bool
ReportTable::LookupReport(Ipv4Address id, ReportTableEntry& rt)
{
    NS_LOG_FUNCTION(this << id);
    Purge();
    if (m_ipv4AddressEntry.empty())
    {
        NS_LOG_LOGIC("Report of " << id << " not found; m_ipv4AddressEntry is empty");
        return false;
    }
    auto i = m_ipv4AddressEntry.find(id);
    if (i == m_ipv4AddressEntry.end())
    {
        NS_LOG_LOGIC("Report of " << id << " not found");
        return false;
    }
    rt = i->second;
    NS_LOG_LOGIC("Report of " << id << " found");
    return true;
}

bool
ReportTable::LookupValidReport(Ipv4Address id, ReportTableEntry& rt)
{
    NS_LOG_FUNCTION(this << id);
    if (!LookupReport(id, rt))
    {
        NS_LOG_LOGIC("Report of " << id << " not found");
        return false;
    }
    NS_LOG_LOGIC("Report of " << id << " flag is "
                             << ((rt.GetFlag() == REPORT_VALID) ? "valid" : "not valid"));

    return (rt.GetFlag() == REPORT_VALID) && rt.IsBlacklisted() && (rt.GetBlacklistTimeout() > Simulator::Now());
}

bool
ReportTable::DeleteReport(Ipv4Address mal)
{
    NS_LOG_FUNCTION(this << mal);
    Purge();
    if (m_ipv4AddressEntry.erase(mal) != 0)
    {
        NS_LOG_LOGIC("Report deletion to " << mal << " successful");
        return true;
    }
    NS_LOG_LOGIC("Report deletion to " << mal << " not successful");
    return false;
}

bool
ReportTable::AddReport(ReportTableEntry& rt)
{
    NS_LOG_FUNCTION(this);
    Purge();
    if (rt.GetFlag() != REPORT_IN_SEARCH)
    {
        rt.SetRepCnt(1);
    }
    auto result = m_ipv4AddressEntry.insert(std::make_pair(rt.GetMaliciousAddr(), rt));
    return result.second;
}

bool
ReportTable::Update(ReportTableEntry& rt)
{
    NS_LOG_FUNCTION(this);
    auto i = m_ipv4AddressEntry.find(rt.GetMaliciousAddr());
    if (i == m_ipv4AddressEntry.end())
    {
        NS_LOG_LOGIC("Report update to " << rt.GetMaliciousAddr() << " fails; not found");
        return false;
    }
    i->second = rt;
    if (i->second.GetFlag() != REPORT_IN_SEARCH)
    {
        NS_LOG_LOGIC("Report update to " << rt.GetMaliciousAddr() << " set RepCnt to n+1");
        i->second.SetRepCnt(i->second.GetRepCnt()+1);
    }
    return true;
}

bool
ReportTable::SetEntryState(Ipv4Address id, ReportFlags state)
{
    NS_LOG_FUNCTION(this);
    auto i = m_ipv4AddressEntry.find(id);
    if (i == m_ipv4AddressEntry.end())
    {
        NS_LOG_LOGIC("Report set entry state to " << id << " fails; not found");
        return false;
    }
    i->second.SetFlag(state);
    //i->second.SetRepCnt(0);
    NS_LOG_LOGIC("Report set entry state to " << id << ": new state is " << state);
    return true;
}

void
ReportTable::InvalidateReportsWithMal(const std::map<Ipv4Address, uint32_t>& unreachable)
{
    NS_LOG_FUNCTION(this);
    Purge();
    for (auto i = m_ipv4AddressEntry.begin(); i != m_ipv4AddressEntry.end(); ++i)
    {
        for (auto j = unreachable.begin(); j != unreachable.end(); ++j)
        {
            if ((i->first == j->first) && (i->second.GetFlag() == REPORT_VALID))
            {
                NS_LOG_LOGIC("Invalidate route with destination address " << i->first);
                i->second.Invalidate(m_badLinkLifetime);
            }
        }
    }
}

void
ReportTable::ValidateReports()
{
    NS_LOG_FUNCTION(this);
    for (auto i = m_ipv4AddressEntry.begin(); i != m_ipv4AddressEntry.end(); ++i)
    {
        if(i->second.GetRepCnt()>=m_reportLimit){
            i->second.SetFlag(REPORT_VALID);
            i->second.SetBlacklisted(true);
            i->second.SetBlacklistTimeout(Simulator::GetMaximumSimulationTime());
            i->second.SetLifeTime(Simulator::GetMaximumSimulationTime());
        }
    }
}

bool
ReportTable::ValidateReports(Ipv4Address id)
{
    NS_LOG_FUNCTION(this);
    auto i = m_ipv4AddressEntry.find(id);
    if (i == m_ipv4AddressEntry.end())
    {
        NS_LOG_LOGIC("Report validation for " << id << " fails; not found");
        return false;
    }
    if (i->second.GetRepCnt() >= m_reportLimit)
    {
        i->second.SetFlag(REPORT_VALID);
        i->second.SetBlacklisted(true);
        i->second.SetBlacklistTimeout(Simulator::GetMaximumSimulationTime());
        i->second.SetLifeTime(Simulator::GetMaximumSimulationTime());
        return true;
    }
    return false;
}

std::vector<ReportTableEntry>
ReportTable::GetValidReports(){
    NS_LOG_FUNCTION(this);
    std::vector<ReportTableEntry> validReports;
    for (auto i = m_ipv4AddressEntry.begin(); i != m_ipv4AddressEntry.end(); ++i)
    {
        if(i->second.GetFlag()==REPORT_VALID){
            validReports.push_back(i->second);
        }
    }
}

void
ReportTable::Purge()
{
    NS_LOG_FUNCTION(this);
    if (m_ipv4AddressEntry.empty())
    {
        return;
    }
    for (auto i = m_ipv4AddressEntry.begin(); i != m_ipv4AddressEntry.end();)
    {
        i->second.PurgePrecursors();
        if (i->second.GetLifeTime() < Seconds(0))
        {
            if (i->second.GetFlag() == REPORT_INVALID)
            {
                auto tmp = i;
                ++i;
                m_ipv4AddressEntry.erase(tmp);
            }
            else if (i->second.GetFlag() == REPORT_VALID)
            {
                NS_LOG_LOGIC("Invalidate report with malicious address " << i->first);
                i->second.Invalidate(m_badLinkLifetime);
                ++i;
            }
            else
            {
                ++i;
            }
        }
        else
        {
            ++i;
        }
    }
}

void
ReportTable::Purge(std::map<Ipv4Address, ReportTableEntry>& table) const
{
    NS_LOG_FUNCTION(this);
    if (table.empty())
    {
        return;
    }
    for (auto i = table.begin(); i != table.end();)
    {
        i->second.PurgePrecursors();
        if (i->second.GetLifeTime() < Seconds(0))
        {
            if (i->second.GetFlag() == REPORT_INVALID)
            {
                auto tmp = i;
                ++i;
                table.erase(tmp);
            }
            else if (i->second.GetFlag() == REPORT_VALID)
            {
                NS_LOG_LOGIC("Invalidate report with malicious address " << i->first);
                i->second.Invalidate(m_badLinkLifetime);
                ++i;
            }
            else
            {
                ++i;
            }
        }
        else
        {
            ++i;
        }
    }
}

void
ReportTable::Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit /* = Time::S */) const
{
    std::map<Ipv4Address, ReportTableEntry> table = m_ipv4AddressEntry;
    Purge(table);
    std::ostream* os = stream->GetStream();
    // Copy the current ostream state
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    *os << std::resetiosflags(std::ios::adjustfield) << std::setiosflags(std::ios::left);
    *os << "\nLESAP-AODV Routing table\n";
    *os << std::setw(16) << "Destination";
    *os << std::setw(16) << "Gateway";
    *os << std::setw(16) << "Interface";
    *os << std::setw(16) << "Flag";
    *os << std::setw(16) << "Expire";
    *os << "Hops" << std::endl;
    for (auto i = table.begin(); i != table.end(); ++i)
    {
        i->second.Print(stream, unit);
    }
    *stream->GetStream() << "\n";
}

} // namespace lesapAodv
} // namespace ns3
