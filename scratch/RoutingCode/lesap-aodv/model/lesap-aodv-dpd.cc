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
 * Authors: Andrew Smith <asmith1138@gmail.com>, written after
 *          AODV::DuplicatePacketDetection by
 *          Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */

#include "lesap-aodv-dpd.h"

namespace ns3
{
namespace lesapAodv
{

bool
DuplicatePacketDetection::IsDuplicate(Ptr<const Packet> p, const Ipv4Header& header)
{
    return m_idCache.IsDuplicate(header.GetSource(), p->GetUid());
}

void
DuplicatePacketDetection::SetLifetime(Time lifetime)
{
    m_idCache.SetLifetime(lifetime);
}

Time
DuplicatePacketDetection::GetLifetime() const
{
    return m_idCache.GetLifeTime();
}

} // namespace lesapAodv
} // namespace ns3
