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
 *          AODV::TypeHeader by
 *          Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */
#ifndef LESAP_AODVPACKET_H
#define LESAP_AODVPACKET_H

#include "ns3/enum.h"
#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"

#include <iostream>
#include <map>

namespace ns3
{
namespace lesapAodv
{

/**
 * \ingroup lesapAodv
 * \brief MessageType enumeration
 */
enum MessageType
{
    LESAPAODVTYPE_RREQ = 1,    //!< LESAPAODVTYPE_RREQ
    LESAPAODVTYPE_RREP = 2,    //!< LESAPAODVTYPE_RREP
    LESAPAODVTYPE_RERR = 3,    //!< LESAPAODVTYPE_RERR
    LESAPAODVTYPE_RREP_ACK = 4, //!< LESAPAODVTYPE_RREP_ACK
    LESAPAODVTYPE_NEEDKEY = 5, //!< LESAPAODVTYPE_NEEDKEY
    LESAPAODVTYPE_SENDKEY = 6, //!< LESAPAODVTYPE_SENDKEY
    LESAPAODVTYPE_REPORT = 7 //!< LESAPAODVTYPE_REPORT
};

/**
 * \ingroup lesapAodv
 * \brief LESAP-AODV types
 */
class TypeHeader : public Header
{
  public:
    /**
     * constructor
     * \param t the LESAP-AODV RREQ type
     */
    TypeHeader(MessageType t = LESAPAODVTYPE_RREQ);

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    /**
     * \returns the type
     */
    MessageType Get() const
    {
        return m_type;
    }

    /**
     * Check that type if valid
     * \returns true if the type is valid
     */
    bool IsValid() const
    {
        return m_valid;
    }

    /**
     * \brief Comparison operator
     * \param o header to compare
     * \return true if the headers are equal
     */
    bool operator==(const TypeHeader& o) const;

  private:
    MessageType m_type; ///< type of the message
    bool m_valid;       ///< Indicates if the message is valid
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \param h the TypeHeader
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const TypeHeader& h);

/**
* \ingroup lesapAodv
* \brief   Route Request (RREQ) Message Format
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |J|R|G|D|U|   Reserved          |   Hop Count   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                            RREQ ID                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Destination IP Address                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Destination Sequence Number                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Originator IP Address                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Originator Sequence Number                   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/
class RreqHeader : public Header
{
  public:
    /**
     * constructor
     *
     * \param flags the message flags (0)
     * \param reserved the reserved bits (0)
     * \param hopCount the hop count
     * \param requestID the request ID
     * \param dst the destination IP address
     * \param dstSeqNo the destination sequence number
     * \param origin the origin IP address
     * \param originSeqNo the origin sequence number
     */
    RreqHeader(uint8_t flags = 0,
               uint8_t reserved = 0,
               uint8_t hopCount = 0,
               uint32_t requestID = 0,
               Ipv4Address dst = Ipv4Address(),
               uint32_t dstSeqNo = 0,
               Ipv4Address origin = Ipv4Address(),
               uint32_t originSeqNo = 0);

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    // Fields
    /**
     * \brief Set the hop count
     * \param count the hop count
     */
    void SetHopCount(uint8_t count)
    {
        m_hopCount = count;
    }

    /**
     * \brief Get the hop count
     * \return the hop count
     */
    uint8_t GetHopCount() const
    {
        return m_hopCount;
    }

    /**
     * \brief Set the request ID
     * \param id the request ID
     */
    void SetId(uint32_t id)
    {
        m_requestID = id;
    }

    /**
     * \brief Get the request ID
     * \return the request ID
     */
    uint32_t GetId() const
    {
        return m_requestID;
    }

    /**
     * \brief Set the destination address
     * \param a the destination address
     */
    void SetDst(Ipv4Address a)
    {
        m_dst = a;
    }

    /**
     * \brief Get the destination address
     * \return the destination address
     */
    Ipv4Address GetDst() const
    {
        return m_dst;
    }

    /**
     * \brief Set the destination sequence number
     * \param s the destination sequence number
     */
    void SetDstSeqno(uint32_t s)
    {
        m_dstSeqNo = s;
    }

    /**
     * \brief Get the destination sequence number
     * \return the destination sequence number
     */
    uint32_t GetDstSeqno() const
    {
        return m_dstSeqNo;
    }

    /**
     * \brief Set the origin address
     * \param a the origin address
     */
    void SetOrigin(Ipv4Address a)
    {
        m_origin = a;
    }

    /**
     * \brief Get the origin address
     * \return the origin address
     */
    Ipv4Address GetOrigin() const
    {
        return m_origin;
    }

    /**
     * \brief Set the origin sequence number
     * \param s the origin sequence number
     */
    void SetOriginSeqno(uint32_t s)
    {
        m_originSeqNo = s;
    }

    /**
     * \brief Get the origin sequence number
     * \return the origin sequence number
     */
    uint32_t GetOriginSeqno() const
    {
        return m_originSeqNo;
    }

    // Flags
    /**
     * \brief Set the gratuitous RREP flag
     * \param f the gratuitous RREP flag
     */
    void SetGratuitousRrep(bool f);
    /**
     * \brief Get the gratuitous RREP flag
     * \return the gratuitous RREP flag
     */
    bool GetGratuitousRrep() const;
    /**
     * \brief Set the Destination only flag
     * \param f the Destination only flag
     */
    void SetDestinationOnly(bool f);
    /**
     * \brief Get the Destination only flag
     * \return the Destination only flag
     */
    bool GetDestinationOnly() const;
    /**
     * \brief Set the unknown sequence number flag
     * \param f the unknown sequence number flag
     */
    void SetUnknownSeqno(bool f);
    /**
     * \brief Get the unknown sequence number flag
     * \return the unknown sequence number flag
     */
    bool GetUnknownSeqno() const;

    /**
     * \brief Comparison operator
     * \param o RREQ header to compare
     * \return true if the RREQ headers are equal
     */
    bool operator==(const RreqHeader& o) const;

  private:
    uint8_t m_flags;        ///< |J|R|G|D|U| bit flags, see RFC
    uint8_t m_reserved;     ///< Not used (must be 0)
    uint8_t m_hopCount;     ///< Hop Count
    uint32_t m_requestID;   ///< RREQ ID
    Ipv4Address m_dst;      ///< Destination IP Address
    uint32_t m_dstSeqNo;    ///< Destination Sequence Number
    Ipv4Address m_origin;   ///< Originator IP Address
    uint32_t m_originSeqNo; ///< Source Sequence Number
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const RreqHeader&);

/**
* \ingroup lesapAodv
* \brief Route Reply (RREP) Message Format
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |R|A|    Reserved     |Prefix Sz|   Hop Count   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Destination IP address                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Destination Sequence Number                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Originator IP address                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Lifetime                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/
class RrepHeader : public Header
{
  public:
    /**
     * constructor
     *
     * \param prefixSize the prefix size (0)
     * \param hopCount the hop count (0)
     * \param dst the destination IP address
     * \param dstSeqNo the destination sequence number
     * \param origin the origin IP address
     * \param lifetime the lifetime
     */
    RrepHeader(uint8_t prefixSize = 0,
               uint8_t hopCount = 0,
               Ipv4Address dst = Ipv4Address(),
               uint32_t dstSeqNo = 0,
               Ipv4Address origin = Ipv4Address(),
               Time lifetime = MilliSeconds(0));
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    // Fields
    /**
     * \brief Set the hop count
     * \param count the hop count
     */
    void SetHopCount(uint8_t count)
    {
        m_hopCount = count;
    }

    /**
     * \brief Get the hop count
     * \return the hop count
     */
    uint8_t GetHopCount() const
    {
        return m_hopCount;
    }

    /**
     * \brief Set the destination address
     * \param a the destination address
     */
    void SetDst(Ipv4Address a)
    {
        m_dst = a;
    }

    /**
     * \brief Get the destination address
     * \return the destination address
     */
    Ipv4Address GetDst() const
    {
        return m_dst;
    }

    /**
     * \brief Set the destination sequence number
     * \param s the destination sequence number
     */
    void SetDstSeqno(uint32_t s)
    {
        m_dstSeqNo = s;
    }

    /**
     * \brief Get the destination sequence number
     * \return the destination sequence number
     */
    uint32_t GetDstSeqno() const
    {
        return m_dstSeqNo;
    }

    /**
     * \brief Set the origin address
     * \param a the origin address
     */
    void SetOrigin(Ipv4Address a)
    {
        m_origin = a;
    }

    /**
     * \brief Get the origin address
     * \return the origin address
     */
    Ipv4Address GetOrigin() const
    {
        return m_origin;
    }

    /**
     * \brief Set the lifetime
     * \param t the lifetime
     */
    void SetLifeTime(Time t);
    /**
     * \brief Get the lifetime
     * \return the lifetime
     */
    Time GetLifeTime() const;

    // Flags
    /**
     * \brief Set the ack required flag
     * \param f the ack required flag
     */
    void SetAckRequired(bool f);
    /**
     * \brief get the ack required flag
     * \return the ack required flag
     */
    bool GetAckRequired() const;
    /**
     * \brief Set the prefix size
     * \param sz the prefix size
     */
    void SetPrefixSize(uint8_t sz);
    /**
     * \brief Set the pefix size
     * \return the prefix size
     */
    uint8_t GetPrefixSize() const;

    /**
     * Configure RREP to be a Hello message
     *
     * \param src the source IP address
     * \param srcSeqNo the source sequence number
     * \param lifetime the lifetime of the message
     */
    void SetHello(Ipv4Address src, uint32_t srcSeqNo, Time lifetime);

    /**
     * \brief Comparison operator
     * \param o RREP header to compare
     * \return true if the RREP headers are equal
     */
    bool operator==(const RrepHeader& o) const;

  private:
    uint8_t m_flags;      ///< A - acknowledgment required flag
    uint8_t m_prefixSize; ///< Prefix Size
    uint8_t m_hopCount;   ///< Hop Count
    Ipv4Address m_dst;    ///< Destination IP Address
    uint32_t m_dstSeqNo;  ///< Destination Sequence Number
    Ipv4Address m_origin; ///< Source IP Address
    uint32_t m_lifeTime;  ///< Lifetime (in milliseconds)
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const RrepHeader&);
/**
* \ingroup lesapAodv
* \brief Need Key (NeedKey) Message Format
  \verbatim
  0                   1
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |   Reserved    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/
class NeedKeyHeader : public Header
{
  public:
    /**
     * constructor
     *
     */
    NeedKeyHeader();
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    /**
     * \brief Comparison operator
     * \param o NeedKey header to compare
     * \return true if the NeedKey headers are equal
     */
    bool operator==(const NeedKeyHeader& o) const;

  private:
    uint8_t m_reserved; ///< Not used (must be 0)
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const NeedKeyHeader&);

/**
* \ingroup lesapAodv
* \brief Send Key (SKey) Message Format
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |R|A|    Reserved     |Prefix Sz|   Hop Count   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Destination IP address                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Destination Sequence Number                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Originator IP address                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Lifetime                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/
class SendKeyHeader : public Header
{
  public:
    /**
     * constructor
     *
     * \param key1 the 1st half of the key
     * \param key2 the 2nd half of the key
     * \param x the position of the node on x-axis
     * \param y the position of the node on y-axis
     * \param z the position of the node on z-axis
     * \param speed the speed of the node
     * \param lifetime the lifetime
     */
    SendKeyHeader(uint64_t key1 = 0,
                  uint64_t key2 = 0,
                  uint64_t key3 = 0,
                  uint64_t key4 = 0,
                  uint32_t velX = 0,
                  uint32_t velY = 0,
                  uint32_t velZ = 0,
                  uint32_t x = 0,
                  uint32_t y = 0,
                  uint32_t z = 0,
               Time lifetime = MilliSeconds(0));
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    // Fields
    /**
     * \brief Set 1st part of key
     * \param key1 1st part of key
     */
    void SetKey1(uint64_t key1)
    {
        m_key1 = key1;
    }

    /**
     * \brief Get 1st part of key
     * \return the 1st part of key
     */
    uint64_t GetKey1() const
    {
        return m_key1;
    }

    /**
     * \brief Set 2nd part of key
     * \param key2 2nd part of key
     */
    void SetKey2(uint64_t key2)
    {
        m_key2 = key2;
    }

    /**
     * \brief Get 2nd part of key
     * \return the 2nd part of key
     */
    uint64_t GetKey2() const
    {
        return m_key2;
    }

    /**
     * \brief Set 3rd part of key
     * \param key3 3rd part of key
     */
    void SetKey3(int64_t key3)
    {
        m_key3 = key3;
    }

    /**
     * \brief Get 3rd part of key
     * \return the 3rd part of key
     */
    uint64_t GetKey3() const
    {
        return m_key3;
    }

    /**
     * \brief Set 4th part of key
     * \param key4 4th part of key
     */
    void SetKey4(uint64_t key4)
    {
        m_key4 = key4;
    }

    /**
     * \brief Get 4th part of key
     * \return the 4th part of key
     */
    uint64_t GetKey4() const
    {
        return m_key4;
    }

    /**
     * \brief Set velocity x
     * \param velX X velocity of node
     */
    void SetVelX(uint32_t velX)
    {
        m_velX = velX;
    }

    /**
     * \brief Get x velocity of node
     * \return the x velocity of node
     */
    int32_t GetVelX() const
    {
        return m_velX;
    }

    /**
     * \brief Set velocity y
     * \param velY Y velocity of node
     */
    void SetVelY(uint32_t velY)
    {
        m_velY = velY;
    }

    /**
     * \brief Get y velocity of node
     * \return the y velocity of node
     */
    int32_t GetVelY() const
    {
        return m_velY;
    }

    /**
     * \brief Set velocity z
     * \param velZ Z velocity of node
     */
    void SetVelZ(uint32_t velZ)
    {
        m_velZ = velZ;
    }

    /**
     * \brief Get z velocity of node
     * \return the z velocity of node
     */
    int32_t GetVelZ() const
    {
        return m_velZ;
    }

    /**
     * \brief Set position on x-axis of node
     * \param x position on x-axis of node
     */
    void SetX(uint32_t x)
    {
        m_xPosition = x;
    }

    /**
     * \brief Get position on x-axis of node
     * \return the position on x-axis of node
     */
    uint32_t GetX() const
    {
        return m_xPosition;
    }

    /**
     * \brief Set position on y-axis of node
     * \param y position on y-axis of node
     */
    void SetY(uint32_t y)
    {
        m_yPosition = y;
    }

    /**
     * \brief Get position on y-axis of node
     * \return the position on y-axis of node
     */
    uint32_t GetY() const
    {
        return m_yPosition;
    }

    /**
     * \brief Set position on z-axis of node
     * \param x position on z-axis of node
     */
    void SetZ(uint32_t z)
    {
        m_zPosition = z;
    }

    /**
     * \brief Get position on z-axis of node
     * \return the position on z-axis of node
     */
    uint32_t GetZ() const
    {
        return m_zPosition;
    }

    /**
     * \brief Set the lifetime
     * \param t the lifetime
     */
    void SetLifeTime(Time t);
    /**
     * \brief Get the lifetime
     * \return the lifetime
     */
    Time GetLifeTime() const;

    /**
     * \brief Comparison operator
     * \param o RREP header to compare
     * \return true if the RREP headers are equal
     */
    bool operator==(const SendKeyHeader& o) const;

  private:
    uint64_t m_key1;   ///< 1st part of public key
    uint64_t m_key2;    ///< 2nd part of public key
    uint64_t m_key3;   ///< 3rd part of public key
    uint64_t m_key4;    ///< 4th part of public key
    uint32_t m_velX;  ///< node x velocity
    uint32_t m_velY;  ///< node y velocity
    uint32_t m_velZ;  ///< node z velocity
    uint32_t m_xPosition; ///< node position on x-axis
    uint32_t m_yPosition; ///< node position on y-axis
    uint32_t m_zPosition; ///< node position on z-axis
    uint32_t m_lifeTime;  ///< Lifetime (in milliseconds)
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const SendKeyHeader&);

/**
* \ingroup lesapAodv
* \brief Report Message Format
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |R|A|    Reserved     |Prefix Sz|   Hop Count   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Destination IP address                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Destination Sequence Number                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Originator IP address                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Lifetime                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/
class ReportHeader : public Header
{
  public:
    /**
     * constructor
     *
     * \param mal the malicious node IP address
     * \param malSeqNo the report sequence number
     * \param origin the original reporter IP address
     * \param lifetime the lifetime
     */
    ReportHeader(Ipv4Address mal = Ipv4Address(),
               uint32_t malSeqNo = 0,
               Ipv4Address origin = Ipv4Address(),
               Time lifetime = MilliSeconds(0));
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    // Fields

    /**
     * \brief Set the destination address
     * \param a the malicious address
     */
    void SetMal(Ipv4Address a)
    {
        m_mal = a;
    }

    /**
     * \brief Get the malicious address
     * \return the malicious address
     */
    Ipv4Address GetMal() const
    {
        return m_mal;
    }

    /**
     * \brief Set the report sequence number
     * \param s the report sequence number
     */
    void SetMalSeqno(uint32_t s)
    {
        m_malSeqNo = s;
    }

    /**
     * \brief Get the report sequence number
     * \return the report sequence number
     */
    uint32_t GetMalSeqno() const
    {
        return m_malSeqNo;
    }

    /**
     * \brief Set the origin address
     * \param a the origin address
     */
    void SetOrigin(Ipv4Address a)
    {
        m_origin = a;
    }

    /**
     * \brief Get the origin address
     * \return the origin address
     */
    Ipv4Address GetOrigin() const
    {
        return m_origin;
    }

    /**
     * \brief Set the lifetime
     * \param t the lifetime
     */
    void SetLifeTime(Time t);
    /**
     * \brief Get the lifetime
     * \return the lifetime
     */
    Time GetLifeTime() const;

    // Flags
    /**
     * \brief Comparison operator
     * \param o Report header to compare
     * \return true if the Report headers are equal
     */
    bool operator==(const ReportHeader& o) const;

  private:
    Ipv4Address m_mal;    ///< malicious IP Address
    uint32_t m_malSeqNo;  ///< report Sequence Number
    Ipv4Address m_origin; ///< Source IP Address
    uint32_t m_lifeTime;  ///< Lifetime (in milliseconds)
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const ReportHeader&);

/**
* \ingroup lesapAodv
* \brief Route Reply Acknowledgment (RREP-ACK) Message Format
  \verbatim
  0                   1
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |   Reserved    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/
class RrepAckHeader : public Header
{
  public:
    /// constructor
    RrepAckHeader();

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    /**
     * \brief Comparison operator
     * \param o RREP header to compare
     * \return true if the RREQ headers are equal
     */
    bool operator==(const RrepAckHeader& o) const;

  private:
    uint8_t m_reserved; ///< Not used (must be 0)
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const RrepAckHeader&);

/**
* \ingroup lesapAodv
* \brief Route Error (RERR) Message Format
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |N|          Reserved           |   DestCount   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |            Unreachable Destination IP Address (1)             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Unreachable Destination Sequence Number (1)           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
  |  Additional Unreachable Destination IP Addresses (if needed)  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Additional Unreachable Destination Sequence Numbers (if needed)|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/
class RerrHeader : public Header
{
  public:
    /// constructor
    RerrHeader();

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator i) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    // No delete flag
    /**
     * \brief Set the no delete flag
     * \param f the no delete flag
     */
    void SetNoDelete(bool f);
    /**
     * \brief Get the no delete flag
     * \return the no delete flag
     */
    bool GetNoDelete() const;

    /**
     * \brief Add unreachable node address and its sequence number in RERR header
     * \param dst unreachable IPv4 address
     * \param seqNo unreachable sequence number
     * \return false if we already added maximum possible number of unreachable destinations
     */
    bool AddUnDestination(Ipv4Address dst, uint32_t seqNo);
    /**
     * \brief Delete pair (address + sequence number) from REER header, if the number of unreachable
     * destinations > 0
     * \param un unreachable pair (address + sequence number)
     * \return true on success
     */
    bool RemoveUnDestination(std::pair<Ipv4Address, uint32_t>& un);
    /// Clear header
    void Clear();

    /**
     * \returns number of unreachable destinations in RERR message
     */
    uint8_t GetDestCount() const
    {
        return (uint8_t)m_unreachableDstSeqNo.size();
    }

    /**
     * \brief Comparison operator
     * \param o RERR header to compare
     * \return true if the RERR headers are equal
     */
    bool operator==(const RerrHeader& o) const;

  private:
    uint8_t m_flag;     ///< No delete flag
    uint8_t m_reserved; ///< Not used (must be 0)

    /// List of Unreachable destination: IP addresses and sequence numbers
    std::map<Ipv4Address, uint32_t> m_unreachableDstSeqNo;
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const RerrHeader&);

} // namespace lesapAodv
} // namespace ns3

#endif /* LESAP_AODVPACKET_H */
