    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
    NS_ASSERT(socket);
    socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), LESAP_AODV_PORT));



    Ptr<Socket>
RoutingProtocol::FindSocketWithInterfaceAddress(Ipv4InterfaceAddress addr) const
{
    NS_LOG_FUNCTION(this << addr);
    for (auto j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        if (iface == addr)
        {
            return socket;
        }
    }
    Ptr<Socket> socket;
    return socket;
}


void
RoutingProtocol::SendTo(Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination)
{
    socket->SendTo(packet, 0, InetSocketAddress(destination, LESAP_AODV_PORT));
}


