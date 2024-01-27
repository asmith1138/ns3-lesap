- Application needed for Sybil nodes
- Application needed for Blackhole nodes
- Modify routing algorithm to validate location of each neighbor (lower distance)
  - Will need to do this multiple times for various routing algorithms
  - aodv-neighbors continues to work as normal
  - aodv-lidar will manage this change
    x Use application on nodes to manage blacklists
- Use routing algorithm to manage blacklists (works for AODV, easily)
  - Make the blacklist timeout settable by the script
  - Set to total time of simulation for permanent blacklisting(or other value as required)
  - Will need to do this multiple times for various routing algorithms
- 1 or 2 Applications needed for normal nodes

Needs for LESAP-AODV

#### lesap-aodv-ntable.h (neighbor table)

- [ ] Create file
- [ ] Create same methods as rtable

#### lesap-aodv-ntable.cc (neighbor table)

- [ ] create file

#### lesap-aodv-lidar.cc (lidar neighbor)

- [ ] Create file

- [ ] Create same methods as neighbor

#### lesap-aodv-lidar.cc (lidar neighbor)

- [ ] Create file

#### lesap-aodv-routing-protocol.h

- [ ] Modify namespace

- [ ] Add NeighborTable m_nieghborTable

- [ ] Add methods to RecvLidarRequest

#### lesap-aodv-routing-protocol.cc

- [ ] Modify namespace
- [ ] Only forward packets from lidar neighbors
- [ ] When RecvPacket ignore if not Lidar Neighbor in RecvAodv
- [ ] When type is RecvLidar, run RecvLidarRequest

#### lesap-aodv-rqueue.h

- [ ] Modify namespace

#### lesap-aodv-rqueue.cc

- [ ] Modify namespace

#### lesap-aodv-packet.h

- [ ] Modify namespace
- [ ] add message types
  - [ ] Signature(RecvLidarNeighbor)
- [ ] figure out packet layout

#### lesap-aodv-packet.cc

- [ ] Modify namespace
- [ ] ad message types
  - [ ] signature
- [ ] figure out packet layout

#### lesap-aodv-rtable.cc

- [ ] Modify namespace

#### lesap-aodv-rtable.h

- [ ] Modify namespace

#### lesap-aodv-neighbor.h

- [ ] Modify namespace

#### lesap-aodv-neighbor.cc

- [ ] Modify namespace

#### lesap-aodv-id-cache.h

- [ ] Modify namespace

#### lesap-aodv-id-cache.cc

- [ ] Modify namespace

#### lesap-aodv-dpd.h

- [ ] Modify namespace

#### lesap-aodv-dpd.cc

- [ ] Modify namespace

#### lesap-aodv-helper.h

- [ ] Modify namespace

#### lesap-aodv-helper.cc

- [ ] Modify namespace


