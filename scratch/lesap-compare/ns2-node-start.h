//
// Created by andrew on 6/11/24.
//

#ifndef NS2_NODE_START_H
#define NS2_NODE_START_H

//#include <string>
#include <fstream>
#include <map>

namespace ns3
{
class Ns2NodeStart
{
  public:
    Ns2NodeStart(std::string file_name);

    uint32_t GetNumNodes();

    double GetStartTimeForNode(uint32_t nodeId);
    double GetEndTimeForNode(uint32_t nodeId);
    double GetSimTime();

  private:
    std::map<uint32_t, std::pair<double, double>> m_nodeTimes;
    double m_simTime;
};
} // namespace ns3

#endif // NS2_NODE_START_H
