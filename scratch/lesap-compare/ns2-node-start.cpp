//
// Created by Andrew Smith on 6/11/24.
//
#include "ns2-node-start.h"

using namespace ns3;

Ns2NodeStart::Ns2NodeStart(std::string file_name)
{
    std::ifstream file;
    file.open(file_name);
    std::string line;

    std::getline(file, line);
    m_simTime = stoi(line);
    while (std::getline(file, line))
    {
        std::string delimiter = "-";
        size_t end = line.find(delimiter);
        size_t begin = 0;
        uint32_t node = stoi(line.substr(begin, end));
        begin = end + 1;
        end = line.find(delimiter, begin);
        double start = stod(line.substr(begin, end));
        begin = end + 1;
        double stop = stod(line.substr(begin));

        m_nodeTimes.insert({node, std::make_pair(start, stop)});
    }
}

uint32_t
Ns2NodeStart::GetNumNodes()
{
    return m_nodeTimes.size();
}

double
Ns2NodeStart::GetStartTimeForNode(uint32_t node)
{
    return m_nodeTimes[node].first;
}

double
Ns2NodeStart::GetEndTimeForNode(uint32_t node)
{
    return m_nodeTimes[node].second;
}

double
Ns2NodeStart::GetSimTime()
{
    return m_simTime;
}
