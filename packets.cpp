/*

This is the code for project 4, a command line packet trace analysis tool that allows the user to get information 
 packets that cross a specific link
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "packets.h"
#include <stdbool.h>
#include <string>
#include <math.h>
#include <vector>
#include <iostream>
#include <unordered_map>

#define IPV4 4
#define ONEBYTE 8
#define TWOBYTES 16
#define THREEBYTES 24

#define BYTESIN32BITS 4

bool traceOption = false;
int *traceFile;
bool sumOption = false;
bool lengthOption = false;
bool packetOption = false;
bool matrixOption = false;

/*Variables for Summary Mode*/
double firtPacketTime = 0.0;
double lastPacketTime = 0.0;
int totalPAckets = 0;
int ipPackets = 0;

/*Arrays for Length Mode*/
std::vector<std::string> timeStampArr;
std::vector<std::string> caplenArr;
std::vector<std::string> ipLenArr;
std::vector<std::string> ipHdrLenArr;
std::vector<std::string> transportArr;
std::vector<std::string> transportHdrLenArr;
std::vector<std::string> payloadLenArr;

/*Arrays for Packet mode*/
std::vector<std::string> timeStampTCPArr;
std::vector<std::string> srcIPArr;
std::vector<std::string> dstIPArr;
std::vector<std::string> ipTTLArr;
std::vector<std::string> srcPortArr;
std::vector<std::string> dstPortArr;
std::vector<std::string> windowArr;
std::vector<std::string> seqNumArr;
std::vector<std::string> AckArr;

int tcppackets;

/*Hashmap for Matrix Mode*/
std::unordered_map<std::string, long> pairsTraffic;

void errexit(std::string msg)
{
    fprintf(stdout, "%s\n", msg.c_str());
    exit(1);
}

// formats the ip address from byte format to human readable ip
std::string formatIP(u_int32_t ip)
{
    std::string formattedIP;

    u_int8_t firstSection = ip & 0xFF;
    u_int8_t secondSection = (ip >> ONEBYTE) & 0xFF;
    u_int8_t thirdSection = (ip >> TWOBYTES) & 0xFF;
    u_int8_t fourthSection = (ip >> THREEBYTES) & 0xFF;

    formattedIP.append(std::to_string(fourthSection)).append(".").append(std::to_string(thirdSection)).append(".").append(std::to_string(secondSection)).append(".").append(std::to_string(firstSection));

    return formattedIP;
}

// fills in the array for the packet mode
void packetMode(struct pkt_info bufferPacket)
{
    timeStampTCPArr.push_back(std::to_string(bufferPacket.now));
    srcIPArr.push_back(formatIP(ntohl(bufferPacket.iph->saddr)));
    dstIPArr.push_back(formatIP(ntohl(bufferPacket.iph->daddr)));
    ipTTLArr.push_back(std::to_string(bufferPacket.iph->ttl));
    srcPortArr.push_back(std::to_string(ntohs(bufferPacket.tcph->th_sport)));
    dstPortArr.push_back(std::to_string(ntohs(bufferPacket.tcph->th_dport)));
    windowArr.push_back(std::to_string(ntohs(bufferPacket.tcph->th_win)));
    seqNumArr.push_back(std::to_string(ntohl(bufferPacket.tcph->th_seq)));

    // checks that the ack bit is set using bitmasks
    if (bufferPacket.tcph->th_flags & TH_ACK)
    {
        AckArr.push_back(std::to_string(ntohl(bufferPacket.tcph->th_ack)));
    }
    else
    {
        AckArr.push_back("-");
    }
}

// fills in the hashmap for the matrix mode
void matrixMode(struct pkt_info bufferPacket)
{
    std::string pair;
    int payloadlen = (ntohs(bufferPacket.iph->tot_len)) - bufferPacket.caplen + sizeof(ether_header);
    pair.append(formatIP(ntohl(bufferPacket.iph->saddr))).append(" ").append(formatIP(ntohl(bufferPacket.iph->daddr)));
    pairsTraffic[pair] += payloadlen;
}

// handles tcp packets specifically
void tcpPacketHandler(struct pkt_info bufferPacket)
{
    transportArr.push_back("T");

    if (packetOption)
    {
        packetMode(bufferPacket);
    }
    if (matrixOption)
    {
        matrixMode(bufferPacket);
    }
    int headerlength = (bufferPacket.caplen) - sizeof(iphdr) - sizeof(ether_header);
    if (headerlength != 0)
    {
        transportHdrLenArr.push_back(std::to_string(headerlength));
        int payloadlen = (ntohs(bufferPacket.iph->tot_len)) - bufferPacket.caplen + sizeof(ether_header);
        payloadLenArr.push_back(std::to_string(payloadlen));
    }
    else
    {
        transportHdrLenArr.push_back("-");
        payloadLenArr.push_back("-");
    }
}

// handles udp packets specifically
void udpPacketHandler(struct pkt_info bufferPacket)
{

    transportArr.push_back("U");

    int headerlength = (bufferPacket.caplen) - sizeof(iphdr) - sizeof(ether_header);
    if (headerlength != 0)
    {
        transportHdrLenArr.push_back(std::to_string(sizeof(struct udphdr)));
        int payloadlen = ntohs(bufferPacket.iph->tot_len) - bufferPacket.caplen + sizeof(ether_header);
        payloadLenArr.push_back(std::to_string(payloadlen));
    }
    else
    {
        transportHdrLenArr.push_back("-");
        payloadLenArr.push_back("-");
    }
}

// checks for IP version
void handleIPV4(struct pkt_info bufferPacket)
{
    if (bufferPacket.iph->version == IPV4)
    {
        caplenArr.push_back(std::to_string(bufferPacket.caplen));
        timeStampArr.push_back(std::to_string(bufferPacket.now));
        ipLenArr.push_back(std::to_string(ntohs(bufferPacket.iph->tot_len)));
        ipHdrLenArr.push_back(std::to_string((bufferPacket.iph->ihl) * 4));
    }
    else
    {
        caplenArr.push_back(std::to_string(bufferPacket.caplen));
        timeStampArr.push_back(std::to_string(bufferPacket.now));
        ipLenArr.push_back("-");
        ipHdrLenArr.push_back("-");
    }
}

// read packets and store the data in the appropriate arrays for length mode
unsigned short read_packet(int tracePointer, int pktCounter)
{
    //packet reader code provided
    struct pkt_info bufferPacket;
    struct meta_info meta;

    memset(&meta, 0x0, sizeof(struct meta_info));
    memset(&bufferPacket, 0x0, sizeof(struct pkt_info));

    int read_bytes = read(tracePointer, &meta, sizeof(meta));

    if (read_bytes == 0)
        return (0);
    if (read_bytes < sizeof(meta))
        errexit("cannot read meta information");

    bufferPacket.caplen = ntohs(meta.caplen);

    if (bufferPacket.caplen == 0)
        return (1);
    if (bufferPacket.caplen > MAX_PKT_SIZE)
        errexit("packet too big");

    bufferPacket.now += ntohl(meta.secs);
    bufferPacket.now += ntohl(meta.usecs) * pow(10, -6);
    if (pktCounter == 0)
    {
        firtPacketTime = bufferPacket.now;
    }
    lastPacketTime = bufferPacket.now;
    //after metadata reads the packets
    read_bytes = read(tracePointer, bufferPacket.pkt, bufferPacket.caplen);

    if (read_bytes == 0)
        return (0);
    if (read_bytes < bufferPacket.caplen)
        errexit("unexpected end of file encountered");
    if (read_bytes < sizeof(struct ether_header))
        return (1);

    bufferPacket.ethh = (struct ether_header *)bufferPacket.pkt;

    bufferPacket.ethh->ether_type = ntohs(bufferPacket.ethh->ether_type);

    if (bufferPacket.ethh->ether_type != ETHERTYPE_IP)
        return (1);

    // point to the IP packet
    bufferPacket.iph = (struct iphdr *)(bufferPacket.pkt + sizeof(struct ether_header));

    if (bufferPacket.ethh->ether_type == ETHERTYPE_IP)
    {
        ipPackets++;
    }

    handleIPV4(bufferPacket);

    // split the packet by protocol
    // TCP is protocol 6
    if (bufferPacket.iph->protocol == 6)
    {
        bufferPacket.tcph = (struct tcphdr *)(bufferPacket.pkt + (bufferPacket.iph->ihl * BYTESIN32BITS) + sizeof(struct ether_header));
        tcppackets++;
        tcpPacketHandler(bufferPacket);
    }
    // UDP
    else if (bufferPacket.iph->protocol == 17)
    {
        bufferPacket.udph = (struct udphdr *)(bufferPacket.pkt + bufferPacket.iph->ihl * BYTESIN32BITS) + sizeof(struct ether_header);
        udpPacketHandler(bufferPacket);
    }
    // another protocol type
    else if ((bufferPacket.iph->protocol) && ((bufferPacket.iph->protocol >= 0 && bufferPacket.iph->protocol < 6) || (bufferPacket.iph->protocol >= 7 && bufferPacket.iph->protocol < 255)))
    {
        transportArr.push_back("?");
        transportHdrLenArr.push_back("?");
        payloadLenArr.push_back("?");
    }
    // not a protocol
    else
    {
        transportArr.push_back("-");
        transportHdrLenArr.push_back("-");
        payloadLenArr.push_back("-");
    }

    return (1);
}

// prints the summary output
void printSummary()
{
    printf("FIRST PKT: %lf\nLAST PKT: %lf\nTOTAL PACKETS: %d\nIP PACKETS: %d\n", firtPacketTime, lastPacketTime, totalPAckets, ipPackets);
}

// prints the arrays allocated for the length information
void printLength()
{
    for (int i = 0; i < ipPackets; i++)
    {
        std::cout << timeStampArr.at(i) << ' ';
        std::cout << caplenArr.at(i) << ' ';
        std::cout << ipLenArr.at(i) << ' ';
        std::cout << ipHdrLenArr.at(i) << ' ';
        std::cout << transportArr.at(i) << ' ';
        std::cout << transportHdrLenArr.at(i) << ' ';
        std::cout << payloadLenArr.at(i) << '\n';
    }
}

// prints every element in the arrays for the packets information
void printPackets()
{
    for (int i = 0; i < tcppackets; i++)
    {
        std::cout << timeStampTCPArr.at(i) << ' ';
        std::cout << srcIPArr.at(i) << ' ';
        std::cout << dstIPArr.at(i) << ' ';
        std::cout << ipTTLArr.at(i) << ' ';
        std::cout << srcPortArr.at(i) << ' ';
        std::cout << dstPortArr.at(i) << ' ';
        std::cout << windowArr.at(i) << ' ';
        std::cout << seqNumArr.at(i) << ' ';
        std::cout << AckArr.at(i) << '\n';
    }
}

// prints every element in the map of ip pairs
void printMatrix()
{
    for (const auto &elem : pairsTraffic)
    {
        std::cout << elem.first << " " << elem.second << "\n";
    }
}

// opens the trace file
void openTraceFile(char *fileToOpen)
{
    int tracePtr = open(fileToOpen, O_RDWR);

    if (tracePtr > 0)
    {
        int packetCount = 0;
        tcppackets = 0;
        while (read_packet(tracePtr, packetCount))
        {
            packetCount++;
        }
        totalPAckets = packetCount;
        close(tracePtr);
    }
    else{
        errexit("Couldn't open file");
    }
}

int main(int argc, char **argv)
{
    char *fileToOpen;
    int optionCount = 0;
    char option;
    while ((option = getopt(argc, argv, OPTSTRING)) != EOF)
    {
        switch (option)
        {
        case 's':
        {
            sumOption = true;
            optionCount++;
            break;
        }

        case 'l':
        {
            lengthOption = true;
            optionCount++;
            break;
        }

        case 'p':
        {
            packetOption = true;
            optionCount++;
            break;
        }

        case 'm':
        {
            matrixOption = true;
            optionCount++;
            break;
        }

        case 't':
        {
            traceOption = true;
            fileToOpen = optarg;
            break;
        }

        case '?':
        {
            errexit("correct usage ./proj4 -t trace_file -s|-l|-p|-m");
            break;
        }

        case ':':
        {
            errexit("correct usage ./proj4 -t trace_file -s|-l|-p|-m");
            break;
        }

        default:
        {

            break;
        }
        }
    }
    if (optionCount > 1)
    {
        errexit("correct usage ./proj4 -t trace_file -s|-l|-p|-m");
    }
    if (traceOption)
    {
        openTraceFile(fileToOpen);
    }

    if (traceOption && sumOption)
    {
        printSummary();
    }
    else if (traceOption && lengthOption)
    {
        printLength();
    }
    else if (traceOption && packetOption)
    {
        printPackets();
    }
    else if (traceOption && matrixOption)
    {
        printMatrix();
    }
    else
    {
        errexit("correct usage ./proj4 -t trace_file -s|-l|-p|-m");
    }
}
