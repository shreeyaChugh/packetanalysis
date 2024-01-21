/*
Name: Shreeya Chugh
Case ID: sxc1514
Project 4 CSDS 325
*/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <ostream>
#include <iostream>
#include <sstream>

#define ERROR 1
#define MAX_PKT_SIZE 1600

bool sexists = false;
bool rexists = false;
bool lexists = false;
bool pexists = false;
bool cexists = false;

char *trace_file;

/* meta information, using the same layout as the trace file */
struct meta_info
{
    unsigned int usecs;
    unsigned int secs;
    unsigned short ignored;
    unsigned short caplen;
};

/* record of information about the current packet */
struct pkt_info
{
    unsigned short caplen; /* from meta info */
    double now;            /* from meta info */
    unsigned char pkt[MAX_PKT_SIZE];
    struct ether_header *ethh; /* ptr to ethernet header, if present,
                                  otherwise NULL */
    struct ip *iph;            /* ptr to IP header, if present,
                                  otherwise NULL */
    struct tcphdr *tcph;       /* ptr to TCP header, if present,
                                  otherwise NULL */
    struct udphdr *udph;       /* ptr to UDP header, if present,
                                  otherwise NULL */
};

bool in_mode = false; // checks if a mode has already been selected

int errexit(const char *format, const char *arg)
{
    fprintf(stderr, format, arg);
    fprintf(stderr, "\n");
    exit(ERROR);
}

/* fd - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

   returns:
   1 - a packet was read and pinfo is set up for processing the packet
   0 - we have hit the end of the file and no packet is available
 */
unsigned short next_packet(int fd, struct pkt_info *pinfo)
{
    struct meta_info meta;
    int bytes_read;

    memset(pinfo, 0x0, sizeof(struct pkt_info));
    memset(&meta, 0x0, sizeof(struct meta_info));

    /* read the meta information */
    bytes_read = read(fd, &meta, sizeof(meta));
    if (bytes_read == 0)
        return (0);
    if (bytes_read < static_cast<int>(sizeof(meta)))
        errexit("cannot read meta information", NULL);
    pinfo->caplen = ntohs(meta.caplen);
    /* TODO: set pinfo->now based on meta.secs & meta.usecs */
    pinfo->now = ntohl(meta.secs) + ntohl(meta.usecs) / 1000000.0;
    if (pinfo->caplen == 0)
        return (1);
    if (pinfo->caplen > MAX_PKT_SIZE)
        errexit("packet too big", NULL);
    /* read the packet contents */
    bytes_read = read(fd, pinfo->pkt, pinfo->caplen);
    if (bytes_read < 0)
        errexit("error reading packet", NULL);
    if (bytes_read < pinfo->caplen)
        errexit("unexpected end of file encountered", NULL);
    if (bytes_read < static_cast<int>(sizeof(struct ether_header)))
        return (1);
    pinfo->ethh = (struct ether_header *)pinfo->pkt;
    pinfo->ethh->ether_type = ntohs(pinfo->ethh->ether_type);
    if (pinfo->ethh->ether_type != ETHERTYPE_IP)
        /* nothing more to do with non-IP packets */
        return (1);
    if (pinfo->caplen == sizeof(struct ether_header))
        /* we don't have anything beyond the ethernet header to process */
        return (1);
    /* TODO:
       set pinfo->iph to start of IP header
       if TCP packet,
          set pinfo->tcph to the start of the TCP header
          setup values in pinfo->tcph, as needed
       if UDP packet,
          set pinfo->udph to the start of the UDP header,
          setup values in pinfo->udph, as needed */

    pinfo->iph = (struct ip *)(pinfo->pkt + sizeof(struct ether_header));

    if (pinfo->iph->ip_p == IPPROTO_TCP)
    {
        /* Set pinfo->tcph to the start of the TCP header and set up values in pinfo->tcph, as needed */
        pinfo->tcph = (struct tcphdr *)(pinfo->pkt + sizeof(struct ether_header) + pinfo->iph->ip_hl * 4);
        // You can access TCP header fields using pinfo->tcph->
    }
    else if (pinfo->iph->ip_p == IPPROTO_UDP)
    {
        /* Set pinfo->udph to the start of the UDP header and set up values in pinfo->udph, as needed */
        pinfo->udph = (struct udphdr *)(pinfo->pkt + sizeof(struct ether_header) + pinfo->iph->ip_hl * 4);
        // You can access UDP header fields using pinfo->udph->
    }
    return (1);
}

/*
Prints out the following information
    - timestamp of first packet
    - timestamp of the last packet
    - the time bw them
    - number of packets in trace file
    - number of IP packets

    This is for the -s command

    */

void in_summary_mode(char *trace_file)
{
    // declaring variables
    double first_timestamp = 0.0;
    double last_timestamp = 0.0;
    double time_difference = 0.0;
    int num_packets = 0;
    int num_ip_packets = 0;

    struct pkt_info curr_packet;
    int fd = open(trace_file, O_RDONLY);
    if (fd == -1)
    {
        errexit("cannot open file", NULL);
    }
    // while next packet is not null
    while (next_packet(fd, &curr_packet))
    {
        if (curr_packet.ethh && curr_packet.ethh->ether_type == ETHERTYPE_IP)
        {
            num_ip_packets++;
        }
        num_packets++;
        // check if it is the first packet
        if (first_timestamp == 0.0)
        {
            first_timestamp = curr_packet.now;
        }
        last_timestamp = curr_packet.now;
        time_difference = last_timestamp - first_timestamp;
    }
    printf("time: first: %.6f last: %.6f duration: %.6f\n", first_timestamp, last_timestamp, time_difference);
    printf("pkts: total: %d ip: %d\n", num_packets, num_ip_packets);
}

// this method is for -l
void in_length_mode(char *trace_file)
{
    struct pkt_info curr_packet;
    int fd = open(trace_file, O_RDONLY);
    if (fd == -1)
    {
        errexit("cannot open file", NULL);
    }

    while (next_packet(fd, &curr_packet))
    {
        // declarations
        char transport;
        int trans_hl;
        int payload_len;
        std::string trans_hl_str = "";
        std::string payload_len_str = "";

        if (curr_packet.ethh && curr_packet.ethh->ether_type == ETHERTYPE_IP)
        {
            double ts = curr_packet.now;
            unsigned short caplen = curr_packet.caplen;

            if (curr_packet.iph)
            {
                int ip_len = ntohs(curr_packet.iph->ip_len);
                int iphl = curr_packet.iph->ip_hl * 4;
                // if it is TCP
                if (curr_packet.iph->ip_p == IPPROTO_TCP)
                {
                    transport = 'T';
                    trans_hl = (curr_packet.tcph) ? curr_packet.tcph->th_off * 4 : 0;
                    trans_hl_str = (trans_hl != 0) ? std::to_string(trans_hl) : "-";
                    payload_len = (trans_hl != 0) ? ip_len - iphl - trans_hl : -1;
                    payload_len_str = (trans_hl != 0) ? std::to_string(payload_len) : "-";
                }
                // if it is UDP
                else if (curr_packet.iph->ip_p == IPPROTO_UDP)
                {
                    transport = 'U';
                    trans_hl = (curr_packet.udph) ? sizeof(struct udphdr) : 0;
                    trans_hl_str = (trans_hl != 0) ? std::to_string(trans_hl) : "-";
                    payload_len = (trans_hl != 0) ? ip_len - iphl - trans_hl : -1;
                    payload_len_str = (trans_hl != 0) ? std::to_string(payload_len) : "-";
                }
                // if protocol is between 0 and 6 and not 17
                else if (curr_packet.iph->ip_p >= 0 && curr_packet.iph->ip_p <= 6 && curr_packet.iph->ip_p != 17)
                {
                    transport = '?';
                    trans_hl_str = "?";
                    payload_len_str = "?";
                }
                else
                {
                    transport = '-';
                    trans_hl_str = "-";
                    payload_len_str = "-";
                }

                // Print formatted output
                printf("%.6f %u %d %d %c %s %s\n", ts, caplen, ip_len, iphl, transport, trans_hl_str.c_str(), payload_len_str.c_str());
            }
            else
            {
                printf("%.6f %u - - - - -\n", ts, caplen);
            }
        }
    }
    close(fd);
}

// this method is for -p
void in_packet_printing_mode(char *trace_file)
{
    struct pkt_info curr_packet;
    int fd = open(trace_file, O_RDONLY);
    if (fd == -1)
    {
        errexit("cannot open file", NULL);
    }

    while (next_packet(fd, &curr_packet))
    {
        if (curr_packet.iph && curr_packet.iph->ip_p == IPPROTO_TCP)
        {
            struct ip *ip_header = curr_packet.iph;
            struct tcphdr *tcp_header = (struct tcphdr *)((unsigned char *)ip_header + (ip_header->ip_hl * 4));

            if (tcp_header)
            {
                double ts = curr_packet.now;
                uint16_t src_port = ntohs(tcp_header->th_sport);
                uint16_t dst_port = ntohs(tcp_header->th_dport);

                // Skip packets with source or destination port as 0
                if (src_port == 0 || dst_port == 0)
                {
                    continue;
                }

                char src_ip_str[INET_ADDRSTRLEN];
                char dst_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

                const char *ack_str = (tcp_header->th_flags & TH_ACK) ? "1" : "-";

                if (tcp_header->th_flags & TH_ACK)
                {
                    uint32_t ackno = ntohl(tcp_header->ack_seq);
                    printf("%.6f %s %u %s %u %u %u %u %u\n",
                           ts, src_ip_str, src_port, dst_ip_str, dst_port,
                           ntohs(ip_header->ip_id), ip_header->ip_ttl,
                           ntohs(tcp_header->window), ackno);
                }
                else
                {
                    printf("%.6f %s %u %s %u %u %u %u %s\n",
                           ts, src_ip_str, src_port, dst_ip_str, dst_port,
                           ntohs(ip_header->ip_id), ip_header->ip_ttl,
                           ntohs(tcp_header->window), ack_str);
                }
            }
        }
    }

    close(fd);
}

struct TrafficInfo
{
    uint64_t totalPkts;
    uint64_t payload_len;
};

// this method is for -c
void in_packet_counting_mode(char *trace_file)
{
    std::unordered_map<std::string, TrafficInfo> trafficMap;

    struct pkt_info curr_packet;
    int fd = open(trace_file, O_RDONLY);
    if (fd == -1)
    {
        errexit("cannot open this file", NULL);
    }

    while (next_packet(fd, &curr_packet))
    {
        if (curr_packet.ethh && curr_packet.ethh->ether_type == ETHERTYPE_IP)
        {
            if (curr_packet.iph && curr_packet.iph->ip_p == IPPROTO_TCP)
            {
                struct ip *ip_header = curr_packet.iph;
                struct tcphdr *tcp_header = (struct tcphdr *)((unsigned char *)ip_header + (ip_header->ip_hl * 4));

                if (tcp_header)
                {
                    char src_ip_str[INET_ADDRSTRLEN];
                    char dst_ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

                    std::string key = std::string(src_ip_str) + " " + std::string(dst_ip_str);

                    uint64_t payload = ntohs(curr_packet.iph->ip_len) - (curr_packet.iph->ip_hl * 4) - (curr_packet.tcph->th_off * 4);

                    // uint64_t payload = ntohs(curr_packet.iph->tot_len) - ntohs(curr_packet.iph->ifl * 4) - ntohs(curr_packet.tcph->th_off * 4);
                    if (trafficMap.find(key) == trafficMap.end())
                    {
                        // TrafficInfo info = {1, curr_packet.caplen - (ip_header->ip_hl * 4 + tcp_header->th_off * 4)};
                        TrafficInfo info = {1, payload};
                        trafficMap[key] = info;
                    }
                    else
                    {
                        trafficMap[key].totalPkts++;
                        // trafficMap[key].payload_len += curr_packet.caplen - (ip_header->ip_hl * 4 + tcp_header->th_off * 4);
                        trafficMap[key].payload_len += payload;
                    }
                }
            }
        }
    }

    // Print the traffic information
    for (const auto &entry : trafficMap)
    {
        const std::string &key = entry.first;
        const TrafficInfo &info = entry.second;

        std::string src_ip, dst_ip;
        uint64_t total_pkts, payload_len;

        std::istringstream iss(key);
        iss >> src_ip >> dst_ip;

        total_pkts = info.totalPkts;
        payload_len = info.payload_len;

        std::cout << src_ip << " " << dst_ip << " " << total_pkts << " " << payload_len << std::endl;
    }

    close(fd);
}

// checking if r is present and if one of s,l,p,c is present
void checkRequiredArgs()
{
    if (!rexists)
    {
        errexit("-r is a required argument. Please try again.", NULL);
    }
    if (!sexists && !lexists && !pexists && !cexists)
    {
        errexit("Please specify at least one mode argument.", NULL);
    }
}
// parsing arguments
void parsingArguments(int argc, char *argv[])
{
    int opt;
    bool rOption = false;

    while ((opt = getopt(argc, argv, "r:slpc")) != -1)
    {
        switch (opt)
        {
        case 'r':
            if (optarg == NULL || optarg[0] == '-')
            {
                errexit("Tracefile Argument missing", NULL);
            }
            trace_file = optarg;
            rexists = true;
            rOption = true;
            break;

        case 's':
            if (in_mode)
            {
                errexit("A mode has already been selected", NULL);
            }
            sexists = true;
            in_mode = true;
            break;

        case 'l':
            if (in_mode)
            {
                errexit("A mode has already been selected", NULL);
            }
            lexists = true;
            in_mode = true;
            break;

        case 'p':
            if (in_mode)
            {
                errexit("A mode has already been selected", NULL);
            }
            pexists = true;
            in_mode = true;
            break;

        case 'c':
            if (in_mode)
            {
                errexit("A mode has already been selected", NULL);
            }
            cexists = true;
            in_mode = true;
            break;

        case '?':
            errexit("Command not known. %c", NULL);
            break;
        case ':':
            errexit("Tracefile missing", NULL);
            break;
        }
    }

    // Check if -r was seen and its argument is NULL
    if (rOption && !trace_file)
    {
        errexit("Tracefile Argument missing", NULL);
    }
    checkRequiredArgs();
}

int main(int argc, char *argv[])
{
    parsingArguments(argc, argv);
    if (sexists)
    {
        // Call the function for '-s' mode
        in_summary_mode(trace_file);
    }
    if (lexists)
    {
        in_length_mode(trace_file);
    }
    if (pexists)
    {
        in_packet_printing_mode(trace_file);
    }
    if (cexists)
    {
        in_packet_counting_mode(trace_file);
    }
    return 0;
}

