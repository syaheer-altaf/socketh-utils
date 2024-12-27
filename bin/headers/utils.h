#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>  // htons()
#include <net/if.h>

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // memcpy()
#include <unistd.h> // close()
#include <datagrams.h>

#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IPV4 0x0800
#define ETH_HW_TYPE 1
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define IPV4_PROTO_TCP 6
#define IPV4_PROTO_UDP 17

#define BROADCAST_ETH_ADDR "ff:ff:ff:ff:ff:ff"
#define BUFFER_SIZE 65536
#define info(...) printf(__VA_ARGS__ "\n")

/*
 * ==================
 * GENERAL UTILITIES:
 * ==================
 */

/*
 * Converts string MAC address to uint8_t *
 */
void convert_mac_addr(const char *mac_str, uint8_t *mac_out) 
{
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_out[0], &mac_out[1], &mac_out[2], 
           &mac_out[3], &mac_out[4], &mac_out[5]);
}
/*
 * Converts string IPv4 address to uint32_t
 */
int convert_ipv4_addr(const char *ip_str, uint32_t *ip_out)
{
    unsigned int octets[4];
    uint8_t byte_array[4];
    if (sscanf(ip_str, "%u.%u.%u.%u", &octets[0], &octets[1], &octets[2], 
    &octets[3]) != 4) {
        perror("invalid IP address format");
        return -1;
    }
    // validate each octet is within the valid range
    for (int i = 0; i < 4; ++i) {
        if (octets[i] > 255) {
            perror("invalid octet in IP address");
            return -1;
        }
        byte_array[i] = (uint8_t)octets[i];
    }
    memcpy(ip_out, byte_array, sizeof(uint32_t));
    return 0;
}
/*
 * Prints MAC address
 */
void print_mac_addr(uint8_t *mac)
{
    printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac[0], mac[1], mac[2],
               mac[3], mac[4], mac[5]);
}
/*
 * Prints IPv4 address
 */
void print_ipv4_addr(uint32_t *ip)
{
    printf("IP address: %d.%d.%d.%d\n",
            (*ip & 0xff), (*ip >> 8) & 0xff,
            (*ip >> 16) & 0xff, (*ip >> 24) & 0xff);
}
/*
 * Gets localhost interface info from if_nameindex struct
 * Returns 0 on success
 */
int get_if_info(struct if_nameindex *_if, uint8_t *mac, uint32_t *ip)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, _if->if_name, IF_NAMESIZE);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // get IP and MAC addresses
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR failed");
        close(sockfd);
        return -1;
    }
    memcpy(ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr, 
    sizeof(uint32_t));
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFHWADDR failed");
        close(sockfd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LENGTH);
    close(sockfd);
    return 0;
}
/*
 * ==============
 * ARP UTILITIES:
 * ==============
 */

/*
 * Prints an ARP packet
 */
void print_arp_pkt(const struct arp_pkt *arp_pkt)
{
    printf("\nARP packet:\n");
    printf("Hardware type:  %d\n", ntohs(arp_pkt->hardware_type));
    printf("Protocol type:  0x%04x\n", ntohs(arp_pkt->protocol_type));
    printf("Hardware size:  %d\n", arp_pkt->hardware_len);
    printf("Protocol size:  %d\n", arp_pkt->protocol_len);
    printf("Opcode: %d\n", ntohs(arp_pkt->opcode));
    printf("Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
    arp_pkt->sender_mac_addr[0],arp_pkt->sender_mac_addr[1],arp_pkt->sender_mac_addr[2],
    arp_pkt->sender_mac_addr[3],arp_pkt->sender_mac_addr[4],arp_pkt->sender_mac_addr[5]);
    printf("Sender IP address:  %d.%d.%d.%d\n",arp_pkt->sender_ip_addr[0],arp_pkt->sender_ip_addr[1],
    arp_pkt->sender_ip_addr[2],arp_pkt->sender_ip_addr[3]);
    printf("Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
    arp_pkt->target_mac_addr[0],arp_pkt->target_mac_addr[1],arp_pkt->target_mac_addr[2],
    arp_pkt->target_mac_addr[3],arp_pkt->target_mac_addr[4],arp_pkt->target_mac_addr[5]);
    printf("Target IP address:  %d.%d.%d.%d\n",arp_pkt->target_ip_addr[0],arp_pkt->target_ip_addr[1],
    arp_pkt->target_ip_addr[2],arp_pkt->target_ip_addr[3]);
    printf("\n\n");
}
/*
 * Gets the ARP packet from a buffer
 * Returns 0 on successs
 */
int get_arp_pkt(unsigned char *buffer, unsigned int buffer_size,
struct arp_pkt *arp_pkt)
{
    unsigned int SIZE = ETH_HDR_LENGTH + ARP_PACKET_LENGTH;
    if (buffer_size < SIZE)
        return -1; // does not meet the size requirement
    struct eth_hdr *recv = (struct eth_hdr *) buffer;
    if (ntohs(recv->eth_type) != (uint16_t) ETH_TYPE_ARP)
        return -1;  // not an ARP packet
    memcpy(arp_pkt, buffer + ETH_HDR_LENGTH, ARP_PACKET_LENGTH);
    return 0;
}
/*
 * Sends an ARP packet from a file descriptor (etc.)
 * Returns 0 on successs
 */
int send_arp_pkt(int fd, int ifindex, int pkt_type, 
                    uint16_t opcode,const uint8_t *src_mac, 
                    const uint32_t *src_ip, const uint8_t *dst_mac, 
                    const uint32_t *dst_ip)
{
    unsigned int SIZE = ETH_HDR_LENGTH + ARP_PACKET_LENGTH;
    unsigned char buffer[SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_family = AF_PACKET; // htons not needed for family
    socket_address.sll_protocol = htons(ETH_TYPE_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_pkttype = pkt_type;
    socket_address.sll_halen = ETH_ADDR_LENGTH;
    memcpy(socket_address.sll_addr, dst_mac, ETH_ADDR_LENGTH);

    // create ARP packet with Ethernet header
    struct eth_hdr *hdr = (struct eth_hdr *)buffer;
    struct arp_pkt *pkt = (struct arp_pkt *)(buffer + ETH_HDR_LENGTH);

    // fill Ethernet header
    memcpy(hdr->dst_addr, dst_mac, ETH_ADDR_LENGTH);
    memcpy(hdr->src_addr, src_mac, ETH_ADDR_LENGTH);
    hdr->eth_type = htons(ETH_TYPE_ARP);

    // fill ARP packet
    pkt->hardware_type = htons(ETH_HW_TYPE);
    pkt->protocol_type = htons(ETH_TYPE_IPV4);
    pkt->hardware_len = ETH_ADDR_LENGTH;
    pkt->protocol_len = IPV4_ADDR_LENGTH;
    pkt->opcode = htons(opcode);
    memcpy(pkt->sender_mac_addr, src_mac, ETH_ADDR_LENGTH);
    memcpy(pkt->sender_ip_addr, src_ip, IPV4_ADDR_LENGTH);
    memcpy(pkt->target_mac_addr, dst_mac, ETH_ADDR_LENGTH);
    memcpy(pkt->target_ip_addr, dst_ip, IPV4_ADDR_LENGTH);

    if (sendto(fd, buffer, SIZE, 0, (struct sockaddr *)&socket_address, 
    sizeof(socket_address)) < 0) {
        perror("sendto()");
        return -1;
    }

    return 0;
}
/*
 * Gets MAC address from file descriptor, if_nameindex struct,
 * and destination ip adress
 * Returns 0 on success
 */
int get_mac_addr(int fd, struct if_nameindex *_if, uint32_t dst_ip, 
                 uint8_t *mac_addr)
{
    // it is easier to check your arp table first
    // but we will implement this later...
    // specify the fields and continuously broadcast arp packet
    uint32_t src_ip;
    uint8_t src_mac[ETH_ADDR_LENGTH];
    uint8_t dst_mac[ETH_ADDR_LENGTH];
    get_if_info(_if, src_mac, &src_ip);
    convert_mac_addr(BROADCAST_ETH_ADDR, dst_mac);
    unsigned char buffer[BUFFER_SIZE];
    while (1) {
        memset(buffer, 0, BUFFER_SIZE); // reset buffer

        // send ARP packet
        if (send_arp_pkt(fd, _if->if_index, PACKET_BROADCAST, ARP_REQUEST, 
        src_mac, &src_ip, dst_mac, &dst_ip) < 0) {
            perror("send_arp_packet() failed");
            return -1;
        }
        // get ARP packet
        struct arp_pkt *arp_pkt = malloc(ARP_PACKET_LENGTH);
        if (arp_pkt == NULL) {
            perror("failed to allocate memory");
            return -1;
        }
        if (recvfrom(fd, buffer, BUFFER_SIZE, 0, NULL, NULL) < 0) {
            perror("recvfrom()");
            free(arp_pkt);
            return -1;
        }
        if (get_arp_pkt(buffer, sizeof(buffer), arp_pkt) == 0) {
            uint32_t sender_ip;
            memcpy(&sender_ip, arp_pkt->sender_ip_addr, sizeof(uint32_t));
            if (sender_ip == dst_ip) {
                memcpy(mac_addr, arp_pkt->sender_mac_addr, ETH_ADDR_LENGTH);
                free(arp_pkt);
                break;
            }
        }
        free(arp_pkt);
    }
    return 0;
}
/*
 * ===============
 * IPV4 UTILITIES:
 * ===============
 */

/*
 * Prints an IPv4 header
 */
void print_ipv4_hdr(struct ipv4_hdr *ipv4)
{
    printf("\nIPv4 Header:\n");
    printf("Version: %u\n", ipv4->version_ihl >> 4);
    printf("IHL: %u (bytes: %u)\n", ipv4->version_ihl & 0x0F, 
            (ipv4->version_ihl & 0x0F) * 4);
    printf("Type of Service: 0x%02x\n", ipv4->type_of_service);
    printf("Total Length: %u\n", ntohs(ipv4->total_length));
    printf("Packet ID: %u\n", ntohs(ipv4->packet_id));
    printf("Fragment Offset: %u\n", ntohs(ipv4->fragment_offset) & 0x1FFF);
    printf("Flags: 0x%x\n", (ntohs(ipv4->fragment_offset) & 0xE000) >> 13);
    printf("Time to Live: %u\n", ipv4->time_to_live);
    printf("Next Protocol ID: %u\n", ipv4->next_proto_id);
    printf("Header Checksum: 0x%04x\n", ntohs(ipv4->hdr_checksum));
    printf("Source IP: %u.%u.%u.%u\n", ipv4->src_addr[0], ipv4->src_addr[1], 
            ipv4->src_addr[2], ipv4->src_addr[3]);
    printf("Destination IP: %u.%u.%u.%u\n", ipv4->dst_addr[0], ipv4->dst_addr[1], 
            ipv4->dst_addr[2], ipv4->dst_addr[3]);
    printf("\n\n");
}
/*
 * Gets the IPv4 header from a buffer
 * Returns 0 on success
 */
int get_ipv4_hdr(unsigned char *buffer, unsigned int buffer_size,
struct ipv4_hdr *ip_hdr)
{
    unsigned int SIZE = ETH_HDR_LENGTH + IPV4_HDR_LENGTH;
    if (buffer_size < SIZE)
        return -1; // does not meet the size requirement
    struct eth_hdr *recv = (struct eth_hdr *) buffer;
    if (ntohs(recv->eth_type) != (uint16_t) ETH_TYPE_IPV4)
        return -1; // not an ip packet
    struct ipv4_hdr* temp = malloc(IPV4_HDR_LENGTH);
    memcpy(temp, buffer + ETH_HDR_LENGTH, IPV4_HDR_LENGTH);
    unsigned int version = temp->version_ihl >> 4;
    if (version != 4) {
        free(temp);
        return -1; // not an ipv4 packet
    }
    memcpy(ip_hdr, temp, IPV4_HDR_LENGTH);
    free(temp);
    return 0;
}
/*
 * Function to calculate IPv4 checksum
 */
uint16_t calculate_ipv4_checksum(unsigned char *header, size_t length) {
    uint32_t sum = 0;

    // sum 16-bit words
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word = (header[i] << 8) | header[i + 1];
        sum += word;
        if (sum > 0xFFFF) {
            sum -= 0xFFFF; // wrap around
        }
    }

    // 1's complement
    return ~sum;
}
/*
 * ==============
 * UDP UTILITIES:
 * ==============
 */

/*
 * Prints a UDP header
 */
void print_udp_hdr(struct udp_hdr *udp_hdr)
{
    printf("\nUDP Header:\n");
    printf("Source port: %u\n", ntohs(udp_hdr->src_port));
    printf("Destination port: %u\n", ntohs(udp_hdr->dst_port));
    printf("Length: %u\n", ntohs(udp_hdr->length));
    printf("Checksum: 0x%04x\n", ntohs(udp_hdr->checksum));
    printf("\n\n");
}
/*
 * Gets the UDP header from a buffer
 * Returns 0 on success
 */
int get_udp_hdr(unsigned char *buffer, unsigned int buffer_size,
struct udp_hdr *udp_hdr)
{
    unsigned int SIZE = ETH_HDR_LENGTH + IPV4_HDR_LENGTH + UDP_HDR_LENGTH;
    if (buffer_size < SIZE)
        return -1; // does not meet the size requirement
    struct ipv4_hdr *temp = malloc(IPV4_HDR_LENGTH);
    if (get_ipv4_hdr(buffer, buffer_size, temp) < 0) {
        free(temp);
        return -1;
    }
    unsigned int protocol_id = temp->next_proto_id;
    if (protocol_id != IPV4_PROTO_UDP)
        return -1; // not udp packet
    // compute the IPv4 header length in bytes (IHL is in 32-bit words)
    unsigned int len = (temp->version_ihl & 0x0F) * 4;
    memcpy(udp_hdr, buffer + (ETH_HDR_LENGTH + len), UDP_HDR_LENGTH);
    free(temp);
    return 0;
}
/*
 * ==============
 * DNS UTILITIES:
 * ==============
 */

/*
 * Prints a DNS header
 */
void print_dns_hdr(struct dns_hdr *dns_hdr)
{
    printf("\nDNS Header:\n");
    printf("ID: 0x%x\n", ntohs(dns_hdr->id));
    printf("Flags: 0x%x\n", ntohs(dns_hdr->flags));
    printf("Questions: %u\n", ntohs(dns_hdr->question_count));
    printf("Answers: %u\n", ntohs(dns_hdr->answer_count));
    printf("Authority RRs: %u\n", ntohs(dns_hdr->authority_count));
    printf("Additional RRs: %u\n", ntohs(dns_hdr->additional_count));
}
void print_dns_query(struct dns_query *dq)
{
    printf("\nDNS Query:\n");
    printf("Query Name: %s\n", dq->qname);
    printf("Query Type: %u\n", dq->qtype);
    printf("Query Class: %u\n", dq->qclass);
}

/*
 * Gets the DNS header + DNS query from a buffer
 * Returns 0 on success
 */
int get_dns_hdr_query(unsigned char *buffer, unsigned int buffer_size,
                      struct dns_hdr *dns_hdr, struct dns_query *dns_query)
{
    unsigned int SIZE = ETH_HDR_LENGTH + IPV4_HDR_LENGTH + UDP_HDR_LENGTH + DNS_HDR_LENGTH;
    if (buffer_size < SIZE)
        return -1; // does not meet the size requirement
    struct udp_hdr *temp = malloc(UDP_HDR_LENGTH);
    if (get_udp_hdr(buffer, buffer_size, temp) < 0) {
        free(temp);
        return -1; // not UDP packet
    }
    if (ntohs(temp->dst_port) != 53) {
        free(temp);
        return -1; // most likely not a DNS query packet
    }
    free(temp);

    // extract the DNS header
    unsigned int udp_offset = ETH_HDR_LENGTH + 20 + UDP_HDR_LENGTH;
    if (buffer_size < udp_offset + DNS_HDR_LENGTH)
        return -1; // not enough space for DNS header

    memcpy(dns_hdr, buffer + udp_offset, DNS_HDR_LENGTH);

    // extract the DNS query
    unsigned char *query_start = buffer + udp_offset + DNS_HDR_LENGTH;
    if (query_start >= buffer + buffer_size)
        return -1; // buffer overflow for DNS query
    unsigned char *qname_ptr = query_start;
    size_t qname_length = 0;
    while (*qname_ptr != 0 && qname_ptr < buffer + buffer_size) {
        size_t label_length = *qname_ptr + 1; // include label length byte
        if (qname_length + label_length >= DNS_DOMAIN_LENGTH || qname_ptr + label_length >= buffer + buffer_size)
            return -1; // domain name too long or exceeds buffer
        memcpy(dns_query->qname + qname_length, qname_ptr + 1, label_length - 1);
        qname_ptr += label_length;
        qname_length += label_length - 1;
        dns_query->qname[qname_length++] = '.'; // append a dot
    }
    if (qname_length > 0)
        dns_query->qname[qname_length - 1] = '\0'; // replace the last dot with null-terminator

    if (*qname_ptr != 0 || qname_ptr + 5 > buffer + buffer_size)
        return -1; // invalid DNS packet format
    dns_query->qtype = ntohs(*(uint16_t *)(qname_ptr + 1));
    dns_query->qclass = ntohs(*(uint16_t *)(qname_ptr + 3));
    return 0;
}