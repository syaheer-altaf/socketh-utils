#include <stdint.h>

#define ETH_HDR_LENGTH 14
#define ETH_ADDR_LENGTH 6
#define ARP_PACKET_LENGTH 28

#define IPV4_HDR_LENGTH 60
#define IPV4_ADDR_LENGTH 4

#define UDP_HDR_LENGTH 8
#define DNS_HDR_LENGTH 12
#define DNS_DOMAIN_LENGTH 255
#define DNS_RDATA_MAX 512
/*
 * uint8_t     :   1 byte unsigned integer 
 * uint16_t    :   2 byte unsigned integer 
 * uint32_t    :   4 byte unsigned integer 
 * uint64_t    :   8 byte unsigned integer
 */

/*
 * Ethernet header struct
 */
struct eth_hdr {
    uint8_t     dst_addr[ETH_ADDR_LENGTH];
    uint8_t     src_addr[ETH_ADDR_LENGTH];
    uint16_t    eth_type;
};
/*
 * ARP packet struct
 */
struct arp_pkt {
    uint16_t    hardware_type;
    uint16_t    protocol_type;
    uint8_t     hardware_len;
    uint8_t     protocol_len;
    uint16_t    opcode;
    uint8_t     sender_mac_addr[ETH_ADDR_LENGTH];
    uint8_t     sender_ip_addr[IPV4_ADDR_LENGTH];
    uint8_t     target_mac_addr[ETH_ADDR_LENGTH];
    uint8_t     target_ip_addr[IPV4_ADDR_LENGTH];
};
/*
 * IPv4 header struct
 */
struct ipv4_hdr {
    uint8_t 	version_ihl;
    uint8_t 	type_of_service;
    uint16_t 	total_length;
    uint16_t 	packet_id;
    uint16_t 	fragment_offset;
    uint8_t 	time_to_live;
    uint8_t 	next_proto_id;
    uint16_t 	hdr_checksum;
    uint8_t 	src_addr[IPV4_ADDR_LENGTH];
    uint8_t 	dst_addr[IPV4_ADDR_LENGTH];
    uint8_t     optional[40];   // (optional)
};
/*
 * UDP header struct
 */
struct udp_hdr {
    uint16_t    src_port;
    uint16_t    dst_port;
    uint16_t    length;
    uint16_t    checksum;   // (optional)
};
/*
 * DNS header struct
 */
struct dns_hdr {
    uint16_t    id;
    uint16_t    flags;
    uint16_t    question_count;
    uint16_t    answer_count;
    uint16_t    authority_count;
    uint16_t    additional_count;
};
/*
 * DNS query struct
 */
struct dns_query {
    char        qname[DNS_DOMAIN_LENGTH];
    uint16_t    qtype;
    uint16_t    qclass;
};
/*
 * DNS response struct
 */
#pragma pack(push, 1)
struct dns_response {
    char            rname[2];
    uint16_t        rtype;
    uint16_t        rclass;
    uint32_t        ttl;
    uint16_t        rdlength;
    uint8_t         rdata[DNS_RDATA_MAX];
};
#pragma pack(pop)