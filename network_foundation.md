# Understanding Networking Through Packet Structures and RFC Standards

## Introduction to RFC Documentation
The **Request for Comments (RFC)** documents are a set of technical and organizational notes about the Internet, including protocols, procedures, programs, and concepts. RFCs are maintained by the Internet Engineering Task Force (IETF) and provide standardized guidelines for implementing networking protocols. Developers refer to RFCs to ensure compatibility and consistency across networking implementations. For example, the structure of IPv4 headers is detailed in **RFC 791**, while the behavior of ARP is explained in **RFC 826**.

---

## Packet Headers and Their Relationship to RFC Standards

Packet headers define how information is encapsulated and transmitted. Below are commonly used headers based on RFC standards, along with their structures and explanations.

### Ethernet Header (RFC 894)

#### Structure
```c
struct eth_hdr {
    uint8_t     dst_addr[ETH_ADDR_LENGTH];
    uint8_t     src_addr[ETH_ADDR_LENGTH];
    uint16_t    eth_type;
};
```

#### Packet Layout (14 bytes)
```
0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Destination MAC Address (6 bytes)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Source MAC Address (6 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Ethertype (2 bytes)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Ethernet header specifies the **source** and **destination MAC addresses**, followed by the Ethertype to indicate the protocol (e.g., IPv4 or ARP). 

### IPv4 Header (RFC 791)

#### Structure
```c
struct ipv4_hdr {
    uint8_t     version_ihl;
    uint8_t     type_of_service;
    uint16_t    total_length;
    uint16_t    packet_id;
    uint16_t    fragment_offset;
    uint8_t     time_to_live;
    uint8_t     next_proto_id;
    uint16_t    hdr_checksum;
    uint8_t     src_addr[IPV4_ADDR_LENGTH];
    uint8_t     dst_addr[IPV4_ADDR_LENGTH];
    uint8_t     optional[40];   // (optional)
};
```

#### Packet Layout (20 bytes minimum)
```
0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|        Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         |Flags|    Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Time to Live  |   Protocol    |       Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Address (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Destination Address (4 bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Options (if any)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
The IPv4 header includes details like the **source and destination IP addresses**, **time-to-live (TTL)**, and **protocol** (e.g., TCP or UDP).

### UDP Header (RFC 768)

#### Structure
```c
struct udp_hdr {
    uint16_t    src_port;
    uint16_t    dst_port;
    uint16_t    length;
    uint16_t    checksum;   // (optional)
};
```

#### Packet Layout (8 bytes)
```
0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Source Port (2 bytes)   |   Destination Port (2 bytes) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Length (2 bytes)    |        Checksum (2 bytes)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
The UDP header specifies the **source and destination ports**, along with the **length** and an optional **checksum**.

### DNS Header (RFC 1035)

#### Structure
```c
struct dns_hdr {
    uint16_t    id;
    uint16_t    flags;
    uint16_t    question_count;
    uint16_t    answer_count;
    uint16_t    authority_count;
    uint16_t    additional_count;
};
```

#### Packet Layout (12 bytes)
```
0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identification (2 bytes)         |     Flags     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Question Count (2 bytes)            |   Answer Count |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Authority Record Count (2 bytes)      | Additional Count|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
DNS headers include fields like **ID**, **flags**, and counts of questions and responses.

### ARP Packet (RFC 826)

#### Structure
```c
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
```

#### Packet Layout (28 bytes)
```
0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Hardware Type (2 bytes)   |    Protocol Type (2 bytes)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Hardware Len  | Protocol Len |           Opcode             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sender MAC Address (6 bytes)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Sender IP Address (4 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target MAC Address (6 bytes)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Target IP Address (4 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
The ARP packet maps network layer addresses (IP) to link-layer addresses (MAC).

---

## Key Definitions and Constants
```c
#define ETH_HDR_LENGTH 14
#define ETH_ADDR_LENGTH 6
#define ARP_PACKET_LENGTH 28
#define IPV4_HDR_LENGTH 20
#define IPV4_ADDR_LENGTH 4
#define UDP_HDR_LENGTH 8
#define DNS_HDR_LENGTH 12
#define DNS_DOMAIN_LENGTH 255
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IPV4 0x0800
#define ETH_HW_TYPE 1
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define IPV4_PROTO_TCP 6
#define IPV4_PROTO_UDP 17
#define BROADCAST_ETH_ADDR "ff:ff:ff:ff:ff:ff"
#define BUFFER_SIZE 65536
```
---

## Understanding `ntohs()`, `ntohl()`, `htons()`, and `htonl()`

The functions `ntohs()`, `ntohl()`, `htons()`, and `htonl()` are provided in the `<arpa/inet.h>` library and are essential for converting multi-byte integers between network byte order (big-endian) and host byte order. These conversions ensure data is correctly interpreted across different architectures.

- `ntohs()`: Converts a 16-bit integer from network byte order to host byte order.
- `ntohl()`: Converts a 32-bit integer from network byte order to host byte order.
- `htons()`: Converts a 16-bit integer from host byte order to network byte order.
- `htonl()`: Converts a 32-bit integer from host byte order to network byte order.

### When to Use

These functions are used to ensure proper byte ordering when sending or receiving data over a network. Network protocols typically define a specific byte order (network byte order, which is big-endian) for their fields. 

- **When crafting a packet** (e.g., when you are building a packet to send over the network), use `htons()` for 16-bit fields and `htonl()` for 32-bit fields. This converts the field values from your system’s native host byte order to the correct network byte order.
- **When reading a packet** (e.g., when receiving data over the network), use `ntohs()` for 16-bit fields and `ntohl()` for 32-bit fields. This converts the network byte order back to your system’s host byte order for proper interpretation.

#### Example:
If a packet contains a 16-bit field (such as a port number) and you are preparing this packet to send, use `htons()` on the port number. When you receive the packet, use `ntohs()` to correctly interpret the port number.

### Note:
- **Crafting a packet**: Convert the values from host byte order to network byte order before inserting them into the packet. For a 16-bit field, use `htons()`; for a 32-bit field, use `htonl()`.
- **Reading a packet**: Convert the received network byte order back to host byte order to correctly interpret the values. For a 16-bit field, use `ntohs()`; for a 32-bit field, use `ntohl()`.

This ensures that the packet data is correctly interpreted regardless of the endianness of the machines involved in communication.

---

## Using `socket.h` for Networking

### Key Functions
1. **`socket()`**
   ```c
   int socket(int domain, int type, int protocol);
   ```
   - `AF_PACKET`: Specifies that the socket operates at the link-layer, allowing raw access to network interfaces and packets.
   - `SOCK_RAW`: Enables sending and receiving raw packets, bypassing normal protocol stack processing. This is useful for implementing custom protocols or inspecting packets directly.
   - `protocol`: Defines the type of packets the socket will handle. For example, using `htons(ETH_TYPE_IPV4)` specifies that IPv4 packets are expected.

   This function initializes the raw socket and is a crucial step in low-level network programming.

2. **`bind()`**
   ```c
   int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
   ```
   Binds the socket to a specific network interface, ensuring the application interacts with the correct device. This is necessary when monitoring or sending packets from a designated interface, especially in multi-interface systems.

3. **`recvfrom()`**
   ```c
   ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, 
                    struct sockaddr *src_addr, socklen_t *addrlen);
   ```
   Receives data directly from the network, storing it in a buffer. This function is key for analyzing incoming packets or implementing packet capture utilities. The `src_addr` parameter captures information about the sender.

4. **`sendto()`**
   ```c
   ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen);
   ```
   Sends raw packets constructed in memory to a specific destination. This function enables sending custom-crafted packets for testing or simulating protocols.

### Why Use `struct sockaddr_ll`?
The `sockaddr_ll` structure is essential when working with raw sockets at the link layer. It includes fields necessary for precise packet manipulation:
- **`sll_ifindex`**: Index of the interface through which the packet is sent or received. This links the socket to a physical or virtual network interface.
- **`sll_protocol`**: Protocol field, typically set to match the packet type (e.g., `htons(ETH_TYPE_IPV4)`).
- **Address Fields**: Includes destination and source link-layer addresses, ensuring accurate communication at the Ethernet level.

Using `sockaddr_ll` ensures proper interfacing with the link layer and enables full control over the packet’s headers and payload.

### Example: Sending an IPv4 Packet using socket.h which is declared in the custom header called utils.h
```c
#include "headers/utils.h"

int main()
{
    int ip_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_TYPE_IPV4));
    if (ip_fd < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }
    struct if_nameindex *ifr = malloc(sizeof(struct if_nameindex *));
    if (!ifr) {
        perror("Memory allocation for if_nameindex failed");
        exit(EXIT_FAILURE);
    }
    ifr->if_name = malloc(IF_NAMESIZE);
    if (!ifr->if_name) {
        perror("Memory allocation for if_name failed");
        free(ifr);
        exit(EXIT_FAILURE);
    }
    // identify your network interface name using 
    // `ip link show`in the command line
    // in this example we use "wlp4s0"
    strncpy(ifr->if_name, "wlp4s0", IF_NAMESIZE);
    ifr->if_index = if_nametoindex(ifr->if_name);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_TYPE_IPV4);
    sll.sll_ifindex = ifr->if_index;

    if (bind(ip_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind()");
        free(ifr->if_name);
        free(ifr);
        exit(EXIT_FAILURE);
    }
    // specify the fields (we use tools specify in utils.h)
    uint32_t src_ip, dest_ip;
    uint8_t src_mac[ETH_ADDR_LENGTH], dest_mac[ETH_ADDR_LENGTH];
    convert_ipv4_addr("192.168.0.100", &src_ip);    // change this to your ip
    convert_ipv4_addr("192.168.0.1", &dest_ip);     // change this to target ip
    convert_mac_addr("aa:aa:aa:aa:aa:aa", src_mac); // change this to your mac
    convert_mac_addr("bb:bb:bb:bb:bb:bb", dest_mac);// change this to target mac

    // you can verify the packet has sent using tools like Wireshark
    for (int i = 0; i < 10; i++) {
        unsigned char ip_packet[ETH_HDR_LENGTH + IPV4_HDR_LENGTH];
        struct eth_hdr *eth = (struct eth_hdr *)ip_packet;
        struct ipv4_hdr *ip = (struct ipv4_hdr *)(ip_packet + ETH_HDR_LENGTH);

        // fill Ethernet header
        memcpy(eth->dst_addr, dest_mac, ETH_ADDR_LENGTH);
        memcpy(eth->src_addr, src_mac, ETH_ADDR_LENGTH);
        eth->eth_type = htons(ETH_TYPE_IPV4);

        // fill IPv4 header
        ip->version_ihl = 0x45;  // IPv4, no options
        ip->total_length = htons(IPV4_HDR_LENGTH);
        ip->time_to_live = 64;
        ip->next_proto_id = IPV4_PROTO_UDP; // we do not provide udp data
        memcpy(ip->src_addr, &src_ip, IPV4_ADDR_LENGTH);
        memcpy(ip->dst_addr, &dest_ip, IPV4_ADDR_LENGTH);

        // send packet
        if (sendto(ip_fd, ip_packet, sizeof(ip_packet), 0, 
                (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("sendto");
            free(ifr->if_name);
            free(ifr);
            exit(EXIT_FAILURE);
        }
        sleep(1);
    }
    free(ifr->if_name);
    free(ifr);
    return 0;
}
```
This example demonstrates crafting and sending a minimal IPv4 packet over a raw socket, using `sockaddr_ll` to define the necessary link-layer details. You can verify packets sent using tools like Wireshark. For more interesting details, you can look at `test_packets.c`.