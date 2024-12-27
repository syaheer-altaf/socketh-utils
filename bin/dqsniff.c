/*
 * After successfully running ./arpspoof program,
 * you can run this program to sniff the dns query packets
 * from the victim's local IP.
 */
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
    if (argc != 3) {
        printf("Usage: %s <INTERFACE> <TARGET_IP>\n", argv[0]);
        printf("example: %s wlp4s0 192.168.1.4\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    info("Initiating DNS Query packet sniffer...");
    uint32_t target_ip;
    if(convert_ipv4_addr(argv[2], &target_ip) < 0) {
        perror("convert_ipv4_addr()");
        exit(EXIT_FAILURE);
    }
    
    int ip_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_TYPE_IPV4));
    if (ip_fd < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }
    struct if_nameindex *ifr = malloc(sizeof(struct if_nameindex *));
    if (!ifr) {
        perror("Memory allocation for if_nameindex failed");
        exit_protocol(&ip_fd, NULL);
        exit(EXIT_FAILURE);
    }
    ifr->if_name = malloc(IF_NAMESIZE);
    if (!ifr->if_name) {
        perror("Memory allocation for if_name failed");
        exit_protocol(&ip_fd, ifr);
        exit(EXIT_FAILURE);
    }
    strncpy(ifr->if_name, argv[1], IF_NAMESIZE);
    ifr->if_index = if_nametoindex(ifr->if_name);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_TYPE_IPV4);
    sll.sll_ifindex = ifr->if_index;

    if (bind(ip_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind()");
        exit_protocol(&ip_fd, ifr);
        exit(EXIT_FAILURE);
    }
    unsigned char buffer[BUFFER_SIZE];

    // register the SIGINT handler
    signal(SIGINT, sigint_handler);
    info("Press CTRL+C to quit.");
    while (keep_running) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t length = recvfrom(ip_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (length < 0) {
            perror("recvfrom()");
            exit_protocol(&ip_fd, ifr);
            exit(EXIT_FAILURE);
        }
        uint32_t src_ip;
        memcpy(&src_ip, ((struct ipv4_hdr *)(buffer + ETH_HDR_LENGTH))->src_addr, sizeof(uint32_t));
        if (src_ip == target_ip) {
            struct dns_hdr *dh = malloc(DNS_HDR_LENGTH);
            struct dns_query *dq = malloc(sizeof(struct dns_query));
            if (get_dns_hdr_query(buffer, sizeof(buffer), dh, dq) < 0) {
                free(dh);
                free(dq);
                continue;
            }
            if (ntohs(dh->question_count) != 1) {
                free(dh);
                free(dq);
                continue;
            }
            printf("\n***********************************\n");
            print_dns_hdr(dh);
            print_dns_query(dq);
            printf("\n***********************************\n");
            free(dh);
            free(dq);
        }
    }
    info("\nGracefully exiting the program...");
    exit_protocol(&ip_fd, ifr);
    return 0;
}