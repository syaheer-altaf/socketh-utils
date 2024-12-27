/*
 * Showcasing how to use the utility functions effectively and safely
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
    if (argc != 2) {
        printf("Usage: %s <INTERFACE>\n", argv[0]);
        printf("example: %s wlp4s0\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    info("Initiating test packets...");
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
        struct ipv4_hdr *ip = malloc(IPV4_HDR_LENGTH);
        struct udp_hdr *udp = malloc(UDP_HDR_LENGTH);
        if (get_ipv4_hdr(buffer, sizeof(buffer), ip) == 0)
            print_ipv4_hdr(ip);
        if (get_udp_hdr(buffer, sizeof(buffer), udp) == 0)
            print_udp_hdr(udp);
        free(ip);
        free(udp);
    }
    info("\nGracefully exiting the program...");
    exit_protocol(&ip_fd, ifr);
    return 0;
}