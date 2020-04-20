//
// Created by maazito on 4/19/20.
//

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#ifdef __APPLE__
#include <netinet/in_systm.h>
#include <netinet/ip.h>
struct icmphdr {
    uint8_t		type;
    uint8_t		code;
    uint16_t	checksum;
    union {
        struct {
            uint16_t	id;
            uint16_t	sequence;
        } echo;
        uint32_t	gateway;
        struct {
            uint16_t	__unused;
            uint16_t	mtu;
        } frag;
    } un;
};
#endif
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif
#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef SOL_RAW
#define SOL_RAW IPPROTO_RAW
#endif
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>




//Define the packet constants
#define PKT_SIZE 64
#define PORT_NUM 0
#define SLEEP_RATE 1000000
#define TIMEOUT 1
#define IDENTIFIER 0x2342

int ping_loop = 1;

/**
 * This struct defines the structure of the packet
 */
struct ping_pkt{
    struct icmphdr hdr;
    char msg[PKT_SIZE - sizeof(struct icmphdr)];
};

struct ping_pkt6{
    struct icmp6_hdr hdr;
    char msg[PKT_SIZE - sizeof(struct icmp6_hdr)];
};

/**
 * Function used to end infinite loop
 * @param tmp: interrupt
 */
void intHandler(int tmp){
    ping_loop = 0;
}

/**
 * Calculates checksum
 * @param b: reference to ping packet
 * @param len: size of packet
 * @return: checksum to be placed in header of IPv4
 */
unsigned short checksum(void *b, int len){
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short res;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;

    if (len == 1) sum += *(unsigned char*) buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    res = ~sum;
    return res;
}

char *dns6_lookup(char *host_addr, struct sockaddr_in6 *con_addr6){
    printf("\nResolving DNS...\n");
    struct hostent *host_entity; //represents entry in hosts database
    char *ip = (char*)malloc(NI_MAXHOST*sizeof(char));
    if((host_entity = gethostbyname2(host_addr, AF_INET6)) == NULL){
        return NULL;
    }
    (*con_addr6).sin6_addr = *(struct in6_addr *)host_entity->h_addr;
    inet_ntop(AF_INET6, (*con_addr6).sin6_addr.s6_addr, *ip, sizeof(ip));

    (*con_addr6).sin6_family = host_entity->h_addrtype; //whether IPv4 or IPv6
    (*con_addr6).sin6_port = htons(PORT_NUM); //converts from host byte order to network byte order
    (*con_addr6).sin6_addr.s6_addr[0] = *(long *) host_entity->h_addr; //address in network byte order
}

/**
 * Performs a DNS lookup
 * @param host_addr: hostname from arguments
 * @param con_addr: socket address struct
 * @return: IP address
 */
char *dns_lookup(char *host_addr, struct sockaddr_in *con_addr){
    printf("\nResolving DNS...\n");
    struct hostent *host_entity; //represents entry in hosts database
    char *ip = (char*)malloc(NI_MAXHOST*sizeof(char));

    //use gethostbyname2 for IPv6 //ADD HERE
    //gethostbyname function returns information about the host

        if ((host_entity = gethostbyname(host_addr)) == NULL) {
            return NULL; //no IP found
        }

        //function returns internet dot address by converting host name: h_addr
        strcpy(ip, inet_ntoa(*(struct in_addr *) host_entity->h_addr));

        (*con_addr).sin_family = host_entity->h_addrtype; //whether IPv4 or IPv6
        (*con_addr).sin_port = htons(PORT_NUM); //converts from host byte order to network byte order
        (*con_addr).sin_addr.s_addr = *(long *) host_entity->h_addr; //address in network byte order

    return ip;
}

bool isValidIpV6Address(char *ipAddress)
{
    struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, ipAddress, &(sa.sin6_addr.s6_addr));
    return result != 0;
}

void send_ping6(int ping_sock, struct sockaddr_in6 *ping_addr, char* ping_ip, char *rev_host){
    int ttl_val = 64, msg_count = 0, addr_len, flag = 1, i, msgs_received = 0;
    struct ping_pkt6 packet;
    struct sockaddr_in6 return_addr;
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec = 0, total_msec = 0;
    struct timeval tv_out;
    tv_out.tv_sec = TIMEOUT;
    tv_out.tv_usec = 0;
    clock_gettime(CLOCK_MONOTONIC, &tfs);

    //Set the TTL value
    if (setsockopt(ping_sock, SOL_IPV6, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0){
        printf("\nSetting socket options to TTL failed!\n");
        return;
    }
    else{
        printf("\nSocket set to TTL..\n");
    }

    //setting the timeout for receive setting
    setsockopt(ping_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out);


    while(ping_loop){
        flag = 1; //whether packet was sent or not
        bzero(&packet, sizeof(packet)); //filling the packet
        packet.hdr.icmp6_type = ICMP6_ECHO_REQUEST;
        packet.hdr.icmp6_code = 0;

        packet.hdr.icmp6_dataun.icmp6_un_data16[0] = htons(IDENTIFIER);;
        packet.hdr.icmp6_dataun.icmp6_un_data16[1] = htons(msg_count++);

        for(i = 0; i < sizeof(packet.msg) - 1; i++) packet.msg[i] = i + '0';

        packet.msg[i] = 0;
        int cksum_ofs = offsetof(struct icmp6_hdr, icmp6_cksum);
        const socklen_t cksum_ofs_sz = sizeof(cksum_ofs);
        const int sso_ret = setsockopt(ping_sock, SOL_RAW, IPV6_CHECKSUM,
                                       &cksum_ofs, cksum_ofs_sz);
        usleep(SLEEP_RATE);

        //send the packet
        clock_gettime(CLOCK_MONOTONIC, &time_start);
        if (sendto(ping_sock, &packet, sizeof(packet), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0){
            printf("\nPacket Sending Failed!\n");
            flag=0;
        }

        //receive the packet
        addr_len = sizeof(return_addr);
        if(recvfrom(ping_sock, &packet, sizeof(packet), 0, (struct sockaddr*)&return_addr, &addr_len) <= 0 && msg_count > 1){
            printf("\nPacket receive failed\n");
        }
        else{
            clock_gettime(CLOCK_MONOTONIC, &time_end);
            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0;
            rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

            if(flag){
                if(!(packet.hdr.icmp6_type == 69 && packet.hdr.icmp6_code == 0)){
                    printf("Error..Packet received with ICMP type %d code %d\n", packet.hdr.icmp6_type, packet.hdr.icmp6_code);
                }
                else{
                    printf("%d bytes (h: %s)(%s) msg_seq=%d ttl=%d rtt = %Lf ms.\n", PKT_SIZE, rev_host, ping_ip, msg_count, ttl_val, rtt_msec);
                    msgs_received++;
                }
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0;

    total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;

    printf("\n===%s ping statistics===\n", ping_ip);
    printf("\n%d packets sent, %d packets received, %f percent packet loss. Total time: %Lf ms.\n\n", msg_count, msgs_received, ((msg_count - msgs_received)/msg_count) * 100.0, total_msec);

}

/**
 * makes ping request
 * @param ping_sock: socket
 * @param ping_addr: address to be pinged
 * @param ping_dom: reverse hostname
 * @param ping_ip: IP address
 * @param rev_host: hostname argument
 */
void send_ping(int ping_sock, struct sockaddr_in *ping_addr, char* ping_ip, char *rev_host){
    int ttl_val = 64, msg_count = 0, addr_len, flag = 1, i, msgs_received = 0;
    struct ping_pkt packet;
    struct sockaddr_in return_addr;
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec = 0, total_msec = 0;
    struct timeval tv_out;
    tv_out.tv_sec = TIMEOUT;
    tv_out.tv_usec = 0;
    clock_gettime(CLOCK_MONOTONIC, &tfs);

    //Set the TTL value
    if (setsockopt(ping_sock, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0){
        printf("\nSetting socket options to TTL failed!\n");
        return;
    }
    else{
        printf("\nSocket set to TTL..\n");
    }

    //setting the timeout for receive setting
    setsockopt(ping_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out);
    while(ping_loop){
        flag = 1; //whether packet was sent or not
        bzero(&packet, sizeof(packet)); //filling the packet
        packet.hdr.type = ICMP_ECHO;
        packet.hdr.un.echo.id = getpid();

        for(i = 0; i < sizeof(packet.msg) - 1; i++) packet.msg[i] = i + '0';

        packet.msg[i] = 0;
        packet.hdr.un.echo.sequence = msg_count++;
        packet.hdr.checksum = checksum(&packet, sizeof(packet));

        usleep(SLEEP_RATE);

        //send the packet
        clock_gettime(CLOCK_MONOTONIC, &time_start);
        if (sendto(ping_sock, &packet, sizeof(packet), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0){
            printf("\nPacket Sending Failed!\n");
            flag=0;
        }

        //receive the packet
        addr_len = sizeof(return_addr);
        if(recvfrom(ping_sock, &packet, sizeof(packet), 0, (struct sockaddr*)&return_addr, &addr_len) <= 0 && msg_count > 1){
            printf("\nPacket receive failed\n");
        }
        else{
            clock_gettime(CLOCK_MONOTONIC, &time_end);
            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0;
            rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

            if(flag){
                if(!(packet.hdr.type == 69 && packet.hdr.code == 0)){
                    printf("Error..Packet received with ICMP type %d code %d\n", packet.hdr.type, packet.hdr.code);
                }
                else{
                    printf("%d bytes (h: %s)(%s) msg_seq=%d ttl=%d rtt = %Lf ms.\n", PKT_SIZE, rev_host, ping_ip, msg_count, ttl_val, rtt_msec);
                    msgs_received++;
                }
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0;

    total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;

    printf("\n===%s ping statistics===\n", ping_ip);
    printf("\n%d packets sent, %d packets received, %f percent packet loss. Total time: %Lf ms.\n\n", msg_count, msgs_received, ((msg_count - msgs_received)/msg_count) * 100.0, total_msec);

}

int main(int argc, char *argv[]){
    int sockfd;
    char *ip_addr, *rev_hostname;
    struct sockaddr_in con_addr;
    struct sockaddr_in6 con_addr6;
    int addrlen = sizeof(con_addr);
    int addrlen6 = sizeof(con_addr6);
    char net_buf[NI_MAXHOST];

    if(argc != 2){
        printf("\nFormat %s <address>\n", argv[0]);
        return 0;
    }
    bool isIPv6 = isValidIpV6Address(argv[1]);
    if(isIPv6){
        ip_addr = dns6_lookup(argv[1], &con_addr6);
        if (ip_addr == NULL) {
            printf("\nDNS lookup failed! Could not resolve hostname!\n");
            return 0;
        }
        //rev_hostname = reverse_dns6_lookup(ip_addr);
        printf("\nTrying to connect to '%s' IP: %s\n", argv[1], ip_addr);
        //printf("\nReverse Lookup domain: %s\n", rev_hostname);
        sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sockfd < 0) {
            printf("\nSocket file descriptor not received!!\n");
            return 0;
        } else printf("\nSocket file descriptor %d received\n", sockfd);

        signal(SIGINT, intHandler);
        send_ping6(sockfd, &con_addr6, ip_addr, argv[1]);
        return 0;
    }
    else {
        ip_addr = dns_lookup(argv[1], &con_addr);
        if (ip_addr == NULL) {
            printf("\nDNS lookup failed! Could not resolve hostname!\n");
            return 0;
        }

        //rev_hostname = reverse_dns_lookup(ip_addr);
        printf("\nTrying to connect to '%s' IP: %s\n", argv[1], ip_addr);
        //printf("\nReverse Lookup domain: %s\n", rev_hostname);

        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0) {
            printf("\nSocket file descriptor not received!!\n");
            return 0;
        } else printf("\nSocket file descriptor %d received\n", sockfd);

        signal(SIGINT, intHandler);

        send_ping(sockfd, &con_addr, ip_addr, argv[1]);
        return 0;
    }
}
