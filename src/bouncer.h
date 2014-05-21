#ifndef BOUNCER_H_
#define BOUNCER_H_

/* Global definitions for the port bouncer
 * Packet headers and so on
 */

#define _BSD_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
 #include <time.h>

/* PCAP declarations */
#include <pcap.h>

/* Standard networking declaration */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * The following system include files should provide you with the 
 * necessary declarations for Ethernet, IP, and TCP headers
 */

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>


/* Interrupt Signal Handling */
#include<signal.h>

/* Add any other declarations you may need here... */


/* My headers */

// definitions
#define SIZE_ETHERNET 14
#define SIZE_ICMP_HEADER 8
#define SIZE_ICMP_PACKET 64
#define ECHO_REQUEST 8
#define ECHO_REPLY 0

#define MIN_IPV4_HEADER_LEN 20
#define MAX_IPV4_HEADER_LEN 60
#define IPV4_VERSION 4
#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6

/* Necessary structs */
struct settings {
	char * bouncer_dev;
	char * bouncer_addr;
	u_int32_t bouncer_addr_int;
	u_int16_t bouncer_port;
	char * server_addr;
	u_int32_t server_addr_int;
	u_int16_t server_port;
};

// variables
u_int32_t icmp_saddr;


struct tmp_hdr
{
  u_int32_t saddr;
  u_int32_t daddr;
  u_int8_t zero;
  u_int8_t proto;
  u_int16_t length;
};

struct port_ftp_request {
	char * source_addr;
	u_int16_t source_data_port;
};

struct Node{
  /*For TCP session identification*/
  unsigned short src_port;
  unsigned short dummy_port;
  u_int32_t address;
  int fin_count;
  int is_data_connection;
  int is_active;

  struct Node *Next;
};

int sockfd;  /* open raw socket */

int DummyPort;


/* Function Definitions */

u_int32_t ipv4_string_to_int(char *addr);

u_int16_t calculate_checksum(const u_char *header, int len);

char * process_icmp_packet(struct settings *paras, struct iphdr *ip_hdr,
                struct icmphdr *icmp_hdr, u_int16_t *dest_port);

//char *process_tcp_header(struct settings *paras, struct tcphdr *tcp_hdr, 
//          u_int16_t * dest_port, struct iphdr *ip_hdr);

void process_pkt(u_char *args, const struct pcap_pkthdr *header,
	const u_char *packet);

struct Node *searchServerTCPList(unsigned short bport);
void addTCPtoList(unsigned short int sport,unsigned short int bport,u_int32_t address,int is_data_connection);
struct Node *searchClientTCPList(unsigned short bport,u_int32_t client_address);
void displayList();
void delTCPfromList (struct Node *del);
/*struct Node *searchClientFTPList(char *client_address, unsigned short clientFTPPort);
struct Node *searchForClientFTPPort (unsigned short dummy_port);*/
void dealloc_all_TCP_Connections();
void Segmentation_Fault_Handler (int signum);
void Interrupt_Handler (int signum);


 
#endif



