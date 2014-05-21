#include "bouncer.h"

/*!
 * Calculate the checksum of an header
 */
u_int16_t calculate_checksum(const u_char *header, int len) {
    ushort word16;
    long sum = 0;
    int i;
    for (i = 0; i < len; i += 2) {
        word16 = (ushort)(((header[i] << 8 ) & 0xFF00) 
        				+ (header[i + 1] & 0xFF));
        sum += (long)word16;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = htons(~sum);
    return (u_int16_t) sum;
}

/*!
 * Convert dot notation of an ipv4 address to integer representation
 */
u_int32_t ipv4_string_to_int(char *addr) {
    const char * start; /* A pointer to the next digit to process. */
    start = addr;

    int i;
    u_char bytes[4];
    for (i = 0; i < 4; i++) {
        char c; /* The digit being processed. */
        bytes[i] = 0; /* The value of this byte. */

        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                bytes[i] *= 10;
                bytes[i] += c - '0';
            } else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return -1;
            }
        }
        if (bytes[i] >= 256) {
            return -1;
        }
    }
    u_int32_t res = bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24;
    return res;
}

/*!
 * Convert integer representation of ipv4 to dot notation string
 */
char * int_to_ipv4_string(u_int32_t ip) {
	unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    char *res = malloc(20);
    sprintf(res, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return res;
}

/*!
 * Validate the IP header, return error if any 
 */
char * validate_ip_header(struct iphdr *ip_hdr, u_int size_ip, struct settings *paras) {
	// validate header length
	if (size_ip < MIN_IPV4_HEADER_LEN || size_ip > MAX_IPV4_HEADER_LEN) {
		return "Invalid IP header length";
	}
	// validate destination address
	//printf("Destination: %s \n", int_to_ipv4_string(ip_hdr->daddr));
	if (paras->bouncer_addr_int != ip_hdr->daddr) {
		return "Invalid destination address";
	}

	// validate checksum
	u_int16_t ip_checksum = ip_hdr->check;
	ip_hdr->check = 0;
	if (calculate_checksum((u_char *) ip_hdr, size_ip) != ip_checksum) {
		return "Invalid IP header checksum";
	}

	// validate version
	if (ip_hdr->version != IPV4_VERSION) {
		return "Invalid IP version";
	}

	// validate evil bit
	if (htons(ip_hdr->frag_off) == IP_RF) {
		return "Evil bit is set in IP header";
	}

	// validate TTL
	if (ip_hdr->ttl <= 0) {
		return "Invalid IP header TTL";
	}

	return NULL;
}

/*!
 * Validate an ICMP header, return error if any
 */
char * validate_icmp_header(struct icmphdr * icmp_hdr) {
	// validate checksum
	u_int16_t icmp_checksum = icmp_hdr->checksum;
	icmp_hdr->checksum = 0;
	printf("ICMP checsum: %d %d\n", icmp_checksum, calculate_checksum((u_char *)icmp_hdr, SIZE_ICMP_PACKET));
	if (icmp_checksum != calculate_checksum((u_char *)icmp_hdr, SIZE_ICMP_PACKET)) {
		return "Invalid ICMP header checksum";
	}
	icmp_hdr->checksum = icmp_checksum;

	// validate code
	if (icmp_hdr->code != 0) {
		return "Unsupported ICMP code";
	}

	return NULL;
}

char * send_packet(struct iphdr *ip_hdr, u_int16_t dest_port) {
	//printf("Sending packet to port: %d\n", dest_port);

	struct sockaddr_in sin; 
	sin.sin_family = AF_INET;
	if (dest_port > 0) {
		sin.sin_port = htons(dest_port);
	}

	char *dest_addr = int_to_ipv4_string(ip_hdr->daddr);
	sin.sin_addr.s_addr = inet_addr(dest_addr);

    if (sendto(sockfd, ip_hdr, ntohs(ip_hdr->tot_len),	0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
    	return "Cannot send the packet";
    }
	
    return NULL;
}

/*!
 * Process ICMP packet
 */
char * process_icmp_packet(struct settings *paras, struct iphdr *ip_hdr,
								struct icmphdr *icmp_hdr, u_int16_t *dest_port) {
	printf("Captured an ICMP packet\n");

	// validate 
	char * error = validate_icmp_header(icmp_hdr);
	if (error != NULL) {
		return error;
	}

	*dest_port = 0;

	// echo request packet, client -> server
	if (icmp_hdr->type == ECHO_REQUEST && ip_hdr->saddr != ipv4_string_to_int(paras->server_addr)) {
		printf("Type: ECHO REQUEST, from %s\n", int_to_ipv4_string(ip_hdr->saddr));
		//printf("Client to server\n");

		// update icmp source address
		icmp_saddr = ip_hdr->saddr;

		ip_hdr->daddr = ipv4_string_to_int(paras->server_addr);
		ip_hdr->saddr = ipv4_string_to_int(paras->bouncer_addr);

		//printf("ICMP source address: %s\n", int_to_ipv4_string(icmp_saddr));
		return NULL;
	} 

	// echo reply packet, server -> client
	if (icmp_hdr->type == ECHO_REPLY && ip_hdr->saddr == ipv4_string_to_int(paras->server_addr)) {
		printf("Type ECHO REPLY, from %s\n", paras->server_addr);
		//printf("Server to client\n");
		ip_hdr->daddr = icmp_saddr;
		ip_hdr->saddr = ipv4_string_to_int(paras->bouncer_addr);
		return NULL;
	} 
	
	return "Invalid ICMP header";
}


unsigned short TCP_Pseduo_Header_Preparation(struct tcphdr *tcp_hdr, struct iphdr *ip_hdr) {
    struct tmp_hdr *tmp_hdr;
    tmp_hdr = (struct tmp_hdr *)malloc(sizeof(struct tmp_hdr));
    u_int temp_len = sizeof(struct tmp_hdr);
    u_int tot_len = ntohs(ip_hdr->tot_len);
    u_int size_ip = ip_hdr->ihl*4;
    u_int tcp_hdr_len= sizeof(struct tcphdr);
    u_int tcp_opt_len = (tcp_hdr->th_off*4) - size_ip;
    u_int tcp_data_len = tot_len - (tcp_hdr->th_off*4) - size_ip;

 //    printf("TH-OFF: %d\n", tcp_hdr->th_off*4);
	// printf("Opt_Len: %d, Data_Len: %d, TCP_Hdr_Len: %d\n", tcp_opt_len, tcp_data_len, tcp_hdr_len);

    tmp_hdr->saddr = ip_hdr->saddr;
    tmp_hdr->daddr = ip_hdr->daddr;
    tmp_hdr->zero = htons(0);
    tmp_hdr->proto = IPPROTO_TCP;
    tmp_hdr->length = htons(tcp_hdr_len + tcp_opt_len + tcp_data_len);

    unsigned char tcpBuf[65536];
    memcpy((unsigned char *)tcpBuf, tmp_hdr, temp_len);
    memcpy((unsigned char *)tcpBuf+temp_len, (unsigned char *)tcp_hdr, tcp_hdr_len);
    memcpy((unsigned char *)tcpBuf+temp_len+tcp_hdr_len, (unsigned char *)tcp_hdr+tcp_hdr_len, tcp_opt_len);
    memcpy((unsigned char *)tcpBuf+temp_len+tcp_hdr_len+tcp_opt_len, (unsigned char *)tcp_hdr+tcp_hdr_len+tcp_opt_len, tcp_data_len); 

    int total_len = temp_len + tcp_hdr_len + tcp_opt_len + tcp_data_len;
    while (tcp_data_len % 4 != 0) {
		tcpBuf[total_len]= 0;
		total_len ++;
		tcp_data_len ++;	
    }

    free(tmp_hdr);
    return calculate_checksum((u_char *)tcpBuf, total_len);
}

/*!
 * Validate the TCP header. Return error if any.
 */
char * validate_tcp_header(struct tcphdr *tcp_hdr, struct iphdr *ip_hdr,
								struct settings *paras) {
    // Check for the minimum lenght of TCP
    if ((tcp_hdr->th_off*4) < 20) {
        return "TCP header length is less than minimum!";
    }

    // Checksum Processing
    unsigned short tcp_received_checksum, tcp_calculated_checksum;
    tcp_received_checksum = (unsigned short) tcp_hdr->th_sum;

    //printf("Original Checksum: %d\n", tcp_received_checksum);
    tcp_hdr->th_sum = htons(0);

    // Verify the received Checksum
    tcp_calculated_checksum = TCP_Pseduo_Header_Preparation(tcp_hdr, ip_hdr);
	//printf("Got one: %d\n", tcp_calculated_checksum);

    if (tcp_received_checksum != tcp_calculated_checksum) {
        return "Invalid TCP checksum";
    }
    tcp_hdr->th_sum = tcp_received_checksum;


    // Deep Analysis of the TCP Segment
 /*   if(strcmp(int_to_ipv4_string(ip_hdr->saddr), paras->server_addr) != 0) {
        if(ntohs(tcp_hdr->th_dport) != paras->bouncer_port) {
            return "Packet arrrived at different port which does not belong to bouncer";
        }
    } */
    return NULL;
}

void calculate_checksum_and_print_details (struct iphdr *ip_hdr, struct tcphdr *tcp_hdr) {
    ip_hdr->check = 0;
    ip_hdr->check = calculate_checksum((u_char *) ip_hdr, (u_int) ip_hdr->ihl*4);

    tcp_hdr->th_sum = htons(0);
    tcp_hdr->th_sum = TCP_Pseduo_Header_Preparation(tcp_hdr, ip_hdr);

    /*printf("Source IP: %s\n",int_to_ipv4_string(ip_hdr->saddr));
    printf("Dst IP: %s\n",int_to_ipv4_string(ip_hdr->daddr));
    printf("Source Port = %u\n",ntohs(tcp_hdr->th_sport));
    printf("Dst Port = %u\n",ntohs(tcp_hdr->th_dport));*/
}

/*!
 * Modify the PORT FTP request according to the bouncer's address and port
 */
struct iphdr * modify_port_ftp_packet(struct tcphdr *tcp_hdr, struct iphdr *ip_hdr, 	
										struct settings *paras, u_int16_t outgoing_data_port) {
	u_int ip_tot_len = ntohs(ip_hdr->tot_len);
    u_int size_ip = ip_hdr->ihl*4;
    u_int tcp_data_len = ip_tot_len - (tcp_hdr->th_off*4) - size_ip;

	unsigned char bytes[6];
	// extract address
    u_int32_t ip = paras->bouncer_addr_int;
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    // extract port
    bytes[4] = (outgoing_data_port >> 8) & 0xFF;
    bytes[5] = outgoing_data_port & 0xFF;

    char *ftp_data = malloc(40);
    // request command
    memcpy(ftp_data, "PORT ", 5);
    u_int new_tcp_data_len = 5;
    // request data
    char request_data[30];
    sprintf(request_data, "%d,%d,%d,%d,%d,%d\r\n", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    memcpy(ftp_data+new_tcp_data_len, request_data, strlen(request_data));
    new_tcp_data_len += strlen(request_data);

    printf("Modified data: %s - %d\n", ftp_data, new_tcp_data_len);

    u_int new_ip_tot_len = ip_tot_len - tcp_data_len + new_tcp_data_len;

    struct iphdr * new_ip_hdr = (struct iphdr *)malloc(new_ip_tot_len);
    memcpy((unsigned char *)new_ip_hdr, (unsigned char *)ip_hdr, ip_tot_len - tcp_data_len);
    memcpy((unsigned char *)new_ip_hdr + ip_tot_len - tcp_data_len, ftp_data, new_tcp_data_len);
    new_ip_hdr->tot_len = htons(new_ip_tot_len);

    free(ftp_data);
    return new_ip_hdr;
    //return ip_hdr;
}

/*!
 * Extract the PORT FTP request's information if any.
 */
struct port_ftp_request * extract_port_ftp_request(struct tcphdr *tcp_hdr, struct iphdr *ip_hdr) {
	u_int ip_tot_len = ntohs(ip_hdr->tot_len);
    u_int size_ip = ip_hdr->ihl*4;
    u_int tcp_hdr_len= sizeof(struct tcphdr);
    u_int tcp_opt_len = (tcp_hdr->th_off*4) - size_ip;
    u_int tcp_data_len = ip_tot_len - (tcp_hdr->th_off*4) - size_ip;

    // check data length
    if (tcp_data_len < 5) {
    	return NULL;
    }

    char * tcp_data = (char *) tcp_hdr + tcp_hdr_len + tcp_opt_len;
	/*int i;
	char *c = tcp_data;
	printf("Data: *");
	for (i = 0; i < tcp_data_len; i++) {
		printf("%c", *c);
		c++;
	}
	printf("*\n");*/
    char request_cmd[5];
    memcpy(request_cmd, tcp_data, 4);
	request_cmd[4] = '\0';
    printf("Request command: %s\n", request_cmd);
    if (strcmp(request_cmd, "PORT") == 0) {
		unsigned char tmp[6];
		memset(tmp, 0, sizeof(tmp));
		int i = 0;
		char * start = tcp_data + 5;
		while (1) {
			char ch = *start;
			if (ch == '\r') {
				break;
			}
			if (ch == ',') {
				i++;
			} else if (ch >= '0' && ch <= '9'){
				tmp[i] = tmp[i]*10 + (ch - '0');
			} else {
				return NULL;
			}
			start++;
		}
		if (i < 5) {
			return NULL;
		}	

		struct port_ftp_request * port_ftp = (struct port_ftp_request *) malloc(sizeof(struct port_ftp_request));
		port_ftp->source_addr = malloc(20);
		sprintf(port_ftp->source_addr, "%d.%d.%d.%d", tmp[0], tmp[1], tmp[2], tmp[3]);
		port_ftp->source_data_port = tmp[4] << 8 | tmp[5];

		printf("Port packet: %s - %d\n", port_ftp->source_addr, port_ftp->source_data_port);
		return port_ftp;
    }
	return NULL;
}

/*!
 * Get available port on the bouncer
 */
int get_available_port() {
    DummyPort++;
    return DummyPort;
    /*int tmp_socket;

    tmp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(tmp_socket == -1) {
        return -1;
    }

    int port = -1;

    while (DummyPort < 65535) {
        DummyPort++;
        struct sockaddr_in sin;
        
        sin.sin_port = htons(DummyPort);
        sin.sin_addr.s_addr = 0;
        sin.sin_addr.s_addr = INADDR_ANY;
        sin.sin_family = AF_INET;

        if(bind(tmp_socket, (struct sockaddr *)&sin,sizeof(struct sockaddr_in) ) == 0) {
            printf("Available port: %d\n", DummyPort);
            port = DummyPort;
            break;
        }
    }

    close(tmp_socket);
    return port;*/
}

/*!
 * Process TCP packet
 */
char *process_tcp_header(struct settings *paras, struct tcphdr *tcp_hdr, 
					u_int16_t * dest_port, struct iphdr **ip_hdr_pointer) {

    struct iphdr *ip_hdr = *ip_hdr_pointer;

	// validate the tcp header
    struct Node *result = NULL;
    struct port_ftp_request *port_ftp = NULL;
    char *error = validate_tcp_header(tcp_hdr, ip_hdr, paras);
    if (error != NULL) {
    	return error;
    }
 
    // From Client
    if(ntohs(tcp_hdr->th_dport) == paras->bouncer_port) {

    	// Check whether the Segment is received on a different port
    	printf(">>>>>>> Packet from Client\n");

    	result = searchClientTCPList(ntohs(tcp_hdr->th_sport), ip_hdr->saddr);

        // Control Message Part for all TCP segment
 		if (result == NULL && (tcp_hdr->th_flags & 0x02) == TH_SYN) {
            int server_side_port = get_available_port();
            if (server_side_port == -1) {
                return "Cannot redirect packet";
            }
        	addTCPtoList(ntohs(tcp_hdr->th_sport), server_side_port, ip_hdr->saddr, 0);
        	displayList();

        	tcp_hdr->th_sport=htons(server_side_port);
            tcp_hdr->th_dport = htons(paras->server_port);    
            *dest_port = paras->server_port;

    	} else if (result != NULL && result->is_active == 1) {
			// Enable only if FTP is enabled
	        if (paras->server_port == 21) {
        	    port_ftp = extract_port_ftp_request(tcp_hdr, ip_hdr);
				// Port Command Packet
	            if (port_ftp != NULL) {
    		        int server_side_port = get_available_port();
                    if (server_side_port == -1) {
                        return "Cannot redirect packet";
                    }
        			
        	        ip_hdr = modify_port_ftp_packet(tcp_hdr, ip_hdr, paras, server_side_port);
               		tcp_hdr = (struct tcphdr *) ((char *) ip_hdr + ip_hdr->ihl*4);
                	*ip_hdr_pointer = ip_hdr;

                    addTCPtoList(port_ftp->source_data_port, server_side_port, ip_hdr->saddr, 1);
                    displayList();
        	    }
        	}

        	tcp_hdr->th_sport = htons(result->dummy_port);
            if (result->is_data_connection == 0) {
                tcp_hdr->th_dport = htons(paras->server_port);    
                *dest_port = paras->server_port;
            } else {
                tcp_hdr->th_dport = htons(20);    
                *dest_port = 20;
            }

    	} else {
            return "Received packet from an unkown connection";
        }

    	ip_hdr->saddr = paras->bouncer_addr_int;
    	ip_hdr->daddr = paras->server_addr_int;
    }
    
    // Sent from Server
    else if(ip_hdr->saddr == paras->server_addr_int) {
        printf("<<<<<<<<< Packet from Server\n");
       
    	result = searchServerTCPList(ntohs(tcp_hdr->th_dport));

    	if (result != NULL) {
            if ((tcp_hdr->th_flags & 0x02) == TH_SYN) {
                result->is_active = 1;
            }
            ip_hdr->saddr = paras->bouncer_addr_int;
            ip_hdr->daddr = result->address;
          
            tcp_hdr->th_sport = htons(paras->bouncer_port);    
            tcp_hdr->th_dport = htons(result->src_port);
            *dest_port = result->src_port;
        } else {
        	return "No such Dummy port found on Bouncer";
    	}
    } else {
        return "Received packet from an unkown connection";
    }

    calculate_checksum_and_print_details (ip_hdr, tcp_hdr);

    if (result != NULL) {
        if ((tcp_hdr->th_flags & 0x01) == TH_FIN) {
            printf("Received FIN Message... Count [%d]\n", (3 - result->fin_count));
            result->fin_count--;
        } else if (((tcp_hdr->th_flags & 0x10) == TH_ACK) && (result->fin_count == 0)) {
            printf("Received Second FIN-ACK... Removing the connection from the list\n");
            delTCPfromList(result);
            displayList();
        }
    }

    return NULL;
}

/*!
 * Process a packet captured with libpcap
 */
void process_pkt(u_char *extras, const struct pcap_pkthdr *header,
	    const u_char *packet){
    printf("-------------------------------------------------------\n");
    
	//printf("in Packet process\n");
	/* Define pointers for packet's attributes */
	struct settings *paras = (struct settings *) extras;
	// error string
	char *error = NULL;
	//struct ether_header *e_hdr = (struct ether_header*) packet;
	struct iphdr *ip_hdr = (struct iphdr*) (packet + SIZE_ETHERNET);

	/* Check IP header*/
	// validate header length
	u_int size_ip = ip_hdr->ihl*4;
	error = validate_ip_header(ip_hdr, size_ip, paras);
	if (error != NULL) {
		fprintf(stderr, "Error: %s\n", error);
		return;
	}

	/* Check type of packet and process*/
	
	u_int16_t dest_port = 0;

	// icmp packet
	if (ip_hdr->protocol == ICMP_PROTOCOL) {
		struct icmphdr *icmp_hdr;

		// find the icmp header and payload
		icmp_hdr = (struct icmphdr*)(packet + SIZE_ETHERNET + size_ip);

		error = process_icmp_packet(paras, ip_hdr, icmp_hdr, &dest_port);

	// tcp packet
	} else if (ip_hdr->protocol == TCP_PROTOCOL) {

		printf("Recieved TCP Packet\n");
		struct tcphdr *tcp_hdr;
		tcp_hdr =(struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);

        /*printf("- IP header received: \n");
        printf("Source: %s - %u \n",int_to_ipv4_string(ip_hdr->saddr), ntohs(tcp_hdr->th_sport));
        printf("Dst: %s - %u\n",int_to_ipv4_string(ip_hdr->daddr), ntohs(tcp_hdr->th_dport));*/

		//process_tcp_packet(u_char *address_info, u_char *packet, struct iphdr *ip_hdr)
		struct iphdr ** ip_hdr_pointer = &ip_hdr;
		error = process_tcp_header(paras, tcp_hdr, &dest_port, ip_hdr_pointer);
		ip_hdr = *ip_hdr_pointer;

        /*printf("- IP header after processing: \n");
        printf("Source: %s - %u \n",int_to_ipv4_string(ip_hdr->saddr), ntohs(tcp_hdr->th_sport));
        printf("Dst: %s - %u\n",int_to_ipv4_string(ip_hdr->daddr), ntohs(tcp_hdr->th_dport));*/
	}
	else {
		printf("Invalid Protocol Format\n");
	}

	//printf("Destination address: %s %d\n", dest_addr, dest_port);

	// if there is no error, Send processed packet
	if (error == NULL) {
		error = send_packet(ip_hdr, dest_port);
	}

	if (error != NULL) {
		printf("Error: %s\n", error);		
	}
}


