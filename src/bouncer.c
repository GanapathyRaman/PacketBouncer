/* Port Bouncer
* To be called as nbouncer local_ip local_port remote_ip remote_port
*/

#include "bouncer.h"

struct settings* parse_parameters(int argc, char *argv[], char *error) {
	printf("Number of arguments: %d\n", argc);
	if (argc != 6) {
		error = "The number of arguments is invalid";
		return NULL;
	}

	struct settings *paras = (struct settings*) malloc(sizeof(struct settings));
	paras->bouncer_dev = argv[1];

	paras->bouncer_addr = argv[2];
	paras->bouncer_addr_int = ipv4_string_to_int(argv[2]);

	paras->bouncer_port = atoi(argv[3]);

	paras->server_addr = argv[4];
	paras->server_addr_int = ipv4_string_to_int(argv[4]);

	paras->server_port = atoi(argv[5]);

	printf("Parameters: %s %d %s %d\n", paras->bouncer_addr, paras->bouncer_port, paras->server_addr, paras->server_port);
	return paras;
}

int main(int argc, char *argv[])
{
	signal(SIGINT, Interrupt_Handler);
	signal(SIGSEGV, Segmentation_Fault_Handler);

	char *error = NULL;
	struct settings *paras = parse_parameters(argc, argv, error);
	if (paras == NULL) {
		if (error != NULL) {
			fprintf(stderr, "Error: %s\n", error);	
		}
		return (1);
	}

	/* Include here your code to initialize the PCAP capturing process */

	/* Initialize raw socket */

	pcap_t *handle;		/* Session handle */
	char *dev = paras->bouncer_dev;		/* Device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "icmp || tcp";	/* The filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	// only capture incoming packets
	pcap_setdirection(handle, PCAP_D_IN);

	/* open raw socket */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);	
	if (sockfd < 0) {
		printf("Cannot open socket\n");
		return (2);
	}

	int one = 1;
    const int *val = &one;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		printf("Cannot set HDRINCL\n");
		return (2);
    }


    // init dummy port
    srand(time(NULL));
    DummyPort =  (rand()%40000)+10000;

	/* Grab a packet */
	pcap_loop(handle, -1, process_pkt, (u_char *)paras);
	
	/* And close the session */
	pcap_close(handle);

	free(paras);

	close(sockfd);
	//shutdown(sockfd, SHUT_RDWR);

	return(0);
}//End of the bouncer
