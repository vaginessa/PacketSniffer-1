#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define LINE_LEN 16
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

typedef u_int tcp_seq;
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    
        u_char  ether_shost[ETHER_ADDR_LEN];    
        u_short ether_type;                     
};

struct sniff_ip {
        u_char  ip_vhl;                 
        u_char  ip_tos;                 
        u_short ip_len;                 
        u_short ip_id;                  
        u_short ip_off;                 
        u_char  ip_ttl;                 
        u_char  ip_p;                   
        u_short ip_sum;                 
        struct  in_addr ip_src,ip_dst;  
};

struct sniff_tcp {
        u_short th_sport;               
        u_short th_dport;               
        tcp_seq th_seq;                 
        tcp_seq th_ack;                 
        u_char  th_offx2;               
		
};

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
}


void print_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			
	int line_len;
	int offset = 0;					
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
}

int myStrStr(const u_char *str1, const u_char *str2, int size_payload) {
    const u_char *p, *q;
    int i;

    for (i = 0; i < size_payload; i++) {
        p = str1 + i;
        q = str2;
        while (*q && *p == *q) {
            ++p;
            ++q;
        }
        if (*q == 0)
            return i;
    }
    return -1;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	const struct sniff_ethernet *ethernet;  
	const struct sniff_ip *ip;              
	const struct sniff_tcp *tcp;            
	const u_char *payload;                    
	struct tm * timeinfo;
	
	int size_ip;
	int size_tcp;
	int size_payload;
	char timestamp[40];
	char millisecond[20];
	timeinfo = localtime (&(header->ts.tv_sec));
	strftime(timestamp,40,"%F %T",timeinfo);
	sprintf(millisecond, "%li", header->ts.tv_usec);
	strcat(timestamp,millisecond);

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("*Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		//printf("*Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	//checking for the pattern
	if(args && (size_payload <= 0 || myStrStr(payload, (const u_char *)args, size_payload)==-1)){
		//printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@skipping this packet@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		return;
	}
	
	printf("\n*********************************************************************************************\n");
	
	// packet timestamp
	printf("%s", timestamp);

	/* print source and destination IP addresses */
	printf("	%x:%x:%x:%x:%x:%x", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2],
		ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
	printf("->%x:%x:%x:%x:%x:%x", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2],
		ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
	printf("	type %04x", ethernet->ether_type);

	// packet size
	printf("	len  %d\n", (bpf_u_int32)header->len);

	/* print source and destination IP addresses */
	
	printf("%s", inet_ntoa(ip->ip_src));
	printf(": %d", ntohs(tcp->th_sport));
	
	printf(" -> %s", inet_ntoa(ip->ip_dst));
	printf(": %d", ntohs(tcp->th_dport));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("	TCP");
			break;
		case IPPROTO_UDP:
			printf("	UDP");
			break;
		case IPPROTO_ICMP:
			printf("	ICMP");
			break;
		case IPPROTO_IP:
			printf("	IP");
			break;
		default:
			printf("	unknown");
			break;
	}
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {

		printf("\nRaw content of the application-layer packet payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
	else{
		printf("\n	************No payload available***********\n");
	}
}

void liveSniffing(char* interface, u_char* filter){

	char *dev = NULL;					
	char errbuf[PCAP_ERRBUF_SIZE];		
	pcap_t *handle;						
	
	/* check for capture device name on command-line */
	if (interface == NULL) {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	else {
		dev = interface;
	}

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, filter);

	/* cleanup */
	pcap_close(handle);

}

void fileSniffing(char* file, u_char* filter){

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

    /* Open a capture file */
    if ((handle = pcap_open_offline(file, errbuf) ) == NULL)
    {
        fprintf(stderr,"\nError opening dump file\n");
        return;
    }

    // read and dispatch packets until EOF is reached
    pcap_loop(handle, -1, got_packet, filter);

}

int main(int argc, char **argv){
	int c;
	char* interface=NULL;
	char* file=NULL;
	u_char* filter=NULL;

	// parsing command line argument to the user level variables
	while ((c = getopt(argc, argv, "i:r:s:")) != -1){ 
	  	switch(c){
	  	// interface	
		case 'i':
		     interface=optarg;
		     break;
		// file
		case 'r':
		     file=optarg;
		     break;
		// filter
		case 's':
		     filter=(u_char*)optarg;
		     break;
		default:
		      break;
		}
	}
	
	if (argc > 7) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	
	if(file == NULL){
		liveSniffing(interface, filter);
	}
	else{
		fileSniffing(file, filter);
	}
return 0;
}
