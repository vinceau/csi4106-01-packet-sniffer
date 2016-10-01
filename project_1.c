/* Some ethernet structure declarations were taken from examples owned by the Tcpdump
 * group and can be found at: http://www.tcpdump.org/pcap.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>

const char POST_DIR[] = "post/";   /* place to store post files */

/* max length of the filenames created by the POST responses*/
#define MAX_FILENAME_SIZE 64

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* dont fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

/*
 * This will not close the file!
 */
FILE*
prep_post(int num)
{
	char filename[MAX_FILENAME_SIZE + strlen(POST_DIR)];
	mkdir(POST_DIR, 0700);
	sprintf(filename, "%s/%d.txt", POST_DIR, num);
	FILE *f = fopen(filename, "w");
	return f;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len, int packet_num)
{
	int end_header = 0;
	int is_post = 0;
	FILE* f;
	const u_char *ch;

	//if (len <= 0)
		//return;

	if (strncmp((char*)payload, "HTTP", 4) == 0) {
		//it's a response
		printf("Response\r\n");
	} else {
		// it's a request
		printf("Request\r\n");
		if (strncmp((char*)payload, "POST", 4) == 0) {
			is_post = 1;
			f = prep_post(packet_num);
		}
	}

	ch = payload;
	for (int i = 0; i < len; i++) {
		if (end_header && is_post) {
			if (isprint(*ch))
				fprintf(f, "%c", *ch);
		} else {
			if (isprint(*ch) || isspace(*ch))
				printf("%c", *ch);
			else
				printf(".");
			if (strncmp((char*)ch, "\r\n\r\n", 4) == 0) {
				end_header = 1;
				if (is_post) {
					//skip to the body of the request
					printf("\n\r\n");
					ch += 3;
					i += 3;
				}
				else
					break;
			}
		}
		ch++;
	}

	// ch should be right before the post body with the parameters
	// so we should be able to just write this to a file
	if (is_post) {
		fclose(f);
	}

	printf("\n");

	return;
}

/*
 * What should we do with the packet?
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if (size_payload > 0) {
		printf("%d ", count);
		
		/* print source IP */
		printf("%s:", inet_ntoa(ip->ip_src));
		// source port
		printf("%d ", ntohs(tcp->th_sport));

		//destination ip
		printf("%s:", inet_ntoa(ip->ip_dst));
		//destination port
		printf("%d HTTP ", ntohs(tcp->th_dport));
		//printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload, count);
		count++;
	}

	//printf("caplen: %u, len: %u\n", header->caplen, header->len);
	//printf("packet contents:\n%s\n", packet);
	
	//printf("protocol: %d\n", ip->ip_p); //6 ==TCP
	return;
}

int
main(int argc, char **argv)
{
	char *dev = NULL;                    /* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];       /* error buffer */
	pcap_t *handle;                      /* packet capture handle */

	char filter_exp[] = "tcp and dst port 80";   /* filter expression [3] */
	struct bpf_program fp;               /* compiled filter program */
	bpf_u_int32 mask;                    /* subnet mask */
	bpf_u_int32 net;                     /* ip */
	int num_packets = -1;                /* number of packets to capture */

	/* get the default device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev,
			errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Sniffing on device: %s\n", dev);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}

