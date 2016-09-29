#include <stdio.h>
#include <pcap.h>

/*
 * What should we do with the packet?
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	printf("received packet!\n");
	return;
}

int
main(int argc, char **argv)
{
	char *dev = NULL;                    /* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];       /* error buffer */
	pcap_t *handle;                      /* packet capture handle */

	char filter_exp[] = "tcp port 80";   /* filter expression [3] */
	struct bpf_program fp;               /* compiled filter program (expression) */
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
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Sniffing on device: %s\n", dev);

	/* open capture device */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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

