#include <stdio.h>
#include <pcap.h>


int main(int argc, char *argv[]) {
    char *dev;    
    char errbuf[PCAP_ERRBUF_SIZE];

    // get network device
    dev = pcap_lookupdev(errbuf);

    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        return 0;
    }

    // print device name
    printf("DEV: %s\n",dev);

}

