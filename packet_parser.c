#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>


typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}macaddress;

struct ip *iph; 
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
	static int count = 1;
	struct ether_header *ep;
	unsigned short ether_type;
	int chcnt =0;
	int length=pkthdr->len;
}

int main(int argc, char *argv[])
{
	pcap_t *handle;         /* Session handle */
	char *dev;         /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
	struct bpf_program fp;      /* The compiled filter */
	char filter_exp[] = "port 23";   /* The filter expression */
	bpf_u_int32 mask;      /* Our netmask */
	bpf_u_int32 net;      /* Our IP */
	struct pcap_pkthdr header;   /* The header that pcap gives us */
	const u_char *packet;      /* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 0x1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	if (pcap_compile(pcd, &fp, argv[2], 0, netp) ==1){
		pcap_perror(pcd, "pcap_compile failure");
		return(2);
	}

	pcap_loop(pcd, atoi(argv[1]), callback, NULL);

	/* And close the session */
	pcap_close(handle);
	return(0);
}
