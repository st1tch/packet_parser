#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t  data_offset;
  uint8_t  flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_p;
} tcp_header_t;

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

	while(1){
		packet = pcap_next(handle, &header);
		printf("------------------------------------------------\n");
		printf("------------------------------------------------\n");
	}

	/* And close the session */
	pcap_close(handle);
	return(0);
}
