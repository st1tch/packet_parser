#include <pcap.h>
#include <memory.h>
#include <libnet.h>
#include <stdint.h>
#include "hexdump.h"

int count = 0;

void print_pack(libnet_ethernet_hdr *eth, libnet_ipv4_hdr *ip, libnet_tcp_hdr *tcp, const unsigned char *p)
{
    char src_ip[16];
    char dst_ip[16];

	int size_ip = (ip->ip_hl) & 0x0f;
	int size_tcp = ((tcp->th_x2 & 0xf0) >> 4)*4;
	int size_tcpdat = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	char *payload = (char *)(p + LIBNET_ETH_H + size_ip + size_tcp);

    printf("NO.%d\n",count);
    printf("============[Packet Info]===========\n");
    printf("| drc mac addr : %02x:%02x:%02x:%02x:%02x:%02x |\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("| sst mac addr : %02x:%02x:%02x:%02x:%02x:%02x |\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("------------------------------------\n");
    printf("| src ip addr  : %s       |\n", inet_ntop(AF_INET, &(ip->ip_src), src_ip, sizeof(src_ip)));
    printf("| dst ip addr  : %s       |\n", inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, sizeof(dst_ip)));
    printf("------------------------------------\n");
    printf("| src port     : %6d            |\n",ntohs(tcp->th_sport));
    printf("| dst port     : %6d            |\n",ntohs(tcp->th_dport));
    printf("--------------[TCP_DATA]-----------\n");
	DumpHex(payload, size_tcpdat);
    printf("====================================\n\n\n");
    count++;
}

void packet_viewer(const unsigned char *p)
{
	libnet_ethernet_hdr *eth_h;
	libnet_ipv4_hdr *ip_h;
	libnet_tcp_hdr *tcp_h;	
	int eth_len = sizeof(*eth_h);
	int ip_len = sizeof(*ip_h);

	eth_h = (libnet_ethernet_hdr *) p;
	ip_h = (libnet_ipv4_hdr *) (p+eth_len);
	
	if(ip_h->ip_p == IPPROTO_TCP){
		tcp_h = (libnet_tcp_hdr *) (p+eth_len+ip_len);	
		print_pack(eth_h, ip_h, tcp_h, p);
	}
}

int main(int argc, char *argv[])
{
	const uint8_t *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	pcap_t *handle;
	uint8_t res;
	
	if (argc != 2){
		printf("[!] Usage : %s [DEVICE]\n", argv[0]);
		return 0;
	}

	if((handle = pcap_open_live(argv[1], 2048, 1, 1024, errbuf)) == NULL){
		printf("[!] Device open Error!!!\n"); 
		perror(errbuf);
		printf("[!] EXIT process\n");
		exit(0);;
	}
	
	/*	
	while(pcap_next_ex(handle, &header, &packet)){
		packet_viewer(packet);
	}
	*/

	while(1){
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0 || packet == NULL)
			continue;
		if (res == -1 || res == -2){
			printf("[!] EXIT process\n");
			break; 
		}
		packet_viewer(packet);
	}

	return 0;
}
