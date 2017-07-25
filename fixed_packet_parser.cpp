#include <pcap.h>
#include <memory.h>
#include <libnet.h>
#include <stdint.h>
#include "hexdump.h"

int count = 0;

void print_pack(libnet_ethernet_hdr *eth, libnet_ipv4_hdr *ip, libnet_tcp_hdr *tcp)
{
    char src_ip[16];
    char dst_ip[16];

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
	char *payload;               
	int size_ip;
	int size_tcp;
	int size_payload;

	eth_h = (libnet_ethernet_hdr *) p;

	ip_h = (libnet_ipv4_hdr *) (p+eth_len);
	size_ip = (ip_h->ip_hl) & 0x0f;
	
	if(ip_h->ip_p == IPPROTO_TCP)
		tcp_h = (libnet_tcp_hdr *) (p+eth_len+ip_len);	
		size_tcp = ((tcp_h->th_x2 & 0xf0) >> 4)*4;

		payload = (char *)(p + LIBNET_ETH_H + size_ip + size_tcp);
		size_payload = ntohs(ip_h->ip_len) - (size_ip + size_tcp);

		print_pack(eth_h, ip_h, tcp_h);
		DumpHex(payload, size_payload);
}

int main(int argc, char *argv[])
{
	const uint8_t *packet;
	char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
	struct pcap_pkthdr *header;
	pcap_t *handle;
	
	if((handle = pcap_open_live("enp0s5", 2048, 1, 1024, errbuf)) == NULL){
		printf("[!] Device open Error!!!\n"); 
		perror(errbuf);
		printf("[!] EXIT process\n");
		exit(0);;
	}
	
	while(pcap_next_ex(handle, &header, &packet)){
		packet_viewer(packet);
	}

	reture 0;
}
