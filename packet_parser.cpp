#include <pcap.h>
#include <memory.h>
#include <libnet.h>

int count = 0;

void convert_ip(int conv_ip[], int ip)
{
	char tmp_ip[9];
	char tmp[2];
	int i = 0;

	snprintf(tmp_ip,sizeof(tmp_ip), "%08x", ip);

	for(i=0;i<10;i++)
	{
		tmp[i%2] = tmp_ip[i++];
		tmp[i%2] = tmp_ip[i];
		conv_ip[i/2] = (int)strtol(tmp, NULL, 16);
	}	
}

void print_pack(libnet_ethernet_hdr *eth, libnet_ipv4_hdr *ip, libnet_tcp_hdr *tcp)
{
    int conv_src_ip[4];
    int conv_dst_ip[4];
    int ip_tmp;
    /*
    IP, PORT
    Big endian to little endian
    */
    ip_tmp = ntohl(*(int *)&ip->ip_src);
    convert_ip(conv_src_ip, ip_tmp);
    ip_tmp = ntohl(*(int *)&ip->ip_dst);
    convert_ip(conv_dst_ip, ip_tmp);

    printf("NO.%d\n",count);
    printf("============[Packet Info]===========\n");
    printf("| drc mac addr : %02x:%02x:%02x:%02x:%02x:%02x |\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("| sst mac addr : %02x:%02x:%02x:%02x:%02x:%02x |\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("------------------------------------\n");
    printf("| src ip addr  : %d.%d.%d.%d       |\n",conv_src_ip[0], conv_src_ip[1], conv_src_ip[2], conv_src_ip[3]);
    printf("| dst ip addr  : %d.%d.%d.%d       |\n",conv_dst_ip[0], conv_dst_ip[1], conv_dst_ip[2], conv_dst_ip[3]);
    printf("------------------------------------\n");
    printf("| src port     : %6d            |\n",ntohs(tcp->th_sport));
    printf("| dst port     : %6d            |\n",ntohs(tcp->th_dport));
    printf("====================================\n\n\n");
    count++;
}

void packet_viewer(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
{
	libnet_ethernet_hdr *eth_h;
	libnet_ipv4_hdr *ip_h;
	libnet_tcp_hdr *tcp_h;	
	int eth_len = sizeof(*eth_h);
	int ip_len = sizeof(*ip_h);

	eth_h = (libnet_ethernet_hdr *) p;
	ip_h = (libnet_ipv4_hdr *) (p+eth_len);
	tcp_h = (libnet_tcp_hdr *) (p+eth_len+ip_len);	

	if(ip_h->ip_p == 6)
		print_pack(eth_h, ip_h, tcp_h);
}

int main(int argc, char *argv[])
{
	char *dev;         /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
	bpf_u_int32 mask;      /* Our netmask */
	bpf_u_int32 net;      /* Our IP */
	pcap_t *pd;
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	printf("[+] Dev : %s\n", dev);
	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	if((pd = pcap_open_live(dev, 1024, 1, 10, errbuf)) == NULL){
		printf("[!] Packet descriptor Error!!!\n"); 
		perror(errbuf);
		printf("[!] EXIT process\n");
		exit(0);;
	}

	/* Compile and apply the filter */
	if (pcap_compile(pd, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pd));
		return 0;
	}
	if (pcap_setfilter(pd, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pd));
		return 0;
	}

	if (pd)
		pcap_loop(pd, -1, packet_viewer, 0); 

	return 0;
}
