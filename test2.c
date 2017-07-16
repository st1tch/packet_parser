#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *spNetDevName = pcap_lookupdev(errbuf);
	const u_char* ucData;
	int iDataLink;
	int iCnt;
	struct pcap_pkthdr stPInfo;
	pcap_t* pDes;
	char *buf;


	if(0 == spNetDevName)
	{
		printf("Error : [%s]\n", errbuf);
		return 100;
	}
	else
	{
		printf("Network Device Name : [%s]\n", spNetDevName);
	}
	pDes = pcap_open_live(spNetDevName, 1500, 1, 0, errbuf);

	if(0 == pDes)
	{
		printf("Error : [%s]\n", errbuf);
		return 101;
	}
	else
	{
		iDataLink = pcap_datalink(pDes);  
	}

	if(DLT_EN10MB == iDataLink)
	{
		printf("2Layer Type : [Ethernet (10MB)]\n");
	}

	//  printf("DataLink [%d]\n", iDataLink);

	ucData = pcap_next(pDes, &stPInfo);

	iCnt = 0;
	buf = malloc(stPInfo.caplen);
	while(iCnt<stPInfo.caplen){
		sprintf(buf[iCnt], "%c", *(ucData+iCnt));
		++iCnt;
	}
	printf("%s\n", buf);
	iCnt = 0;
	while(iCnt<stPInfo.caplen)
	{
		printf("[%02X] ", *(ucData + iCnt));
		++iCnt;
		if(0 == (iCnt % 16))
		{
			putchar('\n');
		}
	}
	putchar('\n');

	pcap_close(pDes);

	return 0;
}
