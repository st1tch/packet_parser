# packet_parser
* pcap을 이용하여 송수신되는 packet의 다음 값을 출력하는 프로그램을 작성하라.
> eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data </br>

* Requirements
> pcap.h - sudo apt-get install libpcap-dev</br>
> libnet.h - sudo apt-get install libnet-cpp-dev libnet1-dev</br>


## headers
- Ethernet header
![1](https://github.com/st1tch/packet_parser/blob/master/ether_header.png)

- Ip header
![2](https://github.com/st1tch/packet_parser/blob/master/ip_header.png)

- Tcp header
![3](https://github.com/st1tch/packet_parser/blob/master/tcp_header.png)
</br>

## Reference
> [https://gitlab.com/gilgil/network/wikis/ethernet-packet-dissection/pcap-programming](https://gitlab.com/gilgil/network/wikis/ethernet-packet-dissection/pcap-programming)</br>
> [https://wiki.kldp.org/wiki.php/DocbookSgml/Libpcap-KLDP](https://wiki.kldp.org/wiki.php/DocbookSgml/Libpcap-KLDP)</br>
