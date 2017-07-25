packet_parser : fixed_packet_parser.cpp
	g++ -o fixed_packet_parser fixed_packet_parser.cpp -lpcap

clean : 
	rm fixed_packet_parser
