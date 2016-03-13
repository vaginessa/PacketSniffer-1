CSE508: Network Security, Spring 2016
Homework 2: Programming with Libpcap
-------------------------------------------------------------------------------
Submission deadline: 3/4/2016 11:59pm EDT
Submission through https://blackboard.stonybrook.edu
Submitted By: Alpit Kumar Gupta (110451714)
________________________________________________________________________________

This project has been developed in C to implement a passive network monitoring application
using the libpcap packet capture library. It provides below key functionalities.
1. Captures live traffic from a network interface like eth0,wlan0 etc. in promiscuous mode. 
2. Read the packets from a pcap trace file, offline sniffing.
3. Takes a string pattern for capturing only packets with matching payloads.

#############################################Technical Design###########################################

File: mydump.c
1.  main function: This is the entry point of the program execution. It takes three types of argument:
    -i: network interface for live sniffing of packets
	-r: pcap file for offline sniffing
	-s: string patter to filter packets with given payload only
	
	In case of any wrong argument type, it will give below error message.
	./mydump: invalid option -- 'X'
    
	All kind of validation has been done and verified.
	If user passes both the live as well as offilne argument using -i & -r options, then it will priority
	offline sniffing option (-r).

	If user passes more than 7 arguments, it will give below error message.
	error: unrecognized command-line options\n\n
	
2. void fileSniffing(char* file, u_char* filter):
	This function load the pcap file and dispatch the packets untill EOF is reached.
	
	
3. void liveSniffing(char* interface, u_char* filter):
	This function check for the capture device on command line. It finds a default capture device in case 
	of no parameter passed. Further it open the capture device and dispatches every packet till user stops
	using ctrl+c command.
	
4. void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)"
	This fucntion computes all the ethernet/IP/TCP header and retrieves all the required informations.
	It also capatures the payload and check if the passed filter string belongs to it.
	In case of filter string option, it only allow printing of packets with given string in their payload.
	
5. int myStrStr(const u_char *str1, const u_char *str2, int size_payload):
	This function compares the user passed string in the packet payload. The reason to implement this function
	is strStr doesnot work properly here as it stops in betweeen if it encounters NULL (\0) in the payload section.
	This might result in not evaluating the entire payload searching for a string. In my implementation, i have 
	used the payload length to properly search for the given string in the packet's payload.
	
6. 	void print_payload(const u_char *payload, int len):
	This function parses the payload line by line with size of 16.
	
7. 	void print_hex_ascii_line(const u_char *payload, int len, int offset):
	This function finally print the payload in both Hex and Ascii printable format.


########################################Structures#############################################
I have defined below Ethernet, IP and TCP header format to capture all the needed informations.
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    
        u_char  ether_shost[ETHER_ADDR_LEN];    
        u_short ether_type;                     
};

struct sniff_ip {
        u_char  ip_vhl;                 
        u_char  ip_tos;                 
        u_short ip_len;                 
        u_short ip_id;                  
        u_short ip_off;                 
        u_char  ip_ttl;                 
        u_char  ip_p;                   
        u_short ip_sum;                 
        struct  in_addr ip_src,ip_dst;  
};

struct sniff_tcp {
        u_short th_sport;               
        u_short th_dport;               
        tcp_seq th_seq;                 
        tcp_seq th_ack;                 
        u_char  th_offx2;               
		
};

	
Note:	
Ignored packets with IP and TCP header size less than 20.
Payload is printed in both Hex and Ascii format


File: Makefile
	This file contains shell command to compile and produce executable using make command.

	
##################################How to run the program###################################

1) ./mydump -i eth0
	To capture live sniffing using network interface eth0. The sample output is saved in the 
	output_liveCapture.txt file.
	
	*********************************************************************************************
	2016-03-11 17:54:27637360	34:17:eb:b5:ff:f6->ff:ff:ff:ff:ff:ff	type 0008	len  278
	130.245.145.7: 138 -> 130.245.145.255: 138	UDP
	Raw content of the application-layer packet payload (212 bytes):
	00000   50 46 44 46 45 45 46 46  43 45 50 45 4f 45 46 43    PFDFEEFFCEPEOEFC
	00016   41 43 41 43 41 41 41 00  20 46 48 45 50 46 43 45    ACACAAA. FHEPFCE
	00032   4c 45 48 46 43 45 50 46  46 46 41 43 41 43 41 43    LEHFCEPFFFACACAC
	00048   41 43 41 43 41 43 41 42  4e 00 ff 53 4d 42 25 00    ACACACABN..SMB%.
	00064   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
	00080   00 00 00 00 00 00 00 00  00 00 11 00 00 44 00 00    .............D..
	00096   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
	00112   00 44 00 56 00 03 00 01  00 01 00 02 00 55 00 5c    .D.V.........U.\
	00128   4d 41 49 4c 53 4c 4f 54  5c 42 52 4f 57 53 45 00    MAILSLOT\BROWSE.
	00144   01 05 80 fc 0a 00 54 45  53 54 4f 53 54 45 52 4f    ......TESTOSTERO
	00160   4e 45 00 00 00 00 04 09  03 9a 81 00 0f 01 55 aa    NE............U.
	00176   74 65 73 74 6f 73 74 65  72 6f 6e 65 20 73 65 72    testosterone ser
	00192   76 65 72 20 28 53 61 6d  62 61 2c 20 55 62 75 6e    ver (Samba, Ubun
	00208   74 75 29 00                                         tu).
	*********************************************************************************************

2) ./mydump -r hw1.pcap
	To capture offline pcap file sniffing. The sample output is saved in the output_fileCapture_hw1pcap.txt
	file. I have used hw1.pcap file to validate the output.
	
	*********************************************************************************************
	2013-01-12 17:20:25176130	0:0:48:46:6c:97->ff:ff:ff:ff:ff:ff	type 0008	len  243
	192.168.0.12: 1183 -> 192.168.0.255: 138	UDP
	Raw content of the application-layer packet payload (161 bytes):
	00000   41 43 41 43 41 43 41 00  20 46 48 45 50 46 43 45    ACACACA. FHEPFCE
	00016   4c 45 48 46 43 45 50 46  46 46 41 43 41 43 41 43    LEHFCEPFFFACACAC
	00032   41 43 41 43 41 43 41 42  4e 00 ff 53 4d 42 25 00    ACACACABN..SMB%.
	00048   00 00 00 18 00 00 00 00  00 00 00 00 00 00 00 00    ................
	00064   00 00 00 00 56 4e 00 00  00 00 11 00 00 21 00 00    ....VN.......!..
	00080   00 00 00 00 00 00 00 00  00 e8 03 00 00 00 00 00    ................
	00096   00 21 00 56 00 03 00 01  00 00 00 02 00 32 00 5c    .!.V.........2.\
	00112   4d 41 49 4c 53 4c 4f 54  5c 42 52 4f 57 53 45 00    MAILSLOT\BROWSE.
	00128   01 00 80 fc 0a 00 45 50  34 36 36 43 39 37 00 00    ......EP466C97..
	00144   00 00 00 00 00 00 01 00  03 03 00 00 00 00 aa 55    ...............U
	00160   00                                                  .
	*********************************************************************************************

3) 	./mydump -r hw1.pcap -s "port"
	To capture the packets from hw1.pcap file with payload containing string pattern "port".
	The sample output is saved in output_fileCapture_filterString-port.txt file.
	
	*********************************************************************************************
	2013-01-14 02:52:52738992	0:c:29:e9:94:8e->c4:3d:c7:17:6f:9b	type 0008	len  308
	192.168.0.200: 54634 -> 91.189.91.14: 80	TCP
	Raw content of the application-layer packet payload (242 bytes):
	00000   47 45 54 20 2f 75 62 75  6e 74 75 2f 64 69 73 74    GET /ubuntu/dist
	00016   73 2f 6f 6e 65 69 72 69  63 2d 62 61 63 6b 70 6f    s/oneiric-backpo
	00032   72 74 73 2f 52 65 6c 65  61 73 65 20 48 54 54 50    rts/Release HTTP
	00048   2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 75 73 2e 61    /1.1..Host: us.a
	00064   72 63 68 69 76 65 2e 75  62 75 6e 74 75 2e 63 6f    rchive.ubuntu.co
	00080   6d 0d 0a 43 6f 6e 6e 65  63 74 69 6f 6e 3a 20 6b    m..Connection: k
	00096   65 65 70 2d 61 6c 69 76  65 0d 0a 43 61 63 68 65    eep-alive..Cache
	00112   2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67    -Control: max-ag
	00128   65 3d 30 0d 0a 49 66 2d  4d 6f 64 69 66 69 65 64    e=0..If-Modified
	00144   2d 53 69 6e 63 65 3a 20  4d 6f 6e 2c 20 31 35 20    -Since: Mon, 15 
	00160   4f 63 74 20 32 30 31 32  20 30 32 3a 33 35 3a 32    Oct 2012 02:35:2
	00176   31 20 47 4d 54 0d 0a 55  73 65 72 2d 41 67 65 6e    1 GMT..User-Agen
	00192   74 3a 20 44 65 62 69 61  6e 20 41 50 54 2d 48 54    t: Debian APT-HT
	00208   54 50 2f 31 2e 33 20 28  30 2e 38 2e 31 36 7e 65    TP/1.3 (0.8.16~e
	00224   78 70 35 75 62 75 6e 74  75 31 33 2e 36 29 0d 0a    xp5ubuntu13.6)..
	00240   0d 0a                                               ..
	*********************************************************************************************

References:
	I have referred below websites/internet sources to implement and develop this tool.
	http://www.tcpdump.org/pcap.html
	https://en.wikipedia.org/wiki/Pcap
	https://wiki.wireshark.org/libpcap
	http://www.tcpdump.org/sniffex.c