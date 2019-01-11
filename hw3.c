#include "hw3.h"
pcap_t *handle;
int isSend=0;
int sendPacket(const void *packet){
	return pcap_inject(handle, packet, sizeof(packet));
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr header) {
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	char *payload; /* Packet payload */
	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		//printf("* Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	//prevent inet_ntoa rewrite buffer
	char src[BUFSIZE],dst[BUFSIZE];
	strcpy(src,inet_ntoa(ip->ip_src));
	strcpy(dst,inet_ntoa(ip->ip_dst));

	//transfer timestamp to printable type
	time_t time;
	struct tm *tm;
	char tmbuf[BUFSIZE];
	time=header.ts.tv_sec;
	tm=localtime(&time);
	strftime(tmbuf,BUFSIZE,"%Y-%m-%d %H:%M:%S",tm);

	//print informationntohl(
	printf("來源ip位址:%s\n目的ip位址:%s\n來源port:%hu\n目的port:%hu\n封包長度:%hu bytes\n封包時間:%s\n",
		src,
		dst,
		ntohs(tcp->th_sport),
	       	ntohs(tcp->th_dport),
		header.len,
		tmbuf
	);

	if(isSend){
		if(sendPacket((const void *)packet)) printf("Packet is sent.\n");
	}
	printf("\n");
}

void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
	print_packet_info(packet,*header);
}

int main(int argc,char **argv){
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];
	int timeout_limit=10000;
	struct bpf_program filter;
	char filter_exp[4096],c,raw_bytes[4096];
	bpf_u_int32 subnet_mask,ip;
	int useFile=0;

	//resolve argument
	//-p:pcap file
	//-f:filter setting
	while((c=getopt(argc, argv, "p:f:s")) != -1)
	{
	    switch(c)
	    {
		case 'p':
			printf("file=%s\n",optarg);
			handle=pcap_open_offline(optarg,error_buffer);	
			useFile=1;	
			break;
		case 'f':
			//printf("optind=%d %d\n",optind,argc);
			optind--;
			for(;optind<argc;optind++){
				if(argv[optind][0]=='-') break;
				//printf("*%d %s\n",optind,argv[optind]);
				strcat(filter_exp,argv[optind]);
				strcat(filter_exp," ");
			}
			printf("filter=%s\n",filter_exp);
			break;
		case 's':
			printf("send file is on\n");
			isSend=1;
			break;
		case ':':
			printf("wrong command\n");
			return 0;
			break;
	    }
	}


	//live capature
	if(!useFile){
		//setting device
		device=pcap_lookupdev(error_buffer);
		if(device==NULL){
			printf("Error finding device: %s\n",error_buffer);
			return 1;
		}
		//printf("Network device found: %s\n", device);


		//get device information
		if (pcap_lookupnet(device, &ip, &subnet_mask, error_buffer) == -1) {
			printf("Could not get information for device: %s\n", device);
			ip = 0;
			subnet_mask = 0;
	    	}
		//printf("IP address: %d\n", ip);
	   	//printf("Subnet mask: %d\n", subnet_mask);


		//open device for live capture
		handle = pcap_open_live(device,BUFSIZ,0,timeout_limit,error_buffer);
		if(handle==NULL){
			printf("Couldn't open device %s:%s\n",device,error_buffer);
		}
		
		//set monitor and promiscuous mode
		pcap_set_rfmon(handle,1);
		pcap_set_promisc(handle,1);
		pcap_activate(handle);
	}


	//set filter
	if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
		printf("Bad filter - %s\n", pcap_geterr(handle));
		return 2;
	}
	if (pcap_setfilter(handle, &filter) == -1) {
		printf("Error setting filter - %s\n", pcap_geterr(handle));
		return 2;
	}

	printf("Start sniffing...\n\n");
	//get packet
	pcap_loop(handle,0,my_packet_handler,NULL);
	pcap_close(handle);
	
	return 0;
}
