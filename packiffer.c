#include <stdio.h> //For standard things
#include <stdlib.h> //malloc
#include <string.h> //strlen
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <netinet/if_ether.h> //For ETH_P_ALL
#include <net/ethernet.h> //For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <pthread.h>

// structure for packets and interfaces
struct packet_interface {
	int arg; // number of packets that taken form command line
	char *tcp_interface; // interface for tcp packets
	char *udp_interface; // interface for udp packets 
};

// function for tcp thread
void *functiontcp(void *argtcp){
	
	struct packet_interface *pacint = (struct packet_interface *)argtcp; // pointer to structure and casting
	int tcpsocket = socket(AF_INET, SOCK_STREAM, 0); // tcp socket
	pcap_t *pdt; // pcap for tcp
	pcap_dumper_t *pdtdumper; // pcap dumper for tcp
	pdtdumper = pcap_dump_open(pdt, pacint->tcp_interface); // save file in interface name
	pdt = pcap_open_live(pacint->tcp_interface, BUFSIZ, 0, -1, errbuf); // open pcap
}

// function for udp thread
void *functionudp(void *argudp){

	struct packet_interface *pacint = (struct packet_interface *)argudp; // // pointer to structure and casting
	int udpsocket = socket(AF_INET, SOCK_DGRAM, 0); // udp socket
	pcap_t *pdu; // pcap for udp
	pcap_dumper_t *pdudumper; // pcap dumper for udp
	pdudumper = pcap_dump_open(pdu, pacint->udp_interface); // save file in interface name
	pdu = pcap_open_live(pacint->udp_interface, BUFSIZ, 0, -1, errbuf);
}

// command line argument help
void displayhelp(){

	printf("demo [-t tcp interface] [-u udp interface] [-c number of packets to capture]\n"); // help text
	exit(1); // exit program
	
}

int main(int argc, char* argv[]){

	char errbuf[PCAP_ERRBUF_SIZE]; // buffer size for error provided by libpacp
	struct packet_interface pacint; // declare pacint of type packet_interface structure
	pacint.arg = atoi(argv[6]); // put number of packets in arg variable of packet_number structure
	pacint.tcp_interface = argv[2]; // put given interface to tcp interface in structure
	pacint.udp_interface = argv[4]; // put given interface to udp interface in structure
	// if taken arguments from command line is less than 6 then print "displayhelp" function
	if(argc < 6){
		displayhelp(); // show help and exit program
	}
	// command line wrong arguments
	if(argv[1] != "-t" && argv[3] != "-u" && argv[5] != "-c"){
		displayhelp(); // help text
	}
	pthread_t pthtcp; // tcp thread def
	pthread_t pthudp; // udp thread def
	pthread_create(&pthtcp, NULL, functiontcp, (void *)&pacint); // tcp thread creation
	pthread_create(&pthudp, NULL, functionudp, (void *)&pacint); // udp thread creation
	pthread_join(pthtcp, NULL); // wait for tcp thread to completes
	pthread_join(pthudp, NULL); // wait for udp thread to completes
	exit(0); // exit program

}
