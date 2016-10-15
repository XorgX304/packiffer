#include <stdio.h> //For standard things
#include <stdlib.h> //malloc
#include <string.h> //strlen
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/if_ether.h> //For ETH_P_ALL
#include <net/ethernet.h> //For ether_header
#include <arpa/inet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <syslog.h>

// command line argument help
void displayhelp(){

	printf("packiffer [-t tcp interface] [-u udp interface] [-c number of packets to capture]\nmake sure interfaces names are typed correctly\nyou can see interfaces with 'ifconfig -a' command\n"); // help text
	exit(1); // exit program
	
}

// structure for packets and interfaces
struct packet_interface {
	int arg; // number of packets that taken form command line
	char *tcp_interface; // interface for tcp packets
	char *udp_interface; // interface for udp packets 
};

// Callback function invoked by libpcap for every incoming tcp packet
void packet_handler_tcp(u_char *pdtdumper, const struct pcap_pkthdr *header, const u_char *pkt_data){
    // save the packet on the dump file
    pcap_dump(pdtdumper, header, pkt_data);
}

// Callback function invoked by libpcap for every incoming udp packet
void packet_handler_udp(u_char *pdudumper, const struct pcap_pkthdr *header, const u_char *pkt_data){
    // save the packet on the dump file
    pcap_dump(pdudumper, header, pkt_data);
}

// function for tcp thread
void *functiontcp(void *argtcp){
	
	char errbuf[PCAP_ERRBUF_SIZE]; // error size buffer provided by libpacp	
	struct packet_interface *pacint = (struct packet_interface *)argtcp; // pointer to structure and casting
	syslog(LOG_INFO, "tcp thread using pcap library"); // syslog
	pcap_t *pdt; // pcap for tcp
	pcap_dumper_t *pdtdumper; // pcap dumper for tcp
	pdt = pcap_open_live(pacint->tcp_interface, BUFSIZ, 0, -1, errbuf); // open pcap
	if (pdt == NULL) {
		 displayhelp();
	 }
	pdtdumper = pcap_dump_open(pdt, pacint->tcp_interface); // save file as interface name
	bpf_u_int32 net; // The IP of our sniffing device
	struct bpf_program fp; // the compiled filter experssion
	if(pcap_compile(pdt, &fp, "tcp", 0, net) == -1){
		displayhelp();
	} // compile filter
	else { 
		if(pcap_setfilter(pdt, &fp) == -1){ // set filter
			displayhelp();
		}
		else {
			syslog(LOG_INFO, "tcp thread started capturing"); // syslog
			if(pcap_loop(pdt, pacint->arg, packet_handler_tcp, (unsigned char *)pdtdumper) == -1){
				displayhelp();
			} // start capture
			else {
			syslog(LOG_INFO, "tcp thread done"); // syslog		
			}
		}
	}
}

// function for udp thread
void *functionudp(void *argudp){

	char errbuf[PCAP_ERRBUF_SIZE]; // error size buffer provided by libpcap
	struct packet_interface *pacint = (struct packet_interface *)argudp; // // pointer to structure and casting
	syslog(LOG_INFO, "udp thread using pcap library"); // syslog
	pcap_t *pdu; // pcap for udp
	pcap_dumper_t *pdudumper; // pcap dumper for udp
	pdu = pcap_open_live(pacint->udp_interface, BUFSIZ, 0, -1, errbuf); // open pcap
	if (pdu == NULL) {
		 displayhelp();
	 }
	pdudumper = pcap_dump_open(pdu, pacint->udp_interface); // save file as interface name
	bpf_u_int32 net; // The IP of our sniffing device
	struct bpf_program fp; // the compiled filter expression
	if(pcap_compile(pdu, &fp, "udp", 0, net) == -1){
		displayhelp();
	} // compile filter
	else {
		if(pcap_setfilter(pdu, &fp) == -1){
			displayhelp();
		} // set filter
		else {
			syslog(LOG_INFO, "udp thread started capturing"); // syslog
			if(pcap_loop(pdu, pacint->arg, packet_handler_udp, (unsigned char *)pdudumper) == -1){
				displayhelp();
			} // start capture
			else {
			syslog(LOG_INFO, "udp thread done"); // syslog
			}
		}
	}
}

int main(int argc, char **argv){

	struct packet_interface pacint; // declare pacint of type packet_interface structure
	int d;
	while ((d = getopt (argc, argv, "t:u:c:")) != -1)
    switch (d)
      {
      case 't':
        pacint.tcp_interface = optarg;
        break;
      case 'u':
        pacint.udp_interface = optarg;
        break;
      case 'c':
        pacint.arg = atoi(optarg);
        break;
      case '?':
        displayhelp();
      default:
        displayhelp();
      }
	struct pcap_pkthdr *header; // pcap.h 
	const u_char *pkt_data; // net/ethernet.h
	openlog("creating threads", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL0); // open log
	pthread_t pthtcp; // tcp thread def
	pthread_t pthudp; // udp thread def
	pthread_create(&pthtcp, NULL, functiontcp, (void *)&pacint); // tcp thread creation
	pthread_create(&pthudp, NULL, functionudp, (void *)&pacint); // udp thread creation
	pthread_join(pthtcp, NULL); // wait for tcp thread to completes
	pthread_join(pthudp, NULL); // wait for udp thread to completes
	pthread_cancel(pthtcp); // kill tcp thread	
	pthread_cancel(pthudp); // kill udp thread
	closelog(); // closing log
	return 0; // exit program

}
