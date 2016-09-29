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
#include <syslog.h>

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
	
	openlog("tcp thread", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL0); // open log
	char errbuf[PCAP_ERRBUF_SIZE]; // error size buffer provided by libpacp	
	struct packet_interface *pacint = (struct packet_interface *)argtcp; // pointer to structure and casting
	syslog(LOG_INFO, "tcp thread using pcap library"); // syslog
	pcap_t *pdt; // pcap for tcp
	pcap_dumper_t *pdtdumper; // pcap dumper for tcp
	pdt = pcap_open_live(pacint->tcp_interface, BUFSIZ, 0, -1, errbuf); // open pcap
	pdtdumper = pcap_dump_open(pdt, pacint->tcp_interface); // save file as interface name
	bpf_u_int32 net; // The IP of our sniffing device
	char filter_exp[] = "tcp"; // set filter to tcp
	struct bpf_program fp; // the compiled filter experssion
	pcap_compile(pdt, &fp, filter_exp, 0, net); // compile filter 
	pcap_setfilter(pdt, &fp); // set filter
	syslog(LOG_INFO, "tcp thread started capturing"); // syslog
	pcap_loop(pdt, pacint->arg, packet_handler_tcp, (unsigned char *)pdtdumper); // start capture
	syslog(LOG_INFO, "tcp thread done"); // syslog	
	closelog(); // close log	
	
}

// function for udp thread
void *functionudp(void *argudp){

	openlog("udp thread", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL0); // open log
	char errbuf[PCAP_ERRBUF_SIZE]; // error size buffer provided by libpcap
	struct packet_interface *pacint = (struct packet_interface *)argudp; // // pointer to structure and casting
	syslog(LOG_INFO, "udp thread using pcap library"); // syslog
	pcap_t *pdu; // pcap for udp
	pcap_dumper_t *pdudumper; // pcap dumper for udp
	pdu = pcap_open_live(pacint->udp_interface, BUFSIZ, 0, -1, errbuf); // open pcap
	pdudumper = pcap_dump_open(pdu, pacint->udp_interface); // save file as interface name
	bpf_u_int32 net; // The IP of our sniffing device
	char filter_exp[] = "udp"; // set filter to udp
	struct bpf_program fp; // the compiled filter expression
	pcap_compile(pdu, &fp, filter_exp, 0, net); // compile filter
	pcap_setfilter(pdu, &fp); // set filter
	syslog(LOG_INFO, "udp thread started capturing"); // syslog
	pcap_loop(pdu, pacint->arg, packet_handler_udp, (unsigned char *)pdudumper); // start capture
	syslog(LOG_INFO, "udp thread done"); // syslog
	closelog(); // close log

}

// command line argument help
void displayhelp(){

	printf("packiffer [-t tcp interface] [-u udp interface] [-c number of packets to capture]\n"); // help text
	exit(1); // exit program
	
}

int main(int argc, char **argv){

	// if taken arguments from command line is less than 6 then print "displayhelp" function
        if(argc != 7 && argv[1] != "-t" && argv[3] != "-u" && argv[5] != "-c"){
              displayhelp(); // show help and exit program
        }
	struct pcap_pkthdr *header; // pcap.h 
	const u_char *pkt_data; // net/ethernet.h
	struct packet_interface pacint; // declare pacint of type packet_interface structure
	pacint.arg = atoi(argv[6]); // put number of packets in arg variable of packet_number structure
	pacint.tcp_interface = argv[2]; // put given interface to tcp interface in structure
	pacint.udp_interface = argv[4]; // put given interface to udp interface in structure
	pthread_t pthtcp; // tcp thread def
	pthread_t pthudp; // udp thread def
	pthread_create(&pthtcp, NULL, functiontcp, (void *)&pacint); // tcp thread creation
	pthread_join(pthtcp, NULL); // wait for tcp thread to completes
	pthread_cancel(pthtcp); // kill tcp thread
	pthread_create(&pthudp, NULL, functionudp, (void *)&pacint); // udp thread creation
	pthread_join(pthudp, NULL); // wait for udp thread to completes
	pthread_cancel(pthudp); // kill udp thread
	return 0; // exit program

}
