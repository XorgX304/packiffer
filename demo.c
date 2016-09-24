#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// structure for packets and interfaces
struct packet_number {
	int arg; // number of packets that taken form command line
	char **tcp_interface; // interface for tcp packets
	char **udp_interface; // interface for udp packets 
};

// function for tcp thread
void *functiontcp(void *argtcp){
	
	struct packet_number *panu = argtcp; // args
	int tcpsocket = socket(AF_INET, SOCK_STREAM, 0); // tcp socket
	// number of packets to capture
	for(int i = 0;i < panu->arg;i++){ // run until the number of received packets
		
	}
}

// function for udp thread
void *functionudp(void *argudp){

	struct packet_number *panu = argudp; // args
	int udpsocket = socket(AF_INET, SOCK_DGRAM, 0); // udp socket
	// number of packets to capture
	for(int i = 0;i < panu->arg;i++){ // run until the number of received packets

	}
}

// command line argument help
void displayhelp(){

	printf("demo [-t tcp interface] [-u udp interface] [-c number of packets to capture]\n"); // help text
	exit(0); // exit program
	
}

int main(int argc, char* argv[]){

	struct packet_number panu; // alias
	panu.arg = argv[6]; // put number of packets in arg variable of packet_number structure
	panu.tcp_interface = argv[2]; // put given interface to tcp interface in structure
	panu.udp_interface = argv[4]; // put given interface to udp interface in structure
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
	pthread_create(&pthtcp, NULL, functiontcp, "tcp processing"); // tcp thread create
	pthread_create(&pthudp, NULL, functionudp, "udp processing"); // udp thread create
	pthread_join(pthtcp, NULL); // wait for tcp thread to completes
	pthread_join(pthudp, NULL); // wait for udp thread to completes
	return 0;

}
