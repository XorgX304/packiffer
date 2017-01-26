/*

Copyright (c) 2016-2017, Massoud Asadi
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include <stdio.h> 
#include <stdlib.h>
#include <string.h> 
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/udp.h> 
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h> 
#include <arpa/inet.h>
#include <pthread.h> 
#include <syslog.h>
#include <gtk/gtk.h>

struct pcap_pkthdr *header; // pcap.h
const u_char *pkt_data; // net/ethernet.h

// structure for button callback
struct btn {
	const char *num;
        const char *tcp_btn;
        const char *udp_btn; 
};

// structure for packets and interfaces
struct packet_interface {
	int arg; // number of packets that taken form command line
	const char *tcp_interface; // interface for tcp packets
	const char *udp_interface; // interface for udp packets 
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
		printf("error");
	}
	pdtdumper = pcap_dump_open(pdt, pacint->tcp_interface); // save file as interface name
	bpf_u_int32 net = 0; // The IP of our sniffing device
	struct bpf_program fp; // the compiled filter experssion
	if(pcap_compile(pdt, &fp, "tcp", 0, net) == -1){
		printf("error");
	} // compile filter
	else { 
		if(pcap_setfilter(pdt, &fp) == -1){ // set filter
			printf("error");
		}
		else {
			syslog(LOG_INFO, "tcp thread started capturing"); // syslog
			if(pcap_loop(pdt, pacint->arg, packet_handler_tcp, (unsigned char *)pdtdumper) == -1){
				printf("error");
			} // start capture
			else {
				syslog(LOG_INFO, "tcp thread done"); // syslog		
			}
		}
	}
	return 0;
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
		printf("error");
	}
	pdudumper = pcap_dump_open(pdu, pacint->udp_interface); // save file as interface name
	bpf_u_int32 net = 0; // The IP of our sniffing device
	struct bpf_program fp; // the compiled filter expression
	if(pcap_compile(pdu, &fp, "udp", 0, net) == -1){
		printf("error");
	} // compile filter
	else {
		if(pcap_setfilter(pdu, &fp) == -1){
			printf("error");
		} // set filter
		else {
			syslog(LOG_INFO, "udp thread started capturing"); // syslog
			if(pcap_loop(pdu, pacint->arg, packet_handler_udp, (unsigned char *)pdudumper) == -1){
				printf("error");
			} // start capture
			else {
				syslog(LOG_INFO, "udp thread done"); // syslog
			}
		}
	}
	return 0;
}

static void destroy (GtkWidget*, gpointer); // destroy function 
static gboolean delete_event (GtkWidget*, GdkEvent*, gpointer); // kill event
void sniff (GtkWidget *widget, gpointer data){
	
	struct packet_interface pacint; // declare pacint of type packet_interface structure
	struct btn *zc = data;
	pacint.arg = atoi(zc->num);
	pacint.tcp_interface = zc->tcp_btn;
	pacint.udp_interface = zc->udp_btn;
	pthread_t pthtcp; // tcp thread def
        pthread_t pthudp; // udp thread def
        pthread_create(&pthtcp, NULL, functiontcp, (void *)&pacint); // tcp thread creation
        pthread_create(&pthudp, NULL, functionudp, (void *)&pacint); // udp thread creation
        pthread_join(pthtcp, NULL); // wait for tcp thread to completes
        pthread_join(pthudp, NULL); // wait for udp thread to completes
        pthread_cancel(pthtcp); // kill tcp thread      
        pthread_cancel(pthudp); // kill udp thread
        closelog(); // closing log
		
} 
int main(int argc, char **argv){

	GtkWidget *grid, *window, *button, *tcp_entry, *udp_entry, *num_entry; // init widgets
        gtk_init (&argc, &argv); // init clp
        window = gtk_window_new (GTK_WINDOW_TOPLEVEL); // creates new window
	gtk_window_set_title (GTK_WINDOW (window), "Packiffer"); // title in master window
	gtk_container_set_border_width (GTK_CONTAINER (window), 10); // cointainer border
	gtk_widget_set_size_request (window, 250, 100); // set windows size
	grid = gtk_grid_new (); // pack our widgets
        /* Connect the main window to the destroy and delete-event signals. */  
	g_signal_connect (G_OBJECT (window), "destroy", G_CALLBACK (destroy), NULL);
	g_signal_connect (G_OBJECT (window), "delete_event", G_CALLBACK (delete_event), NULL);    
        /* Add the grid as a child widget of the window. */
	gtk_container_add (GTK_CONTAINER (window), grid);
	// label tcp
	tcp_entry = gtk_entry_new ();
	gtk_entry_set_placeholder_text(GTK_ENTRY (tcp_entry), "tcp");
	gtk_grid_attach (GTK_GRID (grid), tcp_entry, 0, 0, 1, 1);
	// label udp
	udp_entry = gtk_entry_new ();
	gtk_entry_set_placeholder_text(GTK_ENTRY (udp_entry), "udp");
        gtk_grid_attach (GTK_GRID (grid), udp_entry, 1, 0, 1, 1);
	//label number
	num_entry = gtk_entry_new ();
	gtk_entry_set_placeholder_text(GTK_ENTRY (num_entry), "number");
	gtk_grid_attach (GTK_GRID (grid), num_entry, 2, 0, 1, 1);
	// struct
	struct btn b; // declare pacint of type packet_interface structure
	b.num = gtk_entry_get_text(GTK_ENTRY (num_entry));
	b.tcp_btn = gtk_entry_get_text(GTK_ENTRY (tcp_entry));
	b.udp_btn = gtk_entry_get_text(GTK_ENTRY (udp_entry));
	// button
	button = gtk_button_new_with_label ("sniff");
	g_signal_connect (button, "clicked", G_CALLBACK (sniff), &b);
	gtk_grid_attach (GTK_GRID (grid), button, 0, 1, 3, 1); 
	gtk_widget_show_all (window);
        gtk_main (); // waits for signals
	return 0; // exit program
}

/* Stop the GTK+ main loop function when the window is destroyed. */ 
static void destroy(GtkWidget *window, gpointer data){  
	gtk_main_quit(); 
}
/* Return FALSE to destroy the widget */ 
static gboolean delete_event(GtkWidget *window, GdkEvent *event, gpointer data){   
	return FALSE;
}
