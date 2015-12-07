#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/ethernet.h>
//#include <netinet/sctp.h>
#include <linux/if_packet.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "mam_addr_manager.h"
#include "header_parser.h"

#define TRACE_FLOW 1          //Only trace if no daemonize
float ALPHA = 0.5;            //Only trace if no daemonize

#define BUFFER_SIZE 65536

typedef struct packet_list {
	packet_info pkt;
	long long time_stamp;
	struct packet_list* next;
} packet_list;

typedef struct snd_rcv_pair {
	char snd_addr[LARGEST_KNOWN_FIELD];
	char rcv_addr[LARGEST_KNOWN_FIELD]; 
	packet_list* pkts;
	int pkts_sent;
	int pkts_lost;
	int srtt;
	struct snd_rcv_pair* next;
} snd_rcv_pair;

snd_rcv_pair* head = NULL;   // global head of pair list

char snd_intents[20];
char rcv_intents[20];

void sniffer_trace(char* message) { printf("\n  %s", message); fflush(stdout); } // Declared in mam_addr_manager.c

/*
 * 
 * REMOVE LATER
 * 
 * */
void print_marcus_header (char* buffer, int size)
{
	int i;
	FILE* f;
	f =fopen("marcus_header_trams", "w");
	for (i=0; i < size; i++) fprintf(f,"\n%d", buffer[i]);
	
	fclose(f);
}

/**********************************************************************/
/*                                                                    */
/* - DEALING WITH GATHERING & STATISTICS -                            */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Packet List manipulation/utilities -                             */
/**********************************************************************/

void add_packet_to_list(packet_list* pkt, snd_rcv_pair* pair)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: add_packet_to_list");    }
	if (pair->pkts == NULL) { pkt->next = NULL; pair->pkts = pkt;      }
	else                    { pkt->next = pair->pkts; pair->pkts = pkt;}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: add_packet_to_list");     }
}

void print_packet(packet_list* item)
{
	char snd_ipv4[20];
	char rcv_ipv4[20];
	if(item->pkt.chunk != NULL)
		printf("\n%24s%24s%24u%24u%24lld", make_ipv4_readable(snd_ipv4, item->pkt.snd_addr), make_ipv4_readable(rcv_ipv4, item->pkt.rcv_addr), item->pkt.chunk->seq_nr, item->pkt.chunk->ack_nr, item->time_stamp);
	else
		printf("\n%24s%24s%24lld", make_ipv4_readable(snd_ipv4, item->pkt.snd_addr), make_ipv4_readable(rcv_ipv4, item->pkt.rcv_addr), item->time_stamp);
}

void print_packet_list(packet_list* pkts) 
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: print_packet_list"); }
	packet_list* item = pkts;
	printf("\n===================================================================");
	printf("\n%24s%24s%24s%24s%24s", "snd_addr", "rcv_addr", "seq nr", "ack nr", "time_stamp");
	printf("\n===================================================================");
	printf("1_"); fflush(stdout); 
	while (item != NULL) 
	{
		printf("2_"); fflush(stdout);
		print_packet(item);
		printf("3_"); fflush(stdout);
		item = item->next;
		item = NULL;
		printf("4_"); fflush(stdout);
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: print_packet_list"); }
}

void remove_packet(packet_list* pkts)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: remove_packet"); }
	if(TRACE_FLOW) { sniffer_trace("LEAVING: remove_packet"); }
}

/**********************************************************************/
/* - Pair List manipulation/utilities -                               */
/**********************************************************************/

int addr_cmp(char* snd_addr, char* rcv_addr, int size)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: addr_cmp"); }
	int i = 0;
	for(i=0; i< size; i++)
	{
		if (snd_addr[i] != rcv_addr[i]) { if(TRACE_FLOW) { sniffer_trace("LEAVING: addr_cmp"); } return 0; }
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: addr_cmp"); }
	return 1;
}

snd_rcv_pair* get_pair(char* snd, char* rcv)
{ 
	if(TRACE_FLOW) { sniffer_trace("ENTERING: get_pair"); }
	snd_rcv_pair* pair = head;
	while (pair != NULL) 
	{
		if((addr_cmp(pair->snd_addr, snd, 4) && addr_cmp(pair->rcv_addr, rcv, 4)) 
		|| (addr_cmp(pair->rcv_addr, snd, 4) && addr_cmp(pair->snd_addr, rcv, 4)))
		{
			return pair;
		}
		pair = pair->next;
	}
	if(TRACE_FLOW) { sniffer_trace("    ERROR: No pair found!"); }

	return NULL;
}

snd_rcv_pair* init_new_pair(snd_rcv_pair* new_pair, char* snd_addr, char* rcv_addr)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: init_new_pair"); }
	new_pair = malloc(sizeof(snd_rcv_pair));
	new_pair->pkts = NULL; //head of list
	new_pair->srtt = 0;
	memcpy(new_pair->snd_addr, snd_addr, LARGEST_KNOWN_FIELD);
	memcpy(new_pair->rcv_addr, rcv_addr, LARGEST_KNOWN_FIELD);
	if(TRACE_FLOW) { sniffer_trace("LEAVING: init_new_pair"); }
	return new_pair;
}

void add_pair_to_list(snd_rcv_pair* new_pair)
{
	if(TRACE_FLOW)    { sniffer_trace("ENTERING: add_pair_to_list"); }
	if (head == NULL) { head = new_pair; new_pair->next = NULL;      }
	else              { new_pair ->next = head; head = new_pair;     }
	if(TRACE_FLOW)    { sniffer_trace("LEAVING: add_pair_to_list");  }
}

void print_pair_list()
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: print_pair_list"); }
    //char snd_ipv4[20];
	//char rcv_ipv4[20];
	snd_rcv_pair* item = head;
	printf("\n\n***************PAIR LIST******************************");
	while (item != NULL)
	{
		//printf("\n Packets for pair: %s %s",make_ipv4_readable(snd_ipv4, item->snd_addr), make_ipv4_readable(rcv_ipv4, item->rcv_addr ));
		print_packet_list(item->pkts);
		item = item->next;
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVNING: print_pair_list"); }
}

/**********************************************************************/
/* - Statistics -                                                     */
/**********************************************************************/

int snd_rcv_match(snd_rcv_pair* pair, packet_list* pkt, packet_list ack)
{
	// TODO IPV6
	
	// IPV4
	if(addr_cmp(pkt->pkt.snd_addr, pair->snd_addr, 4) && addr_cmp(ack.pkt.snd_addr, pair->rcv_addr, 4)) 
		return 1;
	return 0;
}

int is_seq_nr_lower(packet_list* pkt, packet_list ack)
{
	if(pkt->pkt.chunk->seq_nr < ack.pkt.chunk->ack_nr)
		return 1;
	return 0;
}

unsigned int calculate_new_srtt(int old_srtt, int ack_time_stamp, int pkt_time_stamp)
{
	return ((ALPHA * old_srtt) + ((1 - ALPHA) * (ack_time_stamp - pkt_time_stamp))) + 0.5;
}

void remove_acked_packets(packet_list* head)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: remove_acked_packets"); }
	//packet_list* pkt = head;
	while(head != NULL)
	{
		//pkt = head;
		head = head->next;
		//free(pkt);
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: remove_acked_packets"); }
}

void set_new_srtt(snd_rcv_pair* pair, packet_list ack)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: set_new_srtt"); }
	packet_list* pkt = pair->pkts,* prev_pkt;
	//print_packet_list(pair->pkts);
	while (pkt != NULL)
	{
		if(snd_rcv_match(pair, pkt, ack) && is_seq_nr_lower(pkt, ack))
		{
			printf("\nack timestamp: %lld", ack.time_stamp);
			printf("\nold srtt = %d", pair->srtt);
			pair->srtt = calculate_new_srtt(pair->srtt, ack.time_stamp, pkt->time_stamp);
			printf("\nnew srtt = %d\n", pair->srtt);
			override_item_data(pair->snd_addr, pair->rcv_addr, -1, -1, pair->srtt, 4);
			//pkt->next = NULL;
			//prev_pkt = pkt;
			if(pair->pkts->next == NULL) // only one item in list
			{
			//	remove_acked_packets(pkt);
				pair->pkts = NULL;
				//pair->pkts->next = NULL;
			}
			else
			{
			//	remove_acked_packets(pkt);
				prev_pkt->next = NULL;
			}
			return;			
		}
		prev_pkt = pkt;
		pkt = pkt->next;
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: set_new_srtt"); }
}

/*
void set_new_srtt(snd_rcv_pair* pair)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: set_new_srtt"); }
	packet_list* pkt = pair->pkts, * next;
	while (pkt != NULL)
	{
		next = pair->pkts;
		while(next != NULL)
		{
			if(addr_cmp(next->pkt.snd_addr, pair->rcv_addr, 4))
				break;
			next = next->next;		
		}
		if(next == NULL)
			return;
		if(addr_cmp(pkt->pkt.snd_addr, pair->snd_addr, 4) && addr_cmp(next->pkt.snd_addr, pair->rcv_addr, 4) && pkt->pkt.seq_nr < next->pkt.ack_nr)
		{
			print_packet_list(pair->pkts);
			char snd_ipv4[20], rcv_ipv4[20];
			printf("\n pair %s %s", make_ipv4_readable(snd_ipv4, pkt->pkt.snd_addr), make_ipv4_readable(rcv_ipv4, pkt->pkt.rcv_addr ));
			printf("\nold srtt = %d", pair->srtt);
			pair->srtt = (ALPHA * pair->srtt) + ((1 - ALPHA) * (next->time_stamp - pkt->time_stamp));
			printf("\nnew srtt = %d\n", pair->srtt);
			override_item_data(pair->snd_addr, pair->rcv_addr, -1, -1, pair->srtt, 4);
			packet_list* tmp_pkt = pkt;
			pkt = pkt->next;
			remove_packet(pair->pkts, tmp_pkt);
			//break;
			tmp_pkt = pkt;
			while(tmp_pkt != NULL)
			{
				if(addr_cmp(tmp_pkt->pkt.snd_addr, pair->snd_addr, 4) && tmp_pkt->pkt.seq_nr < next->pkt.ack_nr)
				{
					packet_list* tmp = tmp_pkt;
					tmp_pkt = tmp_pkt->next;
					remove_packet(pair->pkts, tmp);
				}
				else
					tmp_pkt = tmp_pkt->next;
			}
			//packet_list* tmp_next = next;
			//next = next->next;
			remove_packet(pair->pkts, next);				
		}
		else
			pkt = pkt->next;
		//pkt = pkt->next;
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: set_new_srtt"); }
}*/

/**********************************************************************/
/* - Data gathering -                                                 */
/**********************************************************************/

void set_time_stamp (packet_list pkt) 
{
	struct timeval te; 
	gettimeofday(&te, NULL); // get current time
	pkt.time_stamp = 1000000LL * te.tv_sec + te.tv_usec; // in milli	
}

void gather_data()
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: gather_data"); }
	int sockfd;
	socklen_t saddr_size;
	struct sockaddr saddr;
	char *buffer = (char *)malloc(BUFFER_SIZE);
	
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) 
    {
		if(TRACE_FLOW) { sniffer_trace("    ERROR: socket failed!"); }
		exit(0); 
	}
	
	pkt_ptr ppkt = malloc(sizeof(pkt_ptr)); 			
	while(get_partner_status()) // as long as mam is up we gather data
	{
		//packet_list* pkt = malloc(sizeof(packet_list));
		packet_list pkt;
		saddr_size = sizeof saddr; 
        ppkt->packet_size = recvfrom(sockfd , buffer , BUFFER_SIZE , 0 , &saddr , &saddr_size);
        set_time_stamp(pkt); // setting timestamp directly when packet is received
        ppkt->packet_data = buffer;
        
        //set_ip_header_size(parse_number_from_char(&get_ipv4_ihl(ppkt).field_data[0], 0, 3)*4);
        
        //TCP
        /*memcpy(pkt->pkt.snd_addr, &get_ipv4_snd_addr(ppkt).field_data[0], LARGEST_KNOWN_FIELD);
        memcpy(pkt->pkt.rcv_addr, &get_ipv4_rcv_addr(ppkt).field_data[0], LARGEST_KNOWN_FIELD);
        pkt->pkt.chunk->seq_nr = get_num_tcp_seq_nr(ppkt);
        pkt->pkt.ack_nr = get_num_tcp_ack_nr(ppkt);
        pkt->pkt.is_ack = get_num_tcp_is_ack(ppkt);*/
        pkt.pkt = get_packet_info(ppkt);
        //SCPT
        //pkt->pkt = get_packet_info(ppkt);
        
        /*char test[4];
        test[0]= 10;
        test[1]= 0;
        test[2]= 0;
        test[3]= 4;
		if(addr_cmp(pkt->pkt.rcv_addr, test, 4) && ppkt->packet_size > 1000) // addr_cmp(pkt->pkt.rcv_addr, test, 4) && 
		{
			int i;
			for (i=0; i < ppkt->packet_size; i++) printf("%c", buffer[i]);
			print_marcus_header(buffer, ppkt->packet_size);
			exit(0);
		}*/

		// Adding new pair to list
        if(!entry_exists(pkt.pkt.snd_addr, pkt.pkt.rcv_addr, pkt.pkt.ip_addr_size) && !entry_exists(pkt.pkt.rcv_addr, pkt.pkt.snd_addr, pkt.pkt.ip_addr_size))
        {
			snd_rcv_pair* new_pair = init_new_pair(new_pair, pkt.pkt.snd_addr, pkt.pkt.rcv_addr);
			create_and_add_item_to_list(pkt.pkt.snd_addr, pkt.pkt.rcv_addr, 0, 0 ,0 );
			add_pair_to_list(new_pair);	
	    }
	    snd_rcv_pair* pair = get_pair(pkt.pkt.snd_addr, pkt.pkt.rcv_addr);
	    if(pkt.pkt.chunk != NULL)
	    {
			if(pair != NULL && pkt.pkt.chunk->layer4_type && addr_cmp(pkt.pkt.snd_addr, pair->rcv_addr, 4))
			{
				//set_new_srtt(pair, pkt);
			}
			else if(pair != NULL && !pkt.pkt.chunk->layer4_type && addr_cmp(pkt.pkt.snd_addr, pair->snd_addr, 4))
			{
				add_packet_to_list(&pkt, pair);
				//print_packet(pair->pkts);
			}
		}
		print_pair_list();
		//print_list();	
        if(ppkt->packet_size < 0 && TRACE_FLOW) { sniffer_trace("\n    ERROR: recvfrom failed!"); }
	}
	if(TRACE_FLOW) { sniffer_trace("  SHUTTING DOWN SNIFFER"); }
    close(sockfd);
    delete_state();
    //close_file();
	if(TRACE_FLOW) { sniffer_trace("LEAVING: gather_data"); }
}

/**********************************************************************/
/* - Initialize sniffer (daemonize it) and io -                       */
/**********************************************************************/

/*void open_file()  { sniffer_log = fopen("sniffer_log", "w"); }
void close_file() { fclose(sniffer_log); }
void log_sniffer(char* message) 
{ 
	if(DAEMONIZE) { fprintf(sniffer_log, "%s", message); fflush(sniffer_log); }
	else          { printf("%s", message); fflush(stdout); } 
}*/

void daemonize()
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: daemonize"); }
	umask(0);                        /* change permissions for newly created files */
	int sid = setsid();
	if(sid < 0) { exit(0); }         /* Setting up new sid                         */
	close(STDIN_FILENO);             /* Close standard IO                          */
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	//open_file();                     /* Open log file                              */
	if(TRACE_FLOW) { sniffer_trace("LEAVING: daemonize"); }
}

void wait_for_mam()
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: wait_for_mam"); }
	while(!get_partner_status()) { ; }
	if(TRACE_FLOW) { sniffer_trace("LEAVING: wait_for_mam"); }
}

/**********************************************************************/
/* - Main -                                                           */
/**********************************************************************/

int main()
{
	//Functions at 266 will fetch ALL headers of interest, they only return bytes of data, i.e. mulitple of 8 bits
	//You should not have to bother with what has ben written allready, but you need to know how to use this module
	//These functions require that you UPDATE THE STATE whenever you:
	//  1. Learn the IP-header size, which you may set by calling set_ip_header_size()
	//  2. Cannot get the STL from current chunk, set the new chunk offset via set_sctp_chunk_jump() to where the next chunk starts
	//Keep in mind that the IPv4 header size varies, to get its size call get_ipv4_ihl() 
	//IHL is half a byte, so parse a number from bits 0-3, using parse_number_from_char(<some_char>, 0, 3)
	//When the IP header size is determined, call set_ip_header_size()
	//Similar may apply to getting SCTP TSL field, you may have to move from chunk to chunk
	//It is to be determined which fields have to be flipped
	//Consider that flipping is only required when a HUMAN is to interpret the info
	//Recommend you defer getting the TSL (SEQ) number until last, start by just filtering flows
	//Filter can be hardcoded, should otherwise be set by mommy via share_memory
	//There is so sniffer logic here, move that stuff in here, rename this file, and rename main()
	//Run diagnstics if you think something has been broken, TRACE_MATCH will give more details
	//Or not

	setup_state();
	wait_for_mam();
	gather_data();
	
	return 0;
}
