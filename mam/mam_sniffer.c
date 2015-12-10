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
#include <fcntl.h>
//#include "mam_addr_manager.h"
#include "header_parser.h"
#include "si_exp.h"
#include "query_handler.h"

#define TRACE_FLOW 0          //Only trace if no daemonize
const float ALPHA = 0.125;           // the aplha constant in rtt calcualtions
const float BETA  = 0.250;

int packets = 0;          
int pairs   = 0;          

#define BUFFER_SIZE 65536
#define PAIR_TTL 60      // TTL in seconds, freeing memory used by this pair.
#define DATA_IS_OLD 1     // data is old after xx seconds

typedef struct packet_list {
	packet_info* pkt_info;
	long long time_stamp;
	struct packet_list* next;
} packet_list;

typedef struct snd_rcv_pair {
	char snd_addr[FIELD_LIMIT];
	char rcv_addr[FIELD_LIMIT];
	int addr_size;
	packet_list* pkts;
	long long time_stamp;
	int pkts_sent;
	int pkts_lost;
	int srtt;
	int jitt;
	int loss;
	int rate;
	struct snd_rcv_pair* next;
} snd_rcv_pair;

snd_rcv_pair* pair_list = NULL;   // global head of pair list

long long get_time_stamp();

char snd_intents[20];
char rcv_intents[20];

void sniffer_trace(char* message) { printf("\n  %s", message); fflush(stdout); } // Declared in mam_addr_manager.c
int count_packets();
/*
 * 
 * REMOVE LATER
 * 
 * */
void print_marcus_header (char* buffer, int size, char* rcv_addr)
{
	static int number_of_packets = 0;
	int i;
	FILE* f;
	char addr[20];
	make_ipv4_readable(addr, rcv_addr);
	char fname[20];
	sprintf(fname, "%d_%s", number_of_packets++, addr);
	f = fopen(fname, "w");
	for (i=0; i < size; i++) fprintf(f,"\n%d", buffer[i]);
	
	fclose(f);
}

/**********************************************************************/
/*                                                                    */
/* - PRINT FUNCTIONS -                                                */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Printfunctions -                                                 */
/**********************************************************************/

void print_double_bar() { printf("\n=========================================================================================================================="); }
void print_single_bar() { printf("\n--------------------------------------------------------------------------------------------------------------------------"); }

float get_float_value(int value) { return value/1000.0; }

void print_packet(packet_list* item)
{
	if(item->pkt_info->chunk != NULL)
		printf("\n%24s%24s%24u%24u%24lld", item->pkt_info->snd_addr,item->pkt_info->rcv_addr, item->pkt_info->chunk->seq_nr, item->pkt_info->chunk->ack_nr, item->time_stamp);
	else
		printf("\n%24s%24s%24lld", item->pkt_info->snd_addr, item->pkt_info->rcv_addr, item->time_stamp);
}

void print_packet_list(packet_list* pkts) 
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: print_packet_list"); }
	packet_list* item = pkts;
	if(item == NULL) // empty list
	{
		printf("\n  EMPTY PACKET LIST");
		return;
	}
	printf("\n%24s%24s%24s%24s%24s", "snd_addr", "rcv_addr", "seq nr", "ack nr", "time_stamp");
	while (item != NULL) 
	{
		print_packet(item);
		item = item->next;
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: print_packet_list"); }
}

/**********************************************************************/
/*                                                                    */
/* - REMOVING COMPUND STRUCTS -                                       */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Removing compund structs -                                       */
/**********************************************************************/

void free_pkt(packet_list* pkt)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: free_pkt");    }
	chunk_info* head;
	if(pkt->pkt_info != NULL) 
	{ 
		while(pkt->pkt_info->chunk != NULL)
		{
			head = pkt->pkt_info->chunk;
			pkt->pkt_info->chunk = pkt->pkt_info->chunk->next_chunk;
			free(head);
		}
		free(pkt->pkt_info);
	}
	free(pkt);
	if(TRACE_FLOW) { sniffer_trace("LEAVING: free_pkt");    }
}

void free_pair_and_packets(snd_rcv_pair* pair) 
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: free_pair_and_packets");    }
	pairs--;
	packet_list* pkt;
	while(pair->pkts != NULL)
	{
		packets--;
		pkt = pair->pkts;
		pair->pkts = pkt->next;
		free_pkt(pkt);
		//printf("\npackets in list: %d   packets counted: %d", packets, count_packets()); fflush(stdout);
	}
	free(pair);
	if(TRACE_FLOW) { sniffer_trace("LEAVING: free_pair_and_packets");    }
}

/**********************************************************************/
/*                                                                    */
/* - DEALING WITH GATHERING & STATISTICS -                            */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Packet List manipulation/utilities -                             */
/**********************************************************************/

int count_packets() 
{
	int result = 0;
	snd_rcv_pair* list = pair_list;
	packet_list* pkts;
	while(list != NULL)
	{
		pkts = list->pkts;
		while(pkts != NULL)
		{
			result++;
			pkts = pkts->next;
		}
		list = list->next;
	}
	return result;
}

int count_pairs() 
{
	int result = 0;
	snd_rcv_pair* list = pair_list;
	while(list != NULL)
	{
		result++;
		list = list->next;
	}
	return result;
}

void add_packet_to_list(packet_list* pkt, snd_rcv_pair* pair)
{
	packets++;
	if(TRACE_FLOW) { sniffer_trace("ENTERING: add_packet_to_list");    }
	if (pair->pkts == NULL) { pkt->next = NULL; pair->pkts = pkt;      }
	else                    { pkt->next = pair->pkts; pair->pkts = pkt;}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: add_packet_to_list");     }
	//printf("\npackets in list: %d   packets counted: %d", packets, count_packets()); fflush(stdout);
}


void remove_acked_packets(packet_list* head)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: remove_acked_packets"); }
	packet_list* pkt = head;
	while(head != NULL)
	{
		packets--;
		pkt = head;
		head = head->next;
		free_pkt(pkt);
		//printf("\npackets in list: %d   packets counted: %d", packets, count_packets()); fflush(stdout);
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: remove_acked_packets"); }
}

/**********************************************************************/
/* - Pair List manipulation/utilities -                               */
/**********************************************************************/

void print_pair_list()
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: print_pair_list"); }
	snd_rcv_pair* item = pair_list;
	print_double_bar();
	printf("\n                             LIST OF PAIRS");
	print_double_bar(); 
	while (item != NULL)
	{
		print_double_bar();
		printf("\n              Pair:   %s       %s", item->snd_addr, item->rcv_addr);
		print_double_bar();
		print_packet_list(item->pkts);
		item = item->next;
	}
	print_double_bar();
	printf("\n                              END OF LIST");
	print_double_bar();
	fflush(stdout);
	if(TRACE_FLOW) { sniffer_trace("LEAVNING: print_pair_list"); }
}

int addr_cmp(char* snd_addr, char* rcv_addr, int size)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: addr_cmp"); }
	int i = 0;
	for(i = 0; i < size; i++)
	{
		if (snd_addr[i] != rcv_addr[i]) { if(TRACE_FLOW) { sniffer_trace("LEAVING: addr_cmp"); } return 0; }
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: addr_cmp"); }
	return 1;
}

void set_new_time_stamp_for(snd_rcv_pair* pair) { pair->time_stamp = get_time_stamp(); } 

snd_rcv_pair* get_pair(char* snd, char* rcv)
{ 
	if(TRACE_FLOW) { sniffer_trace("ENTERING: get_pair"); }
	snd_rcv_pair* pair = pair_list;
	while (pair != NULL) 
	{
		if((addr_cmp(pair->snd_addr, snd, pair->addr_size) && addr_cmp(pair->rcv_addr, rcv, pair->addr_size)) 
		|| (addr_cmp(pair->rcv_addr, snd, pair->addr_size) && addr_cmp(pair->snd_addr, rcv, pair->addr_size)))
		{
			set_new_time_stamp_for(pair); // Pair got new data, update timestamp so it doesnt get old and removed
			return pair;
		}
		pair = pair->next;
	}
	if(TRACE_FLOW) { sniffer_trace("    ERROR: No pair found!"); }

	return NULL;
}

snd_rcv_pair* init_new_pair(snd_rcv_pair* new_pair, char* snd_addr, char* rcv_addr, int addr_size)
{
	pairs++;
	if(TRACE_FLOW) { sniffer_trace("ENTERING: init_new_pair"); }
	new_pair = malloc(sizeof(snd_rcv_pair));
	new_pair->pkts = NULL; 
	new_pair->srtt = 0;
	new_pair->jitt = 0;
	new_pair->loss = 0;
	new_pair->rate = 0;
	new_pair->time_stamp = get_time_stamp();
	memcpy(new_pair->snd_addr, snd_addr, FIELD_LIMIT);
	memcpy(new_pair->rcv_addr, rcv_addr, FIELD_LIMIT);
	new_pair->addr_size = addr_size;
	if(TRACE_FLOW) { sniffer_trace("LEAVING: init_new_pair"); }
	return new_pair;
}

void add_pair_to_list(snd_rcv_pair* new_pair)
{
	if(TRACE_FLOW)         { sniffer_trace("ENTERING: add_pair_to_list");       }
	if (pair_list == NULL) { pair_list = new_pair; new_pair->next = NULL;       }
	else                   { new_pair ->next = pair_list; pair_list = new_pair; }
	if(TRACE_FLOW)         { sniffer_trace("LEAVING: add_pair_to_list");        }
}

int pair_exist(char* snd_addr, char* rcv_addr, int addr_size)
{
	if(TRACE_FLOW)    { sniffer_trace("ENTERING: pair_exist");  }
	snd_rcv_pair* tail = pair_list;
	while(tail != NULL)
	{
		if(addr_cmp(snd_addr, tail->snd_addr, addr_size) && addr_cmp(rcv_addr, tail->rcv_addr, addr_size)) { return 1; }
		if(addr_cmp(rcv_addr, tail->snd_addr, addr_size) && addr_cmp(snd_addr, tail->rcv_addr, addr_size)) { return 1; }
		tail = tail->next;
	}
	if(TRACE_FLOW)    { sniffer_trace("LEAVING: pair_exist");  }
	return 0;
}

void add_new_pair(char* snd, char* rcv, int addr_size)
{
	if(TRACE_FLOW)    { sniffer_trace("ENTERING: add_new_pair");  }
	snd_rcv_pair* new_pair = NULL;
	new_pair = init_new_pair(new_pair, snd, rcv, addr_size);
	add_pair_to_list(new_pair);
	if(TRACE_FLOW)    { sniffer_trace("LEAVING: add_new_pair");  }
}

void remove_old_pairs(long long time_stamp)
{
	if(TRACE_FLOW)    { sniffer_trace("ENTERING: remove_old_pair");  }
	snd_rcv_pair* item = pair_list, * prev_pair;
	while(item != NULL)
	{
		if((time_stamp - item->time_stamp) > PAIR_TTL)
		{
			if(item == pair_list)
			{
				pair_list = item->next;
				free_pair_and_packets(item);
				item = pair_list;
			}
			else
			{
				prev_pair->next = item->next;
				free_pair_and_packets(item);
				item = prev_pair->next;
			}
		}
		else
		{
			prev_pair = item;
			item = item->next;
		}
	}
	if(TRACE_FLOW)    { sniffer_trace("LEAVING: remove_old_pair");  }
}

/**********************************************************************/
/* - Data sniffer functions -                                         */
/**********************************************************************/

int setup_data_sniffer_socket()
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: setup_data_sniffer_socket"); }
	int sockfd, flags;
	
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    flags = fcntl(sockfd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(sockfd, F_SETFL, flags);
	
    if (sockfd < 0) { if(TRACE_FLOW) { sniffer_trace("    ERROR: socket failed!"); } exit(0); }
    if(TRACE_FLOW) { sniffer_trace("LEAVING: setup_data_sniffer_socket"); }
	return sockfd;
}

void remove_old(long long time_stamp)
{
	if(TRACE_FLOW)    { sniffer_trace("ENTERING: remove_old");  }
	remove_old_pairs(time_stamp);
	//remove_old_packets(time_stamp);
	if(TRACE_FLOW)    { sniffer_trace("LEAVING: remove_old");  }
}

int snd_rcv_match(snd_rcv_pair* pair, packet_list* pkt, packet_list* ack)
{
	if(TRACE_FLOW)    { sniffer_trace("ENTERING: snd_rcv_match");  }
	// TODO IPV6
	
	// IPV4
	if(addr_cmp(pkt->pkt_info->snd_addr, pair->snd_addr, pkt->pkt_info->ip_addr_size) && addr_cmp(ack->pkt_info->snd_addr, pair->rcv_addr, pkt->pkt_info->ip_addr_size))  { if(TRACE_FLOW)    { sniffer_trace("LEAVING: snd_rcv_match");  }return 1; }
	if(TRACE_FLOW)    { sniffer_trace("LEAVING: snd_rcv_match");  }
	return 0;
}

int is_seq_nr_lower(packet_list* pkt, packet_list* ack)
{
	if(pkt->pkt_info->chunk->seq_nr < ack->pkt_info->chunk->ack_nr)
		return 1;
	return 0;
}

int is_seq_nr_lower_or_equal(packet_list* pkt, unsigned int sack)
{
	if(pkt->pkt_info->chunk->seq_nr <= sack)
		return 1;
	return 0;
}

/**********************************************************************/
/* - Statistics -                                                     */
/**********************************************************************/

void print_statistics()
{
	if(TRACE_FLOW)    { sniffer_trace("ENTERING: print_statistics");  }
	print_double_bar();
	printf("\n    NETWORK STATISTICS");
	print_double_bar();
	print_double_bar();
	printf("\n%20s%20s%10s%10s%10s%10s", "snd", "rcv", "srtt", "jitt", "loss", "rate");
	snd_rcv_pair* tail = pair_list;
	while(tail != NULL)
	{
		printf("\n%20s%20s%10.2f%10.2f%10d%10d", tail->snd_addr, tail->rcv_addr, get_float_value(tail->srtt), get_float_value(tail->jitt), tail->loss, tail->rate);	
		tail = tail->next;
	}
	print_double_bar();
	printf("\n    END");
	print_double_bar();
	if(TRACE_FLOW)    { sniffer_trace("LEAVING: print_statistics");  }
}


/**********************************************************************/
/* - End -                                                            */
/**********************************************************************/
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/**********************************************************************/
/*                                                                    */
/* - PACKET HANDLING -                                                */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Update data -                                                    */
/**********************************************************************/

unsigned int time_diff(int ack_time_stamp, int pkt_time_stamp)  { return ack_time_stamp - pkt_time_stamp;                                         }
unsigned int calculate_new_srtt(int old_srtt, int new_srtt)     { return (((1.0 - ALPHA) * old_srtt) + (ALPHA * new_srtt)) + 0.5;                 }
unsigned int calculate_new_jitt(int old_jitt, int new_srtt)     { return (((1.0 - BETA)  * old_jitt) + (BETA  * abs(new_srtt - old_jitt))) + 0.5; }

/**********************************************************************/
/* - Handle new packet -                                              */
/**********************************************************************/

void set_new_data_for_tcp_pair(snd_rcv_pair* pair, packet_list* ack)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: set_new_srtt"); }
	packet_list* pkt = pair->pkts, * prev_pkt;
	while(pkt != NULL)
	{
		if(snd_rcv_match(pair, pkt, ack) && is_seq_nr_lower(pkt, ack))
		{
			pair->srtt = calculate_new_srtt(pair->srtt, time_diff(ack->time_stamp, pkt->time_stamp));
			pair->jitt = calculate_new_jitt(pair->jitt, time_diff(ack->time_stamp, pkt->time_stamp));
			
			if(pkt == pair->pkts) { remove_acked_packets(pkt); pair->pkts     = NULL; }
			else                  { remove_acked_packets(pkt); prev_pkt->next = NULL; }
			break;			
		}
		prev_pkt = pkt;
		pkt = pkt->next;
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: set_new_srtt"); }
}

void set_new_data_for_sctp_pair(snd_rcv_pair* pair, unsigned int sack, packet_list* ack)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: set_new_srtt_chunk"); }
	packet_list* pkt = pair->pkts, * prev_pkt;
	while(pkt != NULL)
	{
		if(snd_rcv_match(pair, pkt, ack) && is_seq_nr_lower_or_equal(pkt, sack))
		{
			pair->srtt = calculate_new_srtt(pair->srtt, time_diff(ack->time_stamp, pkt->time_stamp));
			pair->jitt = calculate_new_jitt(pair->jitt, time_diff(ack->time_stamp, pkt->time_stamp));

			if(pkt == pair->pkts) { remove_acked_packets(pkt); pair->pkts     = NULL; }
			else                  {	remove_acked_packets(pkt); prev_pkt->next = NULL; }
			break;			
		}
		prev_pkt = pkt;
		pkt = pkt->next;
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: set_new_srtt_chunk"); }
}

/**********************************************************************/
/* - Handle time stamp -                                              */
/**********************************************************************/

long long get_time_stamp()
{
	struct timeval te; 
	gettimeofday(&te, NULL); // get current time
	return te.tv_sec; // seconds
}

void set_time_stamp (packet_list* pkt) 
{
	struct timeval te; 
	gettimeofday(&te, NULL); // get current time
	pkt->time_stamp = 1000000LL * te.tv_sec + te.tv_usec; // in micro	
}

/**********************************************************************/
/* - Process TCP -                                                    */
/**********************************************************************/

int is_tcp_ack(packet_list* pkt) { return pkt->pkt_info->chunk->layer4_type == TCP_ACK; }

void process_tcp_packet(snd_rcv_pair* pair, packet_list* pkt)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: process_tcp_packet"); }
	if(pair != NULL && is_tcp_ack(pkt) && addr_cmp(pkt->pkt_info->snd_addr, pair->rcv_addr, pair->addr_size))
	{
		set_new_data_for_tcp_pair(pair, pkt);
	}
	else if(pair != NULL && addr_cmp(pkt->pkt_info->snd_addr, pair->snd_addr, pair->addr_size))
	{
		add_packet_to_list(pkt, pair);
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: process_tcp_packet"); }
}

/**********************************************************************/
/* - Proecess SCTP -                                                  */
/**********************************************************************/

unsigned int get_sack(chunk_info* chunks)
{
	if(TRACE_FLOW)    { sniffer_trace("ENTERING: get_sack");  }
	while(chunks != NULL)
	{
		if(chunks->layer4_type == CHUNK_SACK) { return chunks->ack_nr; }
		chunks = chunks->next_chunk;
	}
	if(TRACE_FLOW)    { sniffer_trace("LEAVING: get_sack");  }
	return 0;
}

void process_sctp_packet(snd_rcv_pair* pair, packet_list* pkt)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: process_sctp_packet"); }
	if(pair != NULL && addr_cmp(pkt->pkt_info->snd_addr, pair->rcv_addr, pair->addr_size)) 
	{
		unsigned int sack_nr = get_sack(pkt->pkt_info->chunk);
		if(sack_nr != 0) set_new_data_for_sctp_pair(pair, sack_nr, pkt);
	}
	else if(pair != NULL && addr_cmp(pkt->pkt_info->snd_addr, pair->snd_addr, pair->addr_size))
	{
		add_packet_to_list(pkt, pair);
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: process_sctp_packet"); }
}

/**********************************************************************/
/* - End -                                                            */
/**********************************************************************/
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/**********************************************************************/
/*                                                                    */
/* - PROCESS QUERY -                                                  */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Process query -                                                  */
/**********************************************************************/

void process_query(query_addrs* addrs)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: process_query"); }
	ip_addr_ptr rcv_addrs_head = addrs->rcv_addrs, snd_addrs_head = addrs->snd_addrs;
	while(snd_addrs_head != NULL)
	{
		rcv_addrs_head = addrs->rcv_addrs;
		while(rcv_addrs_head != NULL)
		{
			snd_rcv_pair* pair = get_pair(snd_addrs_head->addr, rcv_addrs_head->addr);
			if(pair != NULL) { push_reply_addr_pair(pair->snd_addr, pair->rcv_addr, pair->srtt, pair->jitt, pair->loss, pair->rate); } 
			rcv_addrs_head = rcv_addrs_head->next;
		}
		snd_addrs_head = snd_addrs_head->next;
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: process_query"); }
}

void free_addrs(ip_addr_ptr tail)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: free_addrs"); }
	ip_addr_ptr head;
	while(tail != NULL)
	{ 
		head = tail;
		tail = tail->next;
		free(head);
	}
	if(TRACE_FLOW) { sniffer_trace("LEAVING: free_addrs"); }
}

void free_addrs_struct(query_addrs* addrs)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: free_addrs_struct"); }
	free_addrs(addrs->snd_addrs);
	free_addrs(addrs->rcv_addrs);
	free(addrs);
	if(TRACE_FLOW) { sniffer_trace("LEAVING: free_addrs_struct"); }
}

/**********************************************************************/
/* - Process packet -                                                 */
/**********************************************************************/

int is_valid_protol(packet_list* pkt) 
{ 
	if(pkt->pkt_info->layer4_prot == L4_PROT_TCP || pkt->pkt_info->layer4_prot == L4_PROT_SCTP) { return 1; }
	return 0;
} 

void process(packet_list* pkt)
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: process"); }
	if(!pair_exist(pkt->pkt_info->snd_addr, pkt->pkt_info->rcv_addr, pkt->pkt_info->ip_addr_size)) { add_new_pair(pkt->pkt_info->snd_addr, pkt->pkt_info->rcv_addr, pkt->pkt_info->ip_addr_size); }
	snd_rcv_pair* pair = get_pair(pkt->pkt_info->snd_addr, pkt->pkt_info->rcv_addr);
	if(pkt->pkt_info->chunk != NULL)
	{
		if      (pkt->pkt_info->layer4_prot == L4_PROT_TCP)  { process_tcp_packet(pair, pkt);  }
		else if (pkt->pkt_info->layer4_prot == L4_PROT_SCTP) { process_sctp_packet(pair, pkt); }
	}
	else { free_pkt(pkt); }
	if(TRACE_FLOW) { sniffer_trace("LEAVING: process"); }
}

/**********************************************************************/
/* - Data gathering -                                                 */
/**********************************************************************/

void gather_data()
{
	if(TRACE_FLOW) { sniffer_trace("ENTERING: gather_data"); }
	int sockfd = setup_data_sniffer_socket();
	struct sockaddr saddr;
	socklen_t saddr_size = sizeof(saddr);
	char buffer[BUFFER_SIZE];
	pkt_ptr ppkt = malloc(sizeof(pkt_ptr)); 
	query_addrs* addrs;
	long long last_update = get_time_stamp();
	long long closing_time = get_time_stamp();
			
	while(1)
	{
		addrs = fetch_query(buffer);
		if(addrs != NULL) { 
			printf("\nnew query");
			process_query(addrs);
			free_addrs_struct(addrs);
			commit_reply();
		}
		
        ppkt->packet_size = recvfrom(sockfd , buffer , BUFFER_SIZE , 0 , &saddr , &saddr_size);  		
		if(ppkt->packet_size != -1 && ppkt->packet_size != EAGAIN && ppkt->packet_size != EWOULDBLOCK) 
		{
			packet_list* pkt = malloc(sizeof(packet_list));
			set_time_stamp(pkt);
			ppkt->packet_data = buffer;
			pkt->pkt_info = get_packet_info(ppkt);
			if(is_valid_protol(pkt)) { process(pkt);  }
			else                     { free_pkt(pkt); }
		}
		
		if((get_time_stamp() - last_update) > DATA_IS_OLD)
		{ 
			//printf("\npairs in list:   %d   pairs counted:   %d", pairs, count_pairs()); fflush(stdout);
			//printf("\npackets in list: %d   packets counted: %d", pairs, count_pairs()); fflush(stdout);
			//print_pair_list();
			print_statistics();
			remove_old(get_time_stamp()); 
			last_update = get_time_stamp();
		}
	/*	if((get_time_stamp() - closing_time) > 20)
		{ 
			close(sockfd);
			return ;
		}*/
	}
	if(TRACE_FLOW) { sniffer_trace("  SHUTTING DOWN SNIFFER"); }
    close(sockfd);
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

/**********************************************************************/
/* - Main -                                                           */
/**********************************************************************/

int main()
{	
	//setup_query_listener();
	gather_data();
	return 0;
}

/**********************************************************************/
/* - End -                                                            */
/**********************************************************************/
