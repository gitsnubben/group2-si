#include "si_exp.h"

#define PACKET_LIMIT 65536

#define CHUNK_DATA 0
#define CHUNK_SACK 3
#define TCP_DATA 0
#define TCP_ACK 1
#define L4_PROT_TCP 6
#define L4_PROT_SCTP 132

struct packet {
	char* packet_data;
	unsigned int packet_size;
}; 

typedef struct packet* pkt_ptr;

typedef struct header_field {
	char field_data[FIELD_LIMIT];
	int field_size;
} header_field; 

typedef struct chunk_info {
	unsigned short int layer4_type;     //Parsed in gather_tcp_header_info() or gather_sctp_chunk_header_info()
	unsigned int seq_nr;                //Parsed in gather_tcp_header_info() or gather_sctp_chunk_header_info()
	unsigned int ack_nr;                //Parsed in gather_tcp_header_info() or gather_sctp_chunk_header_info()
	unsigned int packet_size;
	unsigned int retain_diff;
	struct chunk_info* next_chunk;
} chunk_info;

typedef struct packet_info {
	unsigned short int ip_version;      //Parsed in gather_L3_header_info()
	char snd_addr[FIELD_LIMIT]; //Parsed in gather_ipv4_header_info() or in gather_ipv6_header_info()
	char rcv_addr[FIELD_LIMIT]; //Parsed in gather_ipv4_header_info() or in gather_ipv6_header_info()
	unsigned short int ip_addr_size;    //Parsed in gather_ipv4_header_info() or in gather_ipv6_header_info()
	unsigned short int layer4_prot;     //Parsed in gather_ipv4_header_info() or in gather_ipv6_header_info() 
	unsigned short int snd_port;        //Parsed in gather_tcp_header_info() or gather_sctp_header_info()
	unsigned short int rcv_port;        //Parsed in gather_tcp_header_info() or gather_sctp_header_info()
	struct chunk_info* chunk;
} packet_info;

typedef struct packet_info* packet_info_ptr;
typedef struct chunk_info* chunk_info_ptr;

packet_info  get_packet_info         (pkt_ptr pkt_arr);
char*        make_ip_readable        (char* redable, char* addr, int size); // does this one even exist?
char*        make_port_readable      (char* readable_port, char* port);
void         print_raw               (char* string, int limit);
pkt_ptr      make_packet_from_string (char* string, int limit);
void         print_packet_info       (packet_info_ptr info);

char* make_ipv4_readable(char* readable_addr, char* addr);
