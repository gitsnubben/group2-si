#define LARGEST_KNOWN_FIELD 20
#define PACKET_LIMIT 65536

struct packet {
	char* packet_data;
	unsigned int packet_size;
}; 

typedef struct packet* pkt_ptr;

typedef struct header_field {
	char field_data[LARGEST_KNOWN_FIELD];
	int field_size;
} header_field; 

typedef struct packet_info {
	char snd_addr[LARGEST_KNOWN_FIELD];
	char rcv_addr[LARGEST_KNOWN_FIELD];
	unsigned short int snd_port;
	unsigned short int rcv_port;
	unsigned int seq_nr;
	unsigned int packet_size;
	int is_ack;
} packet_info;

header_field get_snd_addr(pkt_ptr pkt_arr);
header_field get_rcv_addr(pkt_ptr pkt_arr);
packet_info get_packet_info(pkt_ptr pkt_arr);
//char* make_ip_readable(char* redable, char* addr, int size);
char* make_ipv4_readable(char* readable_addr, char* addr);

void set_ip_header_size  (int size);
unsigned int parse_number_from_char(char* c, int lsb, int msb);
header_field get_ipv4_ihl      (pkt_ptr pkt);
header_field get_ipv4_snd_addr (pkt_ptr pkt);
