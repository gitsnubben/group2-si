#ifndef SI_EXP
#define SI_EXP

//General limits, FIELD_LIMIT > IPv6 addr
#define FIELD_LIMIT  20
#define DATA_LIMIT   1000

//Communication ports between sniffer and policy/MAM
#define SNIFFER_PORT 34345
#define POLICY_PORT  43436

//Chars used to delimit in format used by query_handler.c
static const char TERMINATION    = '*' ;
static const char LIST_DELIMITER = '#' ;
static const char ITEM_DELIMITER = '-' ;
static const char NULL_CHAR      = '\0';

typedef struct path_traits {
	char snd_addr[FIELD_LIMIT];
	char rcv_addr[FIELD_LIMIT];
	int norm_srtt;
	int norm_jitt;
	int norm_loss;
	int norm_rate;
	struct path_traits* next;
} path_traits; 

typedef struct ip_addr {
	char addr[FIELD_LIMIT];
	int  addr_size;
	struct ip_addr *next;
} ip_addr;

typedef struct ip_addr* ip_addr_ptr;

typedef struct query_addrs {
	ip_addr_ptr snd_addrs;
	ip_addr_ptr rcv_addrs;
} query_addrs;

//Used everywhere
void trace_log(char* message);

//Public print for query_handler.c
void print_struct_reply(path_traits* path);
void print_struct_query(query_addrs* query);
void print_socket_reply(char* socket_reply);
void print_socket_query(char* socket_reply);

#endif
