#ifndef QH_DRIVER
#define QH_DRIVER

#include "si_exp.h"

//Interface for easy use by policy
void push_query_snd_addr(char* addr);
void push_query_rcv_addr(char* addr);
void commit_query();
char* get_current_query();
path_traits* fetch_reply();

//Interface for easy use by sniffer
void push_reply_addr_pair(char* snd_addr, char* rcv_addr, int srtt, int jitt, int loss, int rate);
void commit_reply();
char* get_current_reply();
query_addrs* fetch_query();

void close_query_dispatcher(); 
void close_query_listener(); 
void setup_query_listener(); 

path_traits* convert_reply_to_struct(path_traits* paths, char* array);
query_addrs* convert_query_to_struct(query_addrs* addrs, char* array);

#endif
