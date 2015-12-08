#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "query_handler.h"

#define TRACE_SOCKET_DATA 1
#define TRACE_ERRORS      1

query_addrs policy_addrs;

void parse_addr_from_data(ip_addr_ptr addr);
ip_addr_ptr parse_list_from_data(ip_addr_ptr head);
int add_item_end(char* array, int index);
int add_list_end(char* array, int index);
int add_tentative_list_end(char* array, int index);
int copy_addr_to_array(char* addr, char* array, int index);
int copy_data_to_array(int data, char* array, int index);
int copy_addr_list_to_array(ip_addr_ptr addr, char* array, int index);
void reset_reply();
void reset_query();

/**********************************************************************/
/*                                                                    */
/* - PIVATE FUNCIONS -                                                */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Load into struct auxiliary -                                     */
/**********************************************************************/

int string_to_int(char* string) {
	int number = string[0] - 48, index = 0;
	while(string[++index] != NULL_CHAR) { number = number*10 + string[index] - 48; }
	return number;
}

int skip_index_passed_item_delimiters(char* array, int index) {
	while(array[index] == ITEM_DELIMITER) { index++; }
	return index;
}

int skip_index_passed_list_delimiters(char* array, int index) {
	while(array[index] == LIST_DELIMITER) { index++; }
	return index;
}

int skip_index_passed_delimiters(char* array, int index) {
	while(array[index] == ITEM_DELIMITER || array[index] == LIST_DELIMITER) { index++; }
	return index;
}

int copy_data_from_array(char* dest, char* array, int index) {
	int i = 0;
	index = skip_index_passed_delimiters(array, index);
	while(array[index] != NULL_CHAR && array[index] != ITEM_DELIMITER) { dest[i++] = array[index++]; }
	dest[i] = NULL_CHAR;
	return index;	
}

int copy_num_from_array(int* trait, char* array, int index) {
	int i = 0; char temp[FIELD_LIMIT];
	index = skip_index_passed_delimiters(array, index);
	while(isdigit(array[index])) { temp[i++] = array[index++]; }
	temp[i] = NULL_CHAR;
	*trait = string_to_int(temp);
	return index;	
}

int copy_to_trait_struct_from_array(path_traits* path, char* array, int index) {
	index = copy_data_from_array (path->snd_addr, array, index); 
	index = copy_data_from_array (path->rcv_addr, array, index); 
	index = copy_num_from_array  (&path->norm_srtt, array, index); 
	index = copy_num_from_array  (&path->norm_jitt, array, index);
	index = copy_num_from_array  (&path->norm_loss, array, index);
	index = copy_num_from_array  (&path->norm_rate, array, index);
	return index;	
}

int copy_to_addr_list_struct_from_array(ip_addr_ptr head, char* array, int index) {
	index = skip_index_passed_item_delimiters(array, index);
	if(array[index] != LIST_DELIMITER && array[index] != TERMINATION) {
		index = copy_data_from_array(head->addr, array, index);
		index = skip_index_passed_item_delimiters(array, index);
		ip_addr_ptr last_added = head;
		while(array[index] != NULL_CHAR && array[index] != LIST_DELIMITER && array[index] != TERMINATION) {
			ip_addr_ptr new_tail = malloc(sizeof(ip_addr));
			index = copy_data_from_array(new_tail->addr, array, index);
			last_added->next = new_tail;
			last_added = new_tail;
			new_tail->next = NULL; 
			index = skip_index_passed_item_delimiters(array, index);
		}
	}
	else { head = NULL; }
	return index;
}

path_traits* convert_reply_to_struct(path_traits* head, char* array) {
	head->next = NULL;
	int index = copy_to_trait_struct_from_array(head, array, 0);
	index = skip_index_passed_delimiters(array, index);
	while(array[index] != TERMINATION) {
		path_traits* new_head = malloc(sizeof(path_traits)), *temp;
		index = copy_to_trait_struct_from_array(new_head, array, index);
		temp = head;
		head = new_head;
		new_head->next = temp;
		index = skip_index_passed_delimiters(array, index);
	}
	return head;
}

query_addrs* convert_query_to_struct(query_addrs* addrs, char* array) {
	addrs->snd_addrs = NULL;
	addrs->rcv_addrs = NULL;
	int index = 0;
	if(isdigit(array[0])) {
		addrs->snd_addrs = malloc(sizeof(ip_addr));
		index = copy_to_addr_list_struct_from_array(addrs->snd_addrs, array, index);
		index = skip_index_passed_delimiters(array, index);
	}
	index = skip_index_passed_delimiters(array, index);
	if(isdigit(array[index])) {
		addrs->rcv_addrs = malloc(sizeof(ip_addr));
		index = copy_to_addr_list_struct_from_array(addrs->rcv_addrs, array, index);
	}
	return addrs;
}


/**********************************************************************/
/* - Load into array auxiliary -                                      */
/**********************************************************************/

int add_item_end(char* array, int index) {
	array[index++] = ITEM_DELIMITER;
	array[index+0] = TERMINATION;
	array[index+1] = NULL_CHAR;
	return index;	
}

int add_list_end(char* array, int index) {
	array[index++] = LIST_DELIMITER;
	array[index+0] = TERMINATION;
	array[index+1] = NULL_CHAR;
	return index;	
}

int add_tentative_list_end(char* array, int index) {
	array[index+0] = LIST_DELIMITER;
	array[index+1] = TERMINATION;
	array[index+2] = NULL_CHAR;
	return index;	
}

int copy_data_to_array(int data, char* array, int index) {
	sprintf(array + index, "%d%c%c", data, ITEM_DELIMITER, TERMINATION);
	while(array[index] != TERMINATION) { index++; }
	return index;
}

int copy_addr_to_array(char* addr, char* array, int index) {
	int i = 0; 
	while(addr[i] != NULL_CHAR && i < FIELD_LIMIT) { array[index++] = addr[i++]; }
	return add_item_end(array, index);
}

int copy_addr_list_to_array(ip_addr_ptr addr, char* array, int index) {
	ip_addr_ptr probe = addr;
	while(probe != NULL) {
		copy_addr_to_array(probe->addr, array, index);
		probe = probe->next;
	}
	return add_list_end(array, index);
}

/**********************************************************************/
/* - End of private part -                                            */
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
/* - PUBLIC INTERFACE -                                               */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Easy Query -                                                     */
/**********************************************************************/

char query_to_send[DATA_LIMIT];
int  query_index = 0, adding_snd = 1;

void reset_query() { query_index = 0; adding_snd = 1; query_to_send[0] = TERMINATION; }

void push_query_snd_addr(char* addr) {
	if(query_index < DATA_LIMIT - 50) {
		if(adding_snd) {
			query_index = copy_addr_to_array(addr, query_to_send, query_index);
			query_index = add_tentative_list_end(query_to_send, query_index);
		}
		else if(TRACE_ERRORS)  { trace_log("QUERY ENTRY SKIPPED: snd-list is fixed!");  }
	}
	else if(TRACE_ERRORS)      { trace_log("QUERY ENTRY SKIPPED: total query to big!"); }
}

void push_query_rcv_addr(char* addr) {
	if(adding_snd) { adding_snd = 0; query_index = add_list_end(query_to_send, query_index); }
	if(query_index < DATA_LIMIT - 50) {
		query_index = copy_addr_to_array(addr, query_to_send, query_index);
	}
	else if(TRACE_ERRORS) { trace_log("QUERY ENTRY SKIPPED: total query to big!"); }
}

char* get_current_query() { return query_to_send; }

/**********************************************************************/
/* - Easy Reply -                                                     */
/**********************************************************************/

char reply_to_send[DATA_LIMIT];
int  reply_index = 0;

void reset_reply() { reply_index = 0; reply_to_send[0] = TERMINATION; }

void push_reply_addr_pair(char* snd_addr, char* rcv_addr, int srtt, int jitt, int loss, int rate) { 
	if(reply_index < DATA_LIMIT - 100) {
		reply_index = copy_addr_to_array(snd_addr, reply_to_send, reply_index);
		reply_index = copy_addr_to_array(rcv_addr, reply_to_send, reply_index);
		
		reply_index = copy_data_to_array(srtt, reply_to_send, reply_index);
		reply_index = copy_data_to_array(jitt, reply_to_send, reply_index);
		reply_index = copy_data_to_array(loss, reply_to_send, reply_index);
		reply_index = copy_data_to_array(rate, reply_to_send, reply_index);
		
		reply_index =  add_list_end(reply_to_send, reply_index);
	}
	else if(TRACE_ERRORS) { trace_log("REPLY ENTRY SKIPPED: total reply to big!"); }
}

char* get_current_reply() { return reply_to_send; }

/**********************************************************************/
/* - End of non-socket interface -                                    */
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
/* - POLICY SOCKET INTERFACE -                                        */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Global variables for socket interface -                          */
/**********************************************************************/

int policy_sockfd = 0;
struct sockaddr_in policy_addr;
socklen_t policy_addr_len;

int sniffer_sockfd = 0;
struct sockaddr_in sniffer_addr;
char query[DATA_LIMIT];
socklen_t sniffer_addr_len; 

void setup_socket_endpoints() {
	policy_addr_len = (int)sizeof(struct sockaddr_in);
	sniffer_addr_len = (int)sizeof(struct sockaddr_in);
	
	memset(&policy_addr, 0, sizeof(policy_addr));
	policy_addr.sin_family = AF_INET;
	policy_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	policy_addr.sin_port = htons(POLICY_PORT);
		
	memset(&sniffer_addr, 0, sizeof(sniffer_addr));
	sniffer_addr.sin_family = AF_INET;
	sniffer_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	sniffer_addr.sin_port = htons(SNIFFER_PORT);
}

/**********************************************************************/
/* - Policy socket setup & close -                                    */
/**********************************************************************/

void setup_query_dispatcher() {
	policy_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(policy_sockfd < 0) { trace_log("ERROR: socket failed!"); } 
		
	setup_socket_endpoints();
	
	if(bind(policy_sockfd, (struct sockaddr *)&policy_addr, policy_addr_len) < 0) { trace_log("ERROR: bind failed!"); }
}

void close_query_dispatcher() { close(policy_sockfd); }

/**********************************************************************/
/* - Policy socket outbound interface -                               */
/**********************************************************************/

void commit_query(char* query) { 
	if(policy_sockfd == 0) { setup_query_dispatcher(); }
	if(sendto(policy_sockfd, &query_to_send, query_index + 3, 0, (struct sockaddr *)&sniffer_addr, sniffer_addr_len) < 0) { trace_log("ERROR: send failed!"); }
	reset_query();
}

/**********************************************************************/
/* - Policy socket inbound interface -                                */
/**********************************************************************/

path_traits* fetch_reply(char* query) {
	char reply[DATA_LIMIT];
	recvfrom(policy_sockfd, reply, DATA_LIMIT, 0, (struct sockaddr *)&sniffer_addr, &sniffer_addr_len);
	return convert_reply_to_struct(malloc(sizeof(path_traits)), reply);
}

/**********************************************************************/
/*                                                                    */
/* - SNIFFER SOCKET INTERFACE -                                       */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Sniffer socket setup & close -                                   */
/**********************************************************************/

void setup_query_listener() {
	int flags;	
	sniffer_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sniffer_sockfd < 0) { trace_log("ERROR: socket failed!"); }
	
	flags = fcntl(sniffer_sockfd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(sniffer_sockfd, F_SETFL, flags); 
	
	setup_socket_endpoints();
	
	if(bind(sniffer_sockfd, (struct sockaddr *)&sniffer_addr, sniffer_addr_len) < 0) { trace_log("ERROR: bind failed!"); } 
}

void close_query_listener() { close(sniffer_sockfd); }

/**********************************************************************/
/* - Sniffer socket inbound interface -                               */
/**********************************************************************/

query_addrs* fetch_query() { 
	if(sniffer_sockfd == 0) { setup_query_listener(); }
	int recv = recvfrom(sniffer_sockfd, query, DATA_LIMIT, 0, (struct sockaddr *)&policy_addr, &policy_addr_len);
	if(recv > 0) { 
		return convert_query_to_struct(malloc(sizeof(query_addrs)), query);
	}
	return NULL;
}

/**********************************************************************/
/* - Sniffer socket outbound interface -                              */
/**********************************************************************/

void commit_reply() { 
	if(sniffer_sockfd == 0) { setup_query_listener(); }
	if(sendto(sniffer_sockfd, &reply_to_send, reply_index + 3, 0, (struct sockaddr *)&policy_addr,  policy_addr_len) < 0) { trace_log("ERROR: send failed!"); }
	reset_reply();
}

/**********************************************************************/
/* - End -                                                            */
/**********************************************************************/
