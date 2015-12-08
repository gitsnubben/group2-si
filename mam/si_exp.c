#include <stdio.h>
#include "si_exp.h"

//Private print for query_handler.c
void print_std_qh_line();
void print_std_panel(char* info);
void print_addrs(ip_addr_ptr addrs);
void print_query_addrs(query_addrs* addrs);
void print_char_array(char* array, char new_line_char);
void print_string_and_fill_chars(char* msg, int size, char fill);
void print_num_and_fill_chars(int data, int size, char fill);
void print_path_trait(path_traits* p);

//Should be used by every module for trace
void trace_log(char* message) {
	printf("\n  %s", message);
	fflush(stdout);
}

/**********************************************************************/
/*                                                                    */
/* - PRINT FOR QUERY MANAGER -                                        */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Print string data -                                              */
/**********************************************************************/

void print_std_qh_line() { printf("\n  ================================================================="); }

void print_std_panel(char* info) {
	print_std_qh_line();
	printf("\n  %s", info);
	print_std_qh_line();
}

void print_addrs(ip_addr_ptr addrs) {
	ip_addr_ptr probe = addrs;
	while(probe != NULL) { printf("\n  %s", probe->addr); probe = probe->next; }	
}

void print_query_addrs(query_addrs* addrs) {
	print_std_panel("Snd addresses");
	print_addrs(addrs->snd_addrs);
	print_std_panel("Rcv addresses");
	print_addrs(addrs->rcv_addrs);
	print_std_panel("End of query");
}

void print_char_array(char* array, char new_line_char) {
	int index = 0, row_count = 0;
	while(array[index] != TERMINATION && index < DATA_LIMIT && array[index] != NULL_CHAR) {
		if(row_count % 60 == 0) { printf("\n  "); row_count = 0; }
		printf("%c", array[index]); row_count++;
		if(array[index++] == new_line_char) { row_count = 0; }
	}
	printf("%c", array[index]);
}

void print_socket_reply(char* socket_reply) {
	print_std_panel("Socket reply");
	print_char_array(socket_reply, LIST_DELIMITER); 
	print_std_panel("End of socket reply");
}

void print_socket_query(char* socket_reply) {
	print_std_panel("Socket query");
	print_char_array(socket_reply, ITEM_DELIMITER); 
	print_std_panel("End of socket query");
}

/**********************************************************************/
/* - Print struct data -                                              */
/**********************************************************************/

void print_string_and_fill_chars(char* msg, int size, char fill) {
	int count = 0;
	while(msg[count] != NULL_CHAR) { printf("%c", msg[count++]); }
	while(count++ < size)          { printf("%c", fill);         }
}

void print_num_and_fill_chars(int data, int size, char fill) {
	int count = 0;
	printf("%d", data);
	while(data >= 10)   { data /= 10;  count++; } count++;
	while(count < size) { printf(" "); count++; }
}

void print_path_trait(path_traits* p) {
	printf("\n  ");
	print_string_and_fill_chars (p->snd_addr,  18, ' ');
	print_string_and_fill_chars (p->rcv_addr,  18, ' ');
	print_num_and_fill_chars    (p->norm_srtt, 6,  ' ');
	print_num_and_fill_chars    (p->norm_jitt, 6,  ' ');
	print_num_and_fill_chars    (p->norm_loss, 6,  ' ');
	print_num_and_fill_chars    (p->norm_rate, 6,  ' ');
}

void print_struct_reply(path_traits* path) {
	printf("\n  ");
	print_string_and_fill_chars ("Snd address",  18, ' ');
	print_string_and_fill_chars ("Rcv address",  18, ' ');
	print_string_and_fill_chars ("Srtt",         6,  ' ');
	print_string_and_fill_chars ("Jitt",         6,  ' ');
	print_string_and_fill_chars ("Loss",         6,  ' ');
	print_string_and_fill_chars ("Rate",         6,  ' ');
	print_std_panel("Path traits");
	while(path != NULL) {
		print_path_trait(path);
		path = path->next;
	}
	print_std_panel("End of path traits");
}

void print_struct_query(query_addrs* query) {
	print_std_panel("Query");
	printf("\n  ");
	print_string_and_fill_chars ("Snd address",  18, ' ');
	print_string_and_fill_chars ("Rcv address",  18, ' ');
	ip_addr_ptr snd_addrs = query->snd_addrs;
	ip_addr_ptr rcv_addrs = query->rcv_addrs;
	while(snd_addrs != NULL || rcv_addrs != NULL) {
		printf("\n  ");
		if(snd_addrs != NULL) { print_string_and_fill_chars(snd_addrs->addr, 18, ' '); snd_addrs = snd_addrs->next; }
		else                  { print_string_and_fill_chars(""             , 18, ' ');                              }
		if(rcv_addrs != NULL) { print_string_and_fill_chars(rcv_addrs->addr, 18, ' '); rcv_addrs = rcv_addrs->next; }
		else                  { print_string_and_fill_chars(""             , 18, ' ');                              }
	}
	print_std_panel("End of query"); fflush(stdout);
}

/**********************************************************************/
/* - END -                                                            */
/**********************************************************************/
