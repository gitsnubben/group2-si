#include <stdio.h>
#include <stdlib.h>
#include "query_handler.h"

/**********************************************************************/
/*                                                                    */
/* - DRIVER FOR QUERY HANDLER -                                       */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Testing query creation -                                         */
/**********************************************************************/

void test_socket_query() {
	query_addrs* query = malloc(sizeof(query_addrs));
	printf("\n\n  Adding 0 snd, 0 rcv:\n");
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	printf("\n\n  Adding 1 snd, 0 rcv:\n");
	push_query_snd_addr("1.1.1.1");
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	printf("\n\n  Adding 0 snd, 1 rcv:\n");
	push_query_rcv_addr("2.2.2.2");
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	printf("\n\n  Adding 1 snd, 1 rcv:\n");
	push_query_snd_addr("2.2.2.2");
	push_query_rcv_addr("1.1.1.1");
	push_query_snd_addr("3.3.3.3");
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	printf("\n\n  Adding 2 snd, 2 rcv:\n");
	push_query_snd_addr("2.2.2.2");
	push_query_snd_addr("2.2.2.3");
	push_query_rcv_addr("1.1.1.1");
	push_query_rcv_addr("1.1.1.2");
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	
	printf("\n\n  Adding 32 snd, 32 rcv:\n");
	push_query_snd_addr("200.200.200.201");  push_query_snd_addr("200.200.200.202");
	push_query_snd_addr("200.200.200.203");  push_query_snd_addr("200.200.200.204");
	push_query_snd_addr("200.200.200.205");  push_query_snd_addr("200.200.200.206");
	push_query_snd_addr("200.200.200.207");  push_query_snd_addr("200.200.200.208");
	
	push_query_snd_addr("300.200.200.201");  push_query_snd_addr("300.200.200.202");
	push_query_snd_addr("300.200.200.203");  push_query_snd_addr("300.200.200.204");
	push_query_snd_addr("300.200.200.205");  push_query_snd_addr("300.200.200.206");
	push_query_snd_addr("300.200.200.207");  push_query_snd_addr("300.200.200.208");
	
	push_query_snd_addr("200.200.200.201");  push_query_snd_addr("200.200.200.202");
	push_query_snd_addr("200.200.200.203");  push_query_snd_addr("200.200.200.204");
	push_query_snd_addr("200.200.200.205");  push_query_snd_addr("200.200.200.206");
	push_query_snd_addr("200.200.200.207");  push_query_snd_addr("200.200.200.208");
	
	push_query_snd_addr("300.200.200.201");  push_query_snd_addr("300.200.200.202");
	push_query_snd_addr("300.200.200.203");  push_query_snd_addr("300.200.200.204");
	push_query_snd_addr("300.200.200.205");  push_query_snd_addr("300.200.200.206");
	push_query_snd_addr("300.200.200.207");  push_query_snd_addr("300.200.200.208");
	
	
	push_query_rcv_addr("111.200.200.201");  push_query_rcv_addr("111.200.200.202");
	push_query_rcv_addr("111.200.200.203");  push_query_rcv_addr("111.200.200.204");
	push_query_rcv_addr("111.200.200.205");  push_query_rcv_addr("111.200.200.206");
	push_query_rcv_addr("111.200.200.207");  push_query_rcv_addr("111.200.200.208");
	
	push_query_rcv_addr("444.200.200.201");  push_query_rcv_addr("444.200.200.202");
	push_query_rcv_addr("444.200.200.203");  push_query_rcv_addr("444.200.200.204");
	push_query_rcv_addr("444.200.200.205");  push_query_rcv_addr("444.200.200.206");
	push_query_rcv_addr("444.200.200.207");  push_query_rcv_addr("444.200.200.208");
	
	push_query_rcv_addr("111.200.200.201");  push_query_rcv_addr("111.200.200.202");
	push_query_rcv_addr("111.200.200.203");  push_query_rcv_addr("111.200.200.204");
	push_query_rcv_addr("111.200.200.205");  push_query_rcv_addr("111.200.200.206");
	push_query_rcv_addr("111.200.200.207");  push_query_rcv_addr("111.200.200.208");
	
	push_query_rcv_addr("444.200.200.201");  push_query_rcv_addr("444.200.200.202");
	push_query_rcv_addr("444.200.200.203");  push_query_rcv_addr("444.200.200.204");
	push_query_rcv_addr("444.200.200.205");  push_query_rcv_addr("444.200.200.206");
	push_query_rcv_addr("444.200.200.207");  push_query_rcv_addr("444.200.200.208");
	
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	
	printf("\n\n  Adding 0 snd, 0 rcv:\n");
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	printf("\n\n  Adding 2 snd, 2 rcv:\n");
	push_query_snd_addr("10.1.1.1");
	push_query_snd_addr("11.1.1.1");
	push_query_rcv_addr("20.1.1.1");
	push_query_rcv_addr("21.1.1.1");
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	printf("\n\n  Adding 1 snd, 1 rcv:\n");
	push_query_snd_addr("1.1.1.1");
	push_query_rcv_addr("2.2.2.2");
	print_struct_query(convert_query_to_struct(query, get_current_query()));
	commit_query();
	print_struct_reply(fetch_reply());
	
	close_query_dispatcher();
}

/**********************************************************************/
/* - Testing reply creation -                                         */
/**********************************************************************/

void test_socket_reply() {
	path_traits* path = malloc(sizeof(path_traits));
	
	printf("\n\n  Empty reply:\n");
	commit_reply();
	
	printf("\n\n  Size 1 reply:\n");
	push_reply_addr_pair("10.0.0.3", "170.0.0.4", 0, 1, 2, 3);
	commit_reply();
	path = convert_reply_to_struct(path, get_current_reply());
	
	printf("\n\n  Size 2 reply:\n");
	push_reply_addr_pair("10.0.0.3", "170.0.0.4", 0, 1, 2, 3);
	push_reply_addr_pair("10.0.0.6", "170.0.0.4", 0, 1, 2, 3);
	commit_reply();
	
	printf("\n\n  Size 6 reply:\n");
	push_reply_addr_pair("170.100.100.200", "255.255.255.255", 0, 1, 2, 3);
	push_reply_addr_pair("170.100.100.210", "255.255.255.255", 0, 10, 20, 30);
	push_reply_addr_pair("170.100.100.220", "255.255.255.255", 0, 100, 200, 300);
	push_reply_addr_pair("170.100.100.230", "255.255.255.255", 0, 100, 200, 301);
	push_reply_addr_pair("170.100.100.240", "255.255.255.255", 0, 100, 200, 302);
	push_reply_addr_pair("170.100.100.250", "255.255.255.255", 0, 100, 200, 303);
	commit_reply();
	path = convert_reply_to_struct(path, get_current_reply());
	
	
	printf("\n\n  Size 24 reply (to big):\n");
	push_reply_addr_pair("170.100.100.200", "255.255.255.255", 0, 1, 2, 3);
	push_reply_addr_pair("170.100.100.210", "255.255.255.255", 0, 10, 20, 30);
	push_reply_addr_pair("170.100.100.220", "255.255.255.255", 0, 100, 200, 300);
	push_reply_addr_pair("170.100.100.230", "255.255.255.255", 0, 100, 200, 301);
	push_reply_addr_pair("170.100.100.240", "255.255.255.255", 0, 100, 200, 302);
	push_reply_addr_pair("170.100.100.250", "255.255.255.255", 0, 100, 200, 303);
	push_reply_addr_pair("170.100.100.200", "255.255.255.255", 0, 1, 2, 3);
	push_reply_addr_pair("170.100.100.210", "255.255.255.255", 0, 10, 20, 30);
	push_reply_addr_pair("170.100.100.220", "255.255.255.255", 0, 100, 200, 300);
	push_reply_addr_pair("170.100.100.230", "255.255.255.255", 0, 100, 200, 301);
	push_reply_addr_pair("170.100.100.240", "255.255.255.255", 0, 100, 200, 302);
	push_reply_addr_pair("170.100.100.250", "255.255.255.255", 0, 100, 200, 303);
	push_reply_addr_pair("170.100.100.200", "255.255.255.255", 0, 1, 2, 3);
	push_reply_addr_pair("170.100.100.210", "255.255.255.255", 0, 10, 20, 30);
	push_reply_addr_pair("170.100.100.220", "255.255.255.255", 0, 100, 200, 300);
	push_reply_addr_pair("170.100.100.230", "255.255.255.255", 0, 100, 200, 301);
	push_reply_addr_pair("170.100.100.240", "255.255.255.255", 0, 100, 200, 302);
	push_reply_addr_pair("170.100.100.250", "255.255.255.255", 0, 100, 200, 303);
	push_reply_addr_pair("170.100.100.200", "255.255.255.255", 0, 1, 2, 3);
	push_reply_addr_pair("170.100.100.210", "255.255.255.255", 0, 10, 20, 30);
	push_reply_addr_pair("170.100.100.220", "255.255.255.255", 0, 100, 200, 300);
	push_reply_addr_pair("170.100.100.230", "255.255.255.255", 0, 100, 200, 301);
	push_reply_addr_pair("170.100.100.240", "255.255.255.255", 0, 100, 200, 302);
	push_reply_addr_pair("170.100.100.250", "255.255.255.255", 0, 100, 200, 303);
	commit_reply();
	
	printf("\n\n  Size 1 reply:\n");
	push_reply_addr_pair("1.1.1.1", "2.2.2.2", 90, 90, 90, 90);
	commit_reply();
	
	printf("\n\n  Empty reply:\n");
	commit_reply();
	
	printf("\n\n  Size 2 reply:\n");
	push_reply_addr_pair("1.1.1.1", "2.2.2.2", 9, 9, 9, 9);
	push_reply_addr_pair("10.0.0.6", "170.0.0.4", 0, 1, 2, 3);
	commit_reply();
}

/**********************************************************************/
/* - Main -                                                           */
/**********************************************************************/

int main() {
	test_socket_query();
	//test_socket_reply();
	return 0;
}

/**********************************************************************/
/* - End -                                                            */
/**********************************************************************/
