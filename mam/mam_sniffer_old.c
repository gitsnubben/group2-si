#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include "mam_addr_manager.h"
#include "header_parser.h"

#define TRACE_FLOW 0           //Only trace if no daemonize

#define BUFFER_SIZE 65536

void log_trace(char* message) { printf("\n  %s", message); fflush(stdout); } // Declared in mam_addr_manager.c

/**********************************************************************/
/*                                                                    */
/* - DEALING WITH GATHERING & STATISTICS -                            */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Statistics -                                                     */
/**********************************************************************/


/**********************************************************************/
/* - Data gathering -                                                 */
/**********************************************************************/

void gather_data()
{
	if(TRACE_FLOW) { log_trace("ENTERING: gather_data"); }
	int sockfd, data_size;
	socklen_t saddr_size;
	struct sockaddr saddr;
	char *buffer = (char *)malloc(BUFFER_SIZE);
	
	
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) 
    {
		if(TRACE_FLOW) { log_trace("    ERROR: socket failed!"); }
		exit(0); 
	}
	
	header_field* data;
	while(get_partner_status()) // as long as mam is up we gather data
	{
		saddr_size = sizeof saddr;
        data_size = recvfrom(sockfd , buffer , BUFFER_SIZE , 0 , &saddr , &saddr_size);
        
        // FOR TESTING
        // IP HEADER SIZE
        printf("\n sndaddr size: %d", parse_number_from_char(get_ipv4_ihl(buffer)->field_data[0], 0, 3)*4);
        set_ip_header_size(parse_number_from_char(get_ipv4_ihl(buffer)->field_data[0], 0, 3)*4);
        // GET PROT
        data = get_ipv4_prot(buffer);
        printf("\n PROTOCOL: %d", parse_number_from_char(data->field_data[0], 0, 7)); // 132 = SCTP
        // GET SNDADDR
        data = get_ipv4_snd_addr(buffer);
        printf("\n SND IP: %d.%d.%d.%d", parse_number_from_char(data->field_data[0], 0, 7),
                                         parse_number_from_char(data->field_data[1], 0, 7),
                                         parse_number_from_char(data->field_data[2], 0, 7),
                                         parse_number_from_char(data->field_data[3], 0, 7));  
        // GET RCVADDR
        data = get_ipv4_rcv_addr(buffer);
        printf("\n RCV IP: %d.%d.%d.%d", parse_number_from_char(data->field_data[0], 0, 7),
                                         parse_number_from_char(data->field_data[1], 0, 7),
                                         parse_number_from_char(data->field_data[2], 0, 7),
                                         parse_number_from_char(data->field_data[3], 0, 7));
                                                                
        sleep(1);
        if(data_size < 0 && TRACE_FLOW) { log_trace("\n    ERROR: recvfrom failed!"); }
	}
	
	if(TRACE_FLOW) { log_trace("  SHUTTING DOWN SNIFFER"); }
    close(sockfd);
    delete_state();
    //close_file();
	if(TRACE_FLOW) { log_trace("LEAVING: gather_data"); }
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
	if(TRACE_FLOW) { log_trace("ENTERING: daemonize"); }
	umask(0);                        /* change permissions for newly created files */
	int sid = setsid();
	if(sid < 0) { exit(0); }         /* Setting up new sid                         */
	close(STDIN_FILENO);             /* Close standard IO                          */
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	//open_file();                     /* Open log file                              */
	if(TRACE_FLOW) { log_trace("LEAVING: daemonize"); }
}

void wait_for_mam()
{
	if(TRACE_FLOW) { log_trace("ENTERING: wait_for_mam"); }
	while(!get_partner_status()) { ; }
	if(TRACE_FLOW) { log_trace("LEAVING: wait_for_mam"); }
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
	
	if(RUN_DIAGNOSTICS) { run_diagnostics(); }
	return 0;
}
