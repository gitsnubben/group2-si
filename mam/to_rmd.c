#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include "si_exp.h"


int main() {
	int sockfd, query_size = 0, flags;
	
	socklen_t clientLenght;   //(int)sizeof(struct sockaddr_in)
	clientLenght = (int)sizeof(struct sockaddr_in);
	char query[DATA_LIMIT];
	struct sockaddr_in server;
	struct sockaddr_in client;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockfd < 0) { trace_log("ERROR: socket failed!"); }
	
	flags = fcntl(sockfd, F_GETFL); // NON BLOCKING STUFF
	flags |= O_NONBLOCK;
	fcntl(sockfd, F_SETFL, flags); 
		
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(SNIFFER_PORT);
	
	if(bind(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) { trace_log("ERROR: bind failed!"); } 
	
	while(query_size <= 0) {
		query_size = recvfrom(sockfd, query, DATA_LIMIT, 0, (struct sockaddr *)&client, &clientLenght);
		printf("1"); fflush(stdout);
	}
	printf("\nquery size: %d msg is: - %s -", query_size, query);
	close(sockfd);
	return 0;
}
