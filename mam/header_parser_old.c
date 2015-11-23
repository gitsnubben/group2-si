#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include "header_parser.h"


#define DAEMONIZE 0            //If daemonize, then no trace (log trace ?)
#define TRACE_FLOW 0           //Only trace if no daemonize
#define TRACE_DETAILS 0        //Only trace if no daemonize
#define TRACE_ERROR 1          //Only trace if no daemonize
#define RUN_DIAGNOSTICS 0      //Will run diagnostics, normally keep off
#define TRACE_MATCH 1          //Will confirm successful diagnostics

typedef struct decomposed_byte {
	int bits[8];
} decomposed_byte;

void run_diagnostics();

void log_trace(char* message) { printf("\n  %s", message); fflush(stdout); } // Declared in mam_addr_manager.c

/**********************************************************************/
/*                                                                    */
/* - DEALING WITH HEADER CONSTANTS -                                  */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Header constants & variables -                                   */
/**********************************************************************/

int LATEST_IP_HEADER_SIZE = 20;

//Ethernet header size, plus offsets to fields
const int ETH_HEADER = 14;

//IP header size, may vary, found at IPV4_LENGHT_OFFSET, or constant 40 if IPv6
/***/ int IP_HEADER = 20;                                              
const int IP_VERSION_OFFSET = 0;      const int IP_VERSION_SIZE = 1;

//IPV4 header size, plus offsets to fields
const int IPV4_HEADER_OPT = 24; 
const int IPV4_IHL_OFFSET = 0;        const int IPV4_IHL_SIZE = 1;  
const int IPV4_LENGTH_OFFSET = 2;     const int IPV4_LENGTH_SIZE = 2; 
const int IPV4_PROT_OFFSET = 9;       const int IPV4_PROT_SIZE = 1;       
const int IPV4_SND_ADDR_OFFSET = 12;  const int IPV4_SND_ADDR_SIZE = 4;
const int IPV4_RCV_ADDR_OFFSET = 16;  const int IPV4_RCV_ADDR_SIZE = 4;

//IPV6 header size, plus offsets to fields
const int IPV6_HEADER_OPT = 40; 
const int IPV6_VERSION_OFFSET = 0;    const int IPV6_VERSION_SIZE = 1;
const int IPV6_LENGTH_OFFSET = 4;     const int IPV6_LENGTH_SIZE = 2;
const int IPV6_PROT_OFFSET = 6;       const int IPV6_PROT_SIZE = 1;
const int IPV6_SND_ADDR_OFFSET = 8;   const int IPV6_SND_ADDR_SIZE = 16;
const int IPV6_RCV_ADDR_OFFSET = 24;  const int IPV6_RCV_ADDR_SIZE = 16;

//TCP header size, plus offsets to fields
/***/ int TCP_HEADER = 20;                                              //May vary, found at TCP_LENGHT_OFFSET
const int TCP_SND_PORT_OFFSET = 0;    const int TCP_SND_PORT_SIZE = 2;
const int TCP_RCV_PORT_OFFSET = 2;    const int TCP_RCV_PORT_SIZE = 2;
const int TCP_SEQ_OFFSET = 4;         const int TCP_SEQ_SIZE = 4;
const int TCP_ACK_OFFSET = 8;         const int TCP_ACK_SIZE = 4;
const int TCP_LENGTH_OFFSET = 12;     const int TCP_LENGTH_SIZE = 1;

//SCTP header size, plus offsets to fields
const int SCTP_COMMON_HEADER = 12;
const int SCTP_SND_PORT_OFFSET = 0;   const int SCTP_SND_PORT_SIZE = 2;
const int SCTP_RCV_PORT_OFFSET = 2;   const int SCTP_RCV_PORT_SIZE = 2;

//SCTP data-chunk header size, plus offsets to fields
/***/ int SCTP_CHUNK_JUMP = 12;                                         //Will vary, there are several chunks to each packet
const int SCTP_DATA_HEADER = 16;
const int SCTP_TYPE_OFFSET = 0;       const int SCTP_TYPE_SIZE = 1;     //Data chunk type = 0
const int SCTP_LENGTH_OFFSET = 3;     const int SCTP_LENGTH_SIZE = 1;   //So one may skip to next chunk
const int SCTP_TSN_OFFSET = 4;        const int SCTP_TSN_SIZE = 4;

const int IP_VER_ST_BIT = 4;
const int IP_VER_LN_BIT = 4;
const int IP_IHL_ST_BIT = 0;
const int IP_IHL_LN_BIT = 4;

/**********************************************************************/
/* - Ottsets and sizes for fields of interest -                       */
/**********************************************************************/

int  ip_end          () { return ETH_HEADER + IP_HEADER;                   }
int  sctp_jump       () { return ETH_HEADER + IP_HEADER + SCTP_CHUNK_JUMP; }
int  get_ipv6_header () { return IPV6_HEADER_OPT;                          }

void set_ip_header_size  (int size) { IP_HEADER = size;       }
void set_tcp_header_size (int size) { TCP_HEADER  = size;     }
void set_sctp_chunk_jump (int size) { SCTP_CHUNK_JUMP = size; }

int st_ip_version()    { return ETH_HEADER + IP_VERSION_OFFSET;    }    int ln_ip_version()    { return IP_VERSION_SIZE;    } 

//Get-functions for IPv4 header fields 
int st_ipv4_ihl()      { return ETH_HEADER + IPV4_IHL_OFFSET;      }    int ln_ipv4_ihl()      { return IPV4_IHL_SIZE;      } 
int st_ipv4_prot()     { return ETH_HEADER + IPV4_PROT_OFFSET;     }    int ln_ipv4_prot()     { return IPV4_PROT_SIZE;     } 
int st_ipv4_length()   { return ETH_HEADER + IPV4_LENGTH_OFFSET;   }    int ln_ipv4_length()   { return IPV4_LENGTH_SIZE;   } 
int st_ipv4_snd_addr() { return ETH_HEADER + IPV4_SND_ADDR_OFFSET; }    int ln_ipv4_snd_addr() { return IPV4_SND_ADDR_SIZE; }  
int st_ipv4_rcv_addr() { return ETH_HEADER + IPV4_RCV_ADDR_OFFSET; }    int ln_ipv4_rcv_addr() { return IPV4_RCV_ADDR_SIZE; } 

//Get-functions for IPv6 header fields 
int st_ipv6_prot()     { return ETH_HEADER + IPV6_PROT_OFFSET;     }    int ln_ipv6_prot()     { return IPV6_PROT_SIZE;     } 
int st_ipv6_length()   { return ETH_HEADER + IPV6_LENGTH_OFFSET;   }    int ln_ipv6_length()   { return IPV6_LENGTH_SIZE;   } 
int st_ipv6_snd_addr() { return ETH_HEADER + IPV6_SND_ADDR_OFFSET; }    int ln_ipv6_snd_addr() { return IPV6_SND_ADDR_SIZE; }
int st_ipv6_rcv_addr() { return ETH_HEADER + IPV6_RCV_ADDR_OFFSET; }    int ln_ipv6_rcv_addr() { return IPV6_RCV_ADDR_SIZE; }

//Get-functions for SCTP header fields
int st_sctp_snd_port() { return ip_end() + SCTP_SND_PORT_OFFSET;   }    int ln_sctp_snd_port() { return SCTP_SND_PORT_SIZE; }  
int st_sctp_rcv_port() { return ip_end() + SCTP_RCV_PORT_OFFSET;   }    int ln_sctp_rcv_port() { return SCTP_RCV_PORT_SIZE; } 

//Get-functions for SCTP header fields in chunks
int st_sctp_type()     { return sctp_jump() + SCTP_TYPE_OFFSET;    }    int ln_sctp_type()     { return SCTP_TYPE_SIZE;     } 
int st_sctp_length()   { return sctp_jump() + SCTP_LENGTH_OFFSET;  }    int ln_sctp_length()   { return SCTP_LENGTH_SIZE;   }
int st_sctp_tsn()      { return sctp_jump() + SCTP_TSN_OFFSET;     }    int ln_sctp_tsn()      { return SCTP_TSN_SIZE;      }

//Get-functions for TCP header fields
int st_tcp_snd_port()  { return ip_end() + TCP_SND_PORT_OFFSET;    }    int ln_tcp_snd_port() { return TCP_SND_PORT_SIZE;   }  
int st_tcp_rcv_port()  { return ip_end() + TCP_RCV_PORT_OFFSET;    }    int ln_tcp_rcv_port() { return TCP_RCV_PORT_SIZE;   } 
int st_tcp_seq()       { return ip_end() + TCP_SEQ_OFFSET;         }    int ln_tcp_seq()      { return TCP_SEQ_SIZE;        }
int st_tcp_ack()       { return ip_end() + TCP_ACK_OFFSET;         }    int ln_tcp_ack()      { return TCP_ACK_SIZE;        } 
int st_tcp_length()    { return ip_end() + TCP_LENGTH_OFFSET;      }    int ln_tcp_length()   { return TCP_LENGTH_SIZE;     }

/**********************************************************************/
/* - End of header constants part -                                   */
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
/* - DEALING WITH POSITION WEIGHTS, BYTES, AND ORDER -                */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Position weight constants -                                      */
/**********************************************************************/

const int P0 = 1;             const int P4 = 16;
const int P1 = 2;             const int P5 = 32;
const int P2 = 4;             const int P6 = 64;
const int P3 = 8;             const int P7 = 128;

/**********************************************************************/
/* - Auxiliary -                                                      */
/**********************************************************************/

int get_pos_weight(int pos)
{
	int weight = 1;
	while(pos-- > 0) { weight *= 2; }
	return weight;
}

void print_decomposed_byte(decomposed_byte b)
{
	printf("\n  BYTE: %d%d%d%d%d%d%d%d", b.bits[0], b.bits[1], b.bits[2], b.bits[3], b.bits[4], b.bits[5], b.bits[6], b.bits[7]);
}

/**********************************************************************/
/* - Reverse byte -                                                   */
/**********************************************************************/

decomposed_byte assemble_bits_into_decomposed_byte(int i0, int i1, int i2, int i3, int i4, int i5, int i6, int i7)
{
	decomposed_byte b;
	b.bits[0] = i0;		b.bits[1] = i1;
	b.bits[2] = i2;		b.bits[3] = i3;
	b.bits[4] = i4;		b.bits[5] = i5;
	b.bits[6] = i6;		b.bits[7] = i7;
	return b;
}

int are_inverse(decomposed_byte b1, decomposed_byte b2)
{
	int i = 0, j = 7;
	while(i < 8) { if(b1.bits[i++] != b2.bits[j--]) { return 0; } }
	return 1;
}

decomposed_byte decompose_byte_into_bits(char byte) 
{
	if(TRACE_FLOW) { log_trace("ENTERING: decompose_byte_into_bits"); }
	decomposed_byte b;
	b.bits[0] = (byte & P0) == P0;        b.bits[4] = (byte & P4) == P4;
	b.bits[1] = (byte & P1) == P1;        b.bits[5] = (byte & P5) == P5;
	b.bits[2] = (byte & P2) == P2;        b.bits[6] = (byte & P6) == P6;
	b.bits[3] = (byte & P3) == P3;        b.bits[7] = (byte & P7) == P7;
	if(TRACE_FLOW) { log_trace("LEAVING: decompose_byte_into_bits"); }
	return b;
}

decomposed_byte reverse_bits(decomposed_byte byte) 
{
	if(TRACE_FLOW)    { log_trace("ENTERING: reverse_bits"); }
	int int0 = byte.bits[0], int1 = byte.bits[1], int2 = byte.bits[2], int3 = byte.bits[3];
	byte.bits[0] = byte.bits[7];      byte.bits[1] = byte.bits[6];          
	byte.bits[2] = byte.bits[5];      byte.bits[3] = byte.bits[4];          	        
	byte.bits[4] = int3;              byte.bits[5] = int2;         
	byte.bits[6] = int1;              byte.bits[7] = int0;
	if(TRACE_FLOW)    { log_trace("LEAVING: reverse_bits");  }
	return byte;
}

char recompose_bits_into_char(decomposed_byte byte) 
{
	if(TRACE_FLOW) { log_trace("ENTERING: recompose_bits_into_char"); }
	char c = 0;
	c += byte.bits[0]*P0;                 c += byte.bits[4]*P4;
	c += byte.bits[1]*P1;                 c += byte.bits[5]*P5;
	c += byte.bits[2]*P2;                 c += byte.bits[6]*P6;
	c += byte.bits[3]*P3;                 c += byte.bits[7]*P7;
	if(TRACE_FLOW) { log_trace("LEAVING: recompose_bits_into_char"); }
	return c;
}

/**********************************************************************/
/* - End of byte part -                                               */
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
/* - DEALING WITH HEADERS AND FIELDS -                                */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Parse fields -                                                   */
/**********************************************************************/

unsigned int parse_number_from_char(char* c, int lsb, int msb)
{
	if(TRACE_FLOW) { log_trace("ENTERING: parse_number_from_char"); }
	unsigned int i = 0, limit = msb - lsb, number = 0, c_index = 0;
	while(i <= limit)																//WHILE HÄR
	{
		if(i % 8 == 0 && i != 0) { c++; c_index = 0; }
		int c_mask = get_pos_weight(c_index + lsb);
		if((*c & c_mask) == c_mask) { number += get_pos_weight(i); }
		i++; c_index++;
	}
	if(TRACE_FLOW) { log_trace("LEAVING: parse_number_from_char"); }
	return number;
}

header_field parse_header_field(pkt_ptr pkt, const int offset, const int length)
{
	if(TRACE_FLOW) { log_trace("ENTERING: parse_header_field"); }
	header_field field; 
	int i = 0;
	while(i < length && (offset+i) < pkt->packet_size) 							
	{ 
		field.field_data[i] = pkt->packet_data[offset + i]; 
		if(TRACE_DETAILS) { printf("\n    CHAR %d IS: '%c' (%u)", i,  field.field_data[i], (unsigned int)field.field_data[i]); }
		i++; 
	}
	field.field_data[i] = '\0'; 
	field.field_size = length;
	if(TRACE_FLOW) { log_trace("LEAVING: parse_header_field"); }
	return field;
} 

/**********************************************************************/
/* - Offset and size  -                                               */
/**********************************************************************/

header_field get_undef_field() { header_field field = { "", 0 }; return field; }

header_field get_ip_version    (pkt_ptr pkt)  { return parse_header_field(pkt, st_ip_version(),    ln_ip_version());    }

header_field get_ipv4_ihl      (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv4_ihl(),      ln_ipv4_ihl());      }
header_field get_ipv4_length   (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv4_length(),   ln_ipv4_length());   }
header_field get_ipv4_prot     (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv4_prot(),     ln_ipv4_prot());     }
header_field get_ipv4_snd_addr (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv4_snd_addr(), ln_ipv4_snd_addr()); }
header_field get_ipv4_rcv_addr (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv4_rcv_addr(), ln_ipv4_rcv_addr()); }

header_field get_ipv6_length   (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv6_length(),   ln_ipv6_length());   }
header_field get_ipv6_prot     (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv6_prot(),     ln_ipv6_prot());     }
header_field get_ipv6_snd_addr (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv6_snd_addr(), ln_ipv6_snd_addr()); }
header_field get_ipv6_rcv_addr (pkt_ptr pkt)  { return parse_header_field(pkt, st_ipv6_rcv_addr(), ln_ipv6_rcv_addr()); }

header_field get_sctp_snd_port (pkt_ptr pkt)  { return parse_header_field(pkt, st_sctp_snd_port(), ln_sctp_snd_port()); }
header_field get_sctp_rcv_port (pkt_ptr pkt)  { return parse_header_field(pkt, st_sctp_rcv_port(), ln_sctp_rcv_port()); }
header_field get_sctp_type     (pkt_ptr pkt)  { return parse_header_field(pkt, st_sctp_type(),     ln_sctp_type());     }
header_field get_sctp_length   (pkt_ptr pkt)  { return parse_header_field(pkt, st_sctp_length(),   ln_sctp_length());   }
header_field get_sctp_tsn      (pkt_ptr pkt)  { return parse_header_field(pkt, st_sctp_tsn(),      ln_sctp_tsn());      }

/**********************************************************************/
/* - Num-get -                                                        */
/**********************************************************************/

unsigned int get_num_ip_version    (pkt_ptr pkt)  { return parse_number_from_char(&get_ip_version(pkt).field_data[0],    4, 7  ); }

unsigned int get_num_ipv4_ihl      (pkt_ptr pkt)  { return parse_number_from_char(&get_ipv4_ihl(pkt).field_data[0],      0, 3  )*4; }
unsigned int get_num_ipv4_length   (pkt_ptr pkt)  { return parse_number_from_char(&get_ipv4_length(pkt).field_data[0],   0, 15 ); } 
unsigned int get_num_ipv4_snd_addr (pkt_ptr pkt)  { return parse_number_from_char(&get_ipv4_snd_addr(pkt).field_data[0], 0, 31 ); } 
unsigned int get_num_ipv4_rcv_addr (pkt_ptr pkt)  { return parse_number_from_char(&get_ipv4_rcv_addr(pkt).field_data[0], 0, 31 ); } 

unsigned int get_num_ipv6_length   (pkt_ptr pkt)  { return parse_number_from_char(&get_ipv6_length(pkt).field_data[0],   0, 15 ); } 
unsigned int get_num_ipv6_snd_addr (pkt_ptr pkt)  { return parse_number_from_char(&get_ipv6_snd_addr(pkt).field_data[0], 0, 127); } 
unsigned int get_num_ipv6_rcv_addr (pkt_ptr pkt)  { return parse_number_from_char(&get_ipv6_rcv_addr(pkt).field_data[0], 0, 127); } 

unsigned int get_num_sctp_length   (pkt_ptr pkt)  { return parse_number_from_char(&get_sctp_length(pkt).field_data[0],   0, 31 ); }
unsigned int get_num_sctp_type     (pkt_ptr pkt)  { return parse_number_from_char(&get_sctp_type(pkt).field_data[0],     0, 7  ); }
unsigned int get_num_sctp_tsn      (pkt_ptr pkt)  { return parse_number_from_char(&get_sctp_tsn(pkt).field_data[0],      0, 31 ); } 
unsigned int get_num_sctp_snd_port (pkt_ptr pkt)  { return parse_number_from_char(&get_sctp_snd_port(pkt).field_data[0], 0, 15 ); }
unsigned int get_num_sctp_rcv_port (pkt_ptr pkt)  { return parse_number_from_char(&get_sctp_rcv_port(pkt).field_data[0], 0, 15 ); }

/**********************************************************************/
/* - SCTP chunk handling-                                             */
/**********************************************************************/

int get_next_sctp_chunk(pkt_ptr pkt)
{
	int jump = sctp_jump();
	set_sctp_chunk_jump(jump + get_num_sctp_length(pkt));
	return jump;
}

int get_next_sctp_data_chunk(pkt_ptr pkt)
{	
	int get_next_i = get_next_sctp_chunk(pkt);
	while(get_num_sctp_type(pkt) != 0){ get_next_i = get_next_sctp_chunk(pkt); }		//WHILE HÄR
	return get_next_i;
}

/**********************************************************************/
/* - End of field part -                                              */
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
/* - Auxiliary to public interface -                                  */
/**********************************************************************/

packet_info gather_data_from_eth_ipv4_sctp_header(pkt_ptr pkt, packet_info info)
{
		if(TRACE_FLOW) { log_trace("ENTERING: gather_data_from_eth_ipv4_sctp_header"); }     
		unsigned int ihl = get_num_ipv4_ihl(pkt);
		set_ip_header_size(ihl);
	    memcpy(info.snd_addr, &get_ipv4_snd_addr(pkt).field_data[0], LARGEST_KNOWN_FIELD);
	    memcpy(info.rcv_addr, &get_ipv4_rcv_addr(pkt).field_data[0], LARGEST_KNOWN_FIELD);
	    info.snd_port = get_num_sctp_snd_port(pkt);
	    info.rcv_port = get_num_sctp_rcv_port(pkt);
	    //seq
	    //ack
	    //size
	    if(TRACE_FLOW) { log_trace("LEAVING: gather_data_from_eth_ipv4_sctp_header"); }    
	    return info;
}

packet_info gather_data_from_eth_ipv6_sctp_header(pkt_ptr pkt, packet_info info)
{
		if(TRACE_FLOW) { log_trace("ENTERING: gather_data_from_eth_ipv6_sctp_header"); } 
		set_ip_header_size(get_ipv6_header());   
	    memcpy(info.snd_addr, &get_ipv6_snd_addr(pkt).field_data[0], LARGEST_KNOWN_FIELD);
	    memcpy(info.rcv_addr, &get_ipv6_rcv_addr(pkt).field_data[0], LARGEST_KNOWN_FIELD);
	    info.snd_port = get_num_sctp_snd_port(pkt);
	    info.rcv_port = get_num_sctp_rcv_port(pkt);
	    //seq
	    //ack
	    //size   
	    if(TRACE_FLOW) { log_trace("LEAVING: gather_data_from_eth_ipv6_sctp_header"); }  
	    return info;	      
}

/**********************************************************************/
/* - Public interface -                                               */
/**********************************************************************/

header_field get_snd_addr(pkt_ptr pkt)
{
	unsigned int ip_version = parse_number_from_char(&get_ip_version(pkt).field_data[0], 4, 7);
	if      (ip_version == 4) { return get_ipv4_snd_addr(pkt);              }
	else if (ip_version == 6) { return get_ipv6_snd_addr(pkt);              }
	if      (TRACE_ERROR)     { log_trace("ERROR: unknown network protocol!"); } 	
	return get_undef_field();
}

header_field get_rcv_addr(pkt_ptr pkt)
{
	unsigned int ip_version = parse_number_from_char(&get_ip_version(pkt).field_data[0], 4, 7);
	if      (ip_version == 4) { return get_ipv4_rcv_addr(pkt);              }
	else if (ip_version == 6) { return get_ipv6_rcv_addr(pkt);              }
	if      (TRACE_ERROR)     { log_trace("ERROR: unknown network protocol!"); } 	
	return get_undef_field();
}

packet_info get_packet_info(pkt_ptr pkt)
{
	if(TRACE_FLOW) { log_trace("ENTERING: get_packet_info"); }
	unsigned int ip_version = get_num_ip_version(pkt);
	packet_info info;
	if      (ip_version == 4) { info = gather_data_from_eth_ipv4_sctp_header(pkt, info); }
	else if (ip_version == 6) { info = gather_data_from_eth_ipv6_sctp_header(pkt, info); }
	if(TRACE_FLOW) { log_trace("LEAVING: get_packet_info"); }
	return info;
}

char* make_ipv4_readable(char* readable_addr, char* addr)
{
	sprintf(readable_addr, "%u.%u.%u.%u", 
	                             parse_number_from_char(&addr[0], 0, 7),
	                             parse_number_from_char(&addr[1], 0, 7),
	                             parse_number_from_char(&addr[2], 0, 7),
	                             parse_number_from_char(&addr[3], 0, 7));
	return readable_addr;
}

char* make_ipv6_readable(char* readable_addr, char* addr)
{
	sprintf(readable_addr, "%x:%x:%x:%x:%x:%x:%x:%x", 
	                             parse_number_from_char(&addr[0],  0, 15),
	                             parse_number_from_char(&addr[2],  0, 15),
	                             parse_number_from_char(&addr[4],  0, 15),
	                             parse_number_from_char(&addr[6],  0, 15),
	                             parse_number_from_char(&addr[8],  0, 15),
	                             parse_number_from_char(&addr[10], 0, 15),
	                             parse_number_from_char(&addr[12], 0, 15),
	                             parse_number_from_char(&addr[14], 0, 15));
	return readable_addr;
}

//int main() { run_diagnostics(); return 0; }

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
/* - DIAGNOSTICS -                                                    */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Setup mock header for testing -                                  */
/**********************************************************************/

#ifndef TEST
#define TEST

#define HEADER_LIMIT 1000

int outcome = 1;

pkt_ptr make_packet_from_string(char* string)
{
	pkt_ptr pkt = malloc(sizeof(pkt_ptr));
	strncpy(pkt->packet_data, string, strlen(string));
	pkt->packet_size = strlen(string);
	return pkt;
}

void add_word_to_packet(char* word, pkt_ptr pkt)
{
	strcat(pkt->packet_data, word);
}

void add_byte_to_packet(int i0, int i1, int i2, int i3, int i4, int i5, int i6, int i7, pkt_ptr pkt)
{
	char byte[1];
	byte[0] = recompose_bits_into_char(assemble_bits_into_decomposed_byte(i0, i1, i2, i3, i4, i5, i6, i7));
	strcat(pkt->packet_data, byte);
}

/**********************************************************************/
/* - Individual headers -                                             */
/**********************************************************************/

void setup_common_eth_header(pkt_ptr pkt) 
{
	add_word_to_packet("EE",   pkt);  add_word_to_packet("EEEE", pkt);
	add_word_to_packet("EEEE", pkt);  add_word_to_packet("EEEE", pkt);
}

void setup_ipv4_header(pkt_ptr pkt) 
{
	add_word_to_packet("EdTT", pkt); //E = 69 = 01000101; IHL = 5, Version = 4
	add_word_to_packet("iioo", pkt); 
	add_word_to_packet("tpHH", pkt); 
	add_word_to_packet("SND4", pkt); 
	add_word_to_packet("RCV4", pkt);
}

void setup_ipv4_header_with_addr1(pkt_ptr pkt)
{
	add_word_to_packet("EdTT", pkt); //E = 69 = 01000101; IHL = 5, Version = 4
	add_word_to_packet("iioo", pkt); 
	add_word_to_packet("tpHH", pkt); 
	add_word_to_packet("ABCD", pkt); //41.42.43.44
	add_word_to_packet("abcd", pkt); //97.98.99.100
}

void setup_ipv6_header_with_addr1(pkt_ptr pkt)
{
	int i;
	add_word_to_packet("etff", pkt); //e = 101 = 01100101; Version = 4
	add_word_to_packet("PPNH", pkt); 
	i = 0; while(i++ < 4) { add_word_to_packet("ABCD", pkt); }
	i = 0; while(i++ < 4) { add_word_to_packet("abcd", pkt); } 
}

void setup_ipv6_header(pkt_ptr pkt)
{
	int i; 
	add_word_to_packet("vtff", pkt); 
	add_word_to_packet("PPNH", pkt); 
	i = 0; while(i++ < 4) { add_word_to_packet("SND6", pkt); }
	i = 0; while(i++ < 4) { add_word_to_packet("RCV6", pkt); }
}

void setup_sctp_common_header(pkt_ptr pkt) 
{
	add_word_to_packet("SPDP", pkt); //01010011 01010000 & 01000100 01010000 = 21328 & 17488 
	add_word_to_packet("vvvv", pkt); 
	add_word_to_packet("cccc", pkt); 
}

void setup_sctp_data_chunk(pkt_ptr pkt) 
{
	add_word_to_packet("0fll", pkt);
	add_word_to_packet("seqn", pkt);
	add_word_to_packet("SISN", pkt);
	add_word_to_packet("pppp", pkt);
	int i = 0; while(i++ < 21) { add_word_to_packet("@@@@", pkt); }
}

void setup_sctp_heartbeat_chunk(pkt_ptr pkt) 
{
	add_word_to_packet("4fll", pkt);
	add_word_to_packet("ppPP", pkt);
	add_word_to_packet("HHHH", pkt);
	int i = 0; while(i++ < 7) { add_word_to_packet("@@@@", pkt); }
}

/**********************************************************************/
/* - Entire headers -                                                 */
/**********************************************************************/

// CHAR 69  = 01000101 When byte 0 in an IP header is set to this, IHL = 5, Version = 4
// CHAR 117 = 01001111 Ip version = 4, IHL = 15*4
// CHAR 141 = 01100001 IP version = 6, NO IHL
// CHAR 192 = 11000000 Useful split, 25/75
// CHAR 240 = 11110000 Useful split, 50/50
// CHAR 252 = 11111100 Useful split, 75/25
void split_bytes_for_eth_ipv4_sctp_mock_header1(pkt_ptr pkt)
{
	pkt->packet_data[ETH_HEADER + 0] = 117 ; //Since this byte is split 50/50, see IPv4 header
	pkt->packet_data[ETH_HEADER + 1] = 252; //Since this byte is split 75/25, see IPv4 header
	pkt->packet_data[ETH_HEADER + 6] = 192; //Since this byte is split 25/75, see IPv4 header
	pkt->packet_data[ip_end() + SCTP_COMMON_HEADER] = '\0';     //Chunk type
	pkt->packet_data[ip_end() + SCTP_COMMON_HEADER + 3] = 'd';  //Chunk length
}

void split_bytes_for_eth_ipv4_sctp_mock_header2(pkt_ptr pkt)
{
	pkt->packet_data[ETH_HEADER + 0] = 240; //Since this byte is split 50/50, see IPv4 header
	pkt->packet_data[ETH_HEADER + 1] = 252; //Since this byte is split 75/25, see IPv4 header
	pkt->packet_data[ETH_HEADER + 6] = 192; //Since this byte is split 25/75, see IPv4 header
	pkt->packet_data[ip_end() + SCTP_COMMON_HEADER] = recompose_bits_into_char(assemble_bits_into_decomposed_byte(0, 0, 0, 0, 0, 1, 0, 0)); //Assembling EOT, i.e. char 4, for chunk type
	pkt->packet_data[ip_end() + SCTP_COMMON_HEADER + 3] = '(';  //Chunk length
}

void split_interesting_bytes_for_IPv6(pkt_ptr pkt)
{
	pkt->packet_data[ETH_HEADER + 0] = 141; //Since this byte is split 50/50, see IPv6 header
	pkt->packet_data[ETH_HEADER + 1] = 240; //Since this byte is split 50/50, see IPv6 header	
}

void setup_eth_ipv4_header_with_addr1(pkt_ptr pkt)
{
	setup_common_eth_header(pkt);
	setup_ipv4_header_with_addr1(pkt);
}

void setup_eth_ipv6_header_with_addr1(pkt_ptr pkt)
{
	setup_common_eth_header(pkt);
	setup_ipv6_header_with_addr1(pkt);
}

void setup_eth_ipv4_sctp_mock_header1(pkt_ptr pkt) 
{
	setup_common_eth_header(pkt); 
	setup_ipv4_header(pkt);
	setup_sctp_common_header(pkt);
	setup_sctp_data_chunk(pkt);
}

void setup_eth_ipv4_sctp_mock_header2(pkt_ptr pkt) 
{
	setup_common_eth_header(pkt); 
	setup_ipv4_header(pkt);
	setup_sctp_common_header(pkt);
	setup_sctp_heartbeat_chunk(pkt);
	setup_sctp_data_chunk(pkt);
}

void setup_eth_ipv6_sctp_mock_header1(pkt_ptr pkt)
{
	setup_common_eth_header(pkt); 
	setup_ipv6_header(pkt);
	setup_sctp_common_header(pkt);
	setup_sctp_data_chunk(pkt);
}

/**********************************************************************/
/* - Printing auxiliary -                                             */
/**********************************************************************/

void print_header(pkt_ptr pkt, char* message)
{
	printf("\n  %s\n      ", message); //Two extra trailing spaces since ETH-header-size % 4 = 2
	int i = 0;
	while(pkt->packet_data[i] != 0 && i < HEADER_LIMIT) 
	{
		if((i + 2) % 4 == 0) { printf("\n    "); }
		printf("%c", pkt->packet_data[i++]);
	}
	printf("\n");
}

/**********************************************************************/
/* - Actual tests -                                                   */
/**********************************************************************/

void test_fetch(header_field result, char* expected)
{
	int res = strcmp(result.field_data, expected);
	
	if     (res != 0 && TRACE_ERROR) { printf("\n  ERROR: expected %s, got %s!\a", expected, result.field_data); outcome = 0; }
	else if(res == 0 && TRACE_MATCH) { printf("\n  MATCH: %s is same as %s!\a",    expected, result.field_data);              }
}

void test_are_inverse(char c1, char c2, int exp)
{
	decomposed_byte b1 = decompose_byte_into_bits(c1), b2 = decompose_byte_into_bits(c2);
	int res = are_inverse(b1, b2);
	
	if      (res != exp)                { printf("\n  ERROR: expected %d, result %d!", exp, res); outcome = 0; }
	else if (TRACE_MATCH && res == exp) { printf("\n  MATCH: expected %d, result %d!", exp, res);              }
	if(TRACE_MATCH || res != exp)
	{
		print_decomposed_byte(b1); 
		print_decomposed_byte(b2);
	}
} 

void test_reverse_byte(char byte)
{
	decomposed_byte std_byte = decompose_byte_into_bits(byte), rev_byte = reverse_bits(std_byte);
	if(!are_inverse(rev_byte, std_byte)) 
	{ 
		printf("\n  ERROR: "); 
		print_decomposed_byte(std_byte); 
		print_decomposed_byte(rev_byte); 
		outcome = 0; 
	}
	else if(TRACE_MATCH && are_inverse(rev_byte, std_byte)) 
	{
		printf("\n  MATCH: "); 
		print_decomposed_byte(std_byte); 
		print_decomposed_byte(rev_byte); 
	}
} 

void test_get_pos_weight(int pos, int exp)
{
	if(exp != get_pos_weight(pos)) { printf("\n  ERROR: weight of %d is %d! Should be %d", pos, get_pos_weight(pos), exp); outcome = 0; }
	else if(TRACE_MATCH)           { printf("\n  MATCH: weight of %d is %d; expected %d", pos, get_pos_weight(pos), exp);               }   
}

void test_de_recompose(char c, int index)
{
	decomposed_byte b = decompose_byte_into_bits(c);
	int sum = 0, j = 0;
	while(j < 8) { sum += b.bits[j++]; }
	char r = recompose_bits_into_char(b);
	
	if      (b.bits[index] != 1) { printf("\n  ERROR: failed to detect 1 at position %d for char %d!", index, c);  }
	if      (sum != 1 )          { printf("\n  ERROR: should be a single 1 while there are %d", sum); outcome = 0; }
	else if (TRACE_MATCH)        { printf("\n  MATCH: detected 1 at position %d for char %d", index, c);           }
	if      (r != c )            { printf("\n  ERROR: recomposed %d into %d!", c, r); outcome = 0;                 }
	else if (TRACE_MATCH)        { printf("\n  MATCH: recomposed %d into %d", c, r);                               }
}

void test_parse_number_from_char(char c, int lsb, int msb, int exp)
{
	int res = parse_number_from_char(&c, lsb, msb);
	
	if      (exp != res ) { printf("\n  ERROR: parsed %d from %d, between %d and %d! Should be %d", res, c, lsb, msb, exp); outcome = 0; }
	else if (TRACE_MATCH) { printf("\n  MATCH: parsed %d from %d, between %d and %d", res, c, lsb, msb);                                 }
}

void test_get_ipv4v6_addr(header_field res, char* exp1, int exp2)
{
	if      (strcmp(exp1, res.field_data) != 0) { printf("\n  ERROR: bad addr %s, exp %s",      res.field_data,  exp1); outcome = 0; }
	else if (exp2 != res.field_size           ) { printf("\n  ERROR: bad addr size %d, exp %d", res.field_size, exp2); outcome = 0;  }
	else if (TRACE_MATCH                      ) { printf("\n  MATCH: addr and size match");                                          }  
}

void test_make_ipv4_readable(header_field f, char* exp)
{
	char res[100]; make_ipv4_readable(res, f.field_data);
	
	if      (strcmp(res, exp) != 0) { printf("\n  ERROR: converted %s to %s, expected %s!", f.field_data, res, exp); outcome = 0; }
	else if (TRACE_MATCH          ) { printf("\n  MATCH: converted %s to %s", f.field_data, res);                                 }
}

void test_make_ipv6_readable(header_field f, char* exp)
{
	char res[100]; make_ipv6_readable(res, f.field_data);
	
	if      (strcmp(res, exp) != 0) { printf("\n  ERROR: converted %s to %s, expected %s!", f.field_data, res, exp); outcome = 0; }
	else if (TRACE_MATCH          ) { printf("\n  MATCH: converted %s to %s", f.field_data, res);                                 }
}

void test_get_packet_info(pkt_ptr pkt)
{
	packet_info new = get_packet_info(pkt);
	if(get_num_ip_version(pkt) == 4)
	{
		set_ip_header_size(get_num_ipv4_ihl(pkt));
		printf("\n  CONVERTED: %s -> %s", &get_ipv4_snd_addr(pkt).field_data[0], new.snd_addr);
		printf("\n  CONVERTED: %s -> %s", &get_ipv4_rcv_addr(pkt).field_data[0], new.rcv_addr);
	}
	else if(get_num_ip_version(pkt) == 6)
	{
		set_ip_header_size(IPV6_HEADER_OPT);
		printf("\n  CONVERTED: %s -> %s", &get_ipv6_snd_addr(pkt).field_data[0], new.snd_addr);
		printf("\n  CONVERTED: %s -> %s", &get_ipv6_rcv_addr(pkt).field_data[0], new.rcv_addr);
	}
	else { printf("\n  ERROR: unknown network protocol (%u)!", get_num_ip_version(pkt)); }
	printf("\n  CONVERTED: %s -> %u", &get_sctp_snd_port(pkt).field_data[0], new.snd_port);
	printf("\n  CONVERTED: %s -> %u", &get_sctp_rcv_port(pkt).field_data[0], new.rcv_port);
}

/**********************************************************************/
/* - Main testing -                                                   */
/**********************************************************************/

void run_diagnostics()
{
	pkt_ptr  eth_ipv4_packet1 = malloc(sizeof(pkt_ptr)); char pkt1[PACKET_LIMIT]; //First chunk is data
	pkt_ptr  eth_ipv4_packet2 = malloc(sizeof(pkt_ptr)); char pkt2[PACKET_LIMIT]; //First chunk is heartbeat 
	pkt_ptr  eth_ipv6_packet1 = malloc(sizeof(pkt_ptr)); char pkt3[PACKET_LIMIT]; 
	pkt_ptr  eth_ipv4_addr    = malloc(sizeof(pkt_ptr)); char pkt4[PACKET_LIMIT]; //Has actual address
	pkt_ptr  eth_ipv6_addr    = malloc(sizeof(pkt_ptr)); char pkt5[PACKET_LIMIT]; //Has actual address
	
	bzero(pkt1, PACKET_LIMIT);   eth_ipv4_packet1->packet_data = pkt1;  eth_ipv4_packet1->packet_size = PACKET_LIMIT; setup_eth_ipv4_sctp_mock_header1(eth_ipv4_packet1);
	bzero(pkt2, PACKET_LIMIT);   eth_ipv4_packet2->packet_data = pkt2;  eth_ipv4_packet2->packet_size = PACKET_LIMIT; setup_eth_ipv4_sctp_mock_header2(eth_ipv4_packet2);
	bzero(pkt3, PACKET_LIMIT);   eth_ipv6_packet1->packet_data = pkt3;  eth_ipv6_packet1->packet_size = PACKET_LIMIT; setup_eth_ipv6_sctp_mock_header1(eth_ipv6_packet1);
	bzero(pkt4, PACKET_LIMIT);   eth_ipv4_addr->packet_data    = pkt4;  eth_ipv4_addr->packet_size    = PACKET_LIMIT; setup_eth_ipv4_header_with_addr1(eth_ipv4_addr);
	bzero(pkt5, PACKET_LIMIT);   eth_ipv6_addr->packet_data    = pkt5;  eth_ipv6_addr->packet_size    = PACKET_LIMIT; setup_eth_ipv6_header_with_addr1(eth_ipv6_addr);
	
	if(TRACE_MATCH) { print_header(eth_ipv4_packet1, "PRINTING: header with eth & IPv4"); }
	if(TRACE_MATCH) { print_header(eth_ipv6_packet1, "PRINTING: header with eth & IPv6"); }
	
	if(TRACE_FLOW) { log_trace("TESTING: number from part of char"); }
	
	test_parse_number_from_char(127, 0, 3, 15);
	test_parse_number_from_char(127, 1, 4, 15);
	test_parse_number_from_char(127, 2, 5, 15);
	test_parse_number_from_char(127, 3, 6, 15);
	test_parse_number_from_char(127, 4, 7, 7 );
	
	test_parse_number_from_char(51,  0, 3, 3 );
	test_parse_number_from_char(51,  1, 4, 9 );
	test_parse_number_from_char(51,  2, 5, 12);
	test_parse_number_from_char(51,  3, 6, 6 );
	test_parse_number_from_char(51,  4, 7, 3 );
	
	if(TRACE_FLOW) { log_trace("TESTING: fields in header with eth & IPv4"); }
	
	set_ip_header_size(parse_number_from_char(&get_ipv4_ihl(eth_ipv4_packet1).field_data[0], 0, 3)*4);
	test_fetch(get_ip_version    (eth_ipv4_packet1), "E"   );
	test_fetch(get_ipv4_ihl      (eth_ipv4_packet1), "E"   );
	test_fetch(get_ipv4_length   (eth_ipv4_packet1), "TT"  );
	test_fetch(get_ipv4_prot     (eth_ipv4_packet1), "p"   );
	test_fetch(get_ipv4_snd_addr (eth_ipv4_packet1), "SND4");
	test_fetch(get_ipv4_rcv_addr (eth_ipv4_packet1), "RCV4");
	
	if(TRACE_FLOW) { log_trace("TESTING: fields in header with eth, IPv4, & SCTP"); }
	
	test_fetch(get_sctp_snd_port (eth_ipv4_packet1), "SP"  );
	test_fetch(get_sctp_rcv_port (eth_ipv4_packet1), "DP"  );
	test_fetch(get_sctp_type     (eth_ipv4_packet1), "0"   );
	test_fetch(get_sctp_length   (eth_ipv4_packet1), "l"   );
	test_fetch(get_sctp_tsn      (eth_ipv4_packet1), "seqn");
	
	if(TRACE_FLOW) { log_trace("TESTING: bit-patterns in header with eth & IPv4"); }
	
	split_bytes_for_eth_ipv4_sctp_mock_header1(eth_ipv4_packet1);
	
	if(TRACE_FLOW) { log_trace("TESTING: test_get_packet_info"); }
	
	test_get_packet_info(eth_ipv4_packet1);

	if(TRACE_FLOW) { log_trace("TESTING: fields in header with eth & IPv6"); }
	
	test_fetch(get_ip_version    (eth_ipv6_packet1), "v"   );
	test_fetch(get_ipv6_length   (eth_ipv6_packet1), "PP"  );
	test_fetch(get_ipv6_prot     (eth_ipv6_packet1), "N"   );
	test_fetch(get_ipv6_snd_addr (eth_ipv6_packet1), "SND6SND6SND6SND6");
	test_fetch(get_ipv6_rcv_addr (eth_ipv6_packet1), "RCV6RCV6RCV6RCV6");
	
	if(TRACE_FLOW) { log_trace("TESTING: bit-patterns in header with eth & IPv6"); }
	
	split_interesting_bytes_for_IPv6(eth_ipv6_packet1);
	
	if(TRACE_FLOW) { log_trace("TESTING: fields in header with eth, IPv4, & SCTP"); }
	
	set_ip_header_size(40);
	test_fetch(get_sctp_snd_port (eth_ipv6_packet1), "SP"  );
	test_fetch(get_sctp_rcv_port (eth_ipv6_packet1), "DP"  );
	test_fetch(get_sctp_type     (eth_ipv6_packet1), "0"   );
	test_fetch(get_sctp_length   (eth_ipv6_packet1), "l"   );
	test_fetch(get_sctp_tsn      (eth_ipv6_packet1), "seqn");
	
	if(TRACE_FLOW) { log_trace("TESTING: bit-patterns in header with eth & IPv6"); }
	
	split_interesting_bytes_for_IPv6(eth_ipv6_packet1);
	
	if(TRACE_FLOW) { log_trace("TESTING: test_get_packet_info"); }
	
	test_get_packet_info(eth_ipv6_packet1);
	
	if(TRACE_FLOW) { log_trace("TESTING: testing reverse function"); }
	
	test_reverse_byte (240);
	test_reverse_byte (252);
	test_reverse_byte (192);
	
	if(TRACE_FLOW) { log_trace("TESTING: testing are_inverse function"); }
	
	test_are_inverse (240, 15,  1);     test_are_inverse (252, 63,  1);
	test_are_inverse (192, 3,   1);     test_are_inverse (192, 11,  0);
	test_are_inverse (192, 15,  0);     test_are_inverse (192, 19,  0);
	test_are_inverse (0,   0,   1);     test_are_inverse (255, 255, 1);
	
	test_are_inverse (255, 254, 0);     test_are_inverse (255, 253, 0);
	test_are_inverse (255, 251, 0);     test_are_inverse (255, 247, 0);
	test_are_inverse (255, 239, 0);     test_are_inverse (255, 223, 0);
	test_are_inverse (255, 191, 0);     test_are_inverse (255, 127, 0);
	
	if(TRACE_FLOW) { log_trace("TESTING: testing get_weight function"); }
	
	test_get_pos_weight (0, 1  );       test_get_pos_weight (1, 2  );
	test_get_pos_weight (2, 4  );       test_get_pos_weight (3, 8  );
	test_get_pos_weight (4, 16 );       test_get_pos_weight (5, 32 );
	test_get_pos_weight (6, 64 );       test_get_pos_weight (7, 128);
	test_get_pos_weight (8, 256);       test_get_pos_weight (9, 512);
	
	if(TRACE_FLOW) { log_trace("TESTING: testing decompose and recompose"); }
	
	test_de_recompose(1,  0);           test_de_recompose(2,   1);
	test_de_recompose(4,  2);           test_de_recompose(8,   3);
	test_de_recompose(16, 4);           test_de_recompose(32,  5);
	test_de_recompose(64, 6);           test_de_recompose(128, 7);
	
	if(TRACE_FLOW) { log_trace("TESTING: verifying weight constants"); }
	
	if (P0 != 1  ) { printf("\n  ERROR: bad constant weight P0!"); outcome = 0; }             
	if (P1 != 2  ) { printf("\n  ERROR: bad constant weight P1!"); outcome = 0; }  
	if (P2 != 4  ) { printf("\n  ERROR: bad constant weight P2!"); outcome = 0; }            
	if (P3 != 8  ) { printf("\n  ERROR: bad constant weight P3!"); outcome = 0; }  
	if (P4 != 16 ) { printf("\n  ERROR: bad constant weight P4!"); outcome = 0; }          
	if (P5 != 32 ) { printf("\n  ERROR: bad constant weight P5!"); outcome = 0; }          
	if (P6 != 64 ) { printf("\n  ERROR: bad constant weight P6!"); outcome = 0; }
	if (P7 != 128) { printf("\n  ERROR: bad constant weight P7!"); outcome = 0; }
	
	if(TRACE_FLOW) { log_trace("TESTING: verifying weight constants"); }
	
	test_fetch(get_ip_version    (eth_ipv4_addr), "E"   );
	test_fetch(get_ipv4_snd_addr (eth_ipv4_addr), "ABCD");
	test_fetch(get_ipv4_rcv_addr (eth_ipv4_addr), "abcd");
	
	if(TRACE_FLOW) { log_trace("TESTING: blind addr fetch"); }
	
	test_get_ipv4v6_addr(get_snd_addr(eth_ipv4_addr), "ABCD"            , 4 );
	test_get_ipv4v6_addr(get_rcv_addr(eth_ipv4_addr), "abcd"            , 4 );
	test_get_ipv4v6_addr(get_snd_addr(eth_ipv6_addr), "ABCDABCDABCDABCD", 16);
	test_get_ipv4v6_addr(get_rcv_addr(eth_ipv6_addr), "abcdabcdabcdabcd", 16);
	
	if(TRACE_FLOW) { log_trace("TESTING: make ipv4 readable"); }
	
	test_make_ipv4_readable(get_ipv4_snd_addr(eth_ipv4_addr), "65.66.67.68" );
	test_make_ipv4_readable(get_ipv4_rcv_addr(eth_ipv4_addr), "97.98.99.100");
	
	if(TRACE_FLOW) { log_trace("TESTING: make ipv6 readable"); }
	
	test_make_ipv6_readable(get_ipv6_snd_addr(eth_ipv6_addr), "4241:4443:4241:4443:4241:4443:4241:4443");
	test_make_ipv6_readable(get_ipv6_rcv_addr(eth_ipv6_addr), "6261:6463:6261:6463:6261:6463:6261:6463");
	
	if(outcome) { printf("\n  Diagnostic passed!\n"      ); }
	else        { printf("\n  Diagnostic FAILED!\n\a\a\a"); }
}

#endif

/**********************************************************************/
/* - End diagnostics -                                                */
/**********************************************************************/
