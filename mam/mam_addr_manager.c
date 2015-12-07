/** NOTES/NEED TO BE FIXED
 * 
 * when calling delete_state() with an empty list we get an "ERROR: fd" which is not an error"
 * 
 * 
 * */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>     
#include <fcntl.h>
#include <limits.h>
#include "mam_addr_manager.h"


/**********************************************************************/
/* - Prototypes -                                                     */
/**********************************************************************/

#ifndef MAM_ADDR_MANAGER_PROT
#define MAM_ADDR_MANAGER_PROT

char* get_mem_name();
char* get_semaphore_name();
char* get_index_name();
char* get_prefix();
data_item* get_probe();
int get_first_call();
int get_data_index();
int get_partner_status();
int* get_data_index_ptr();
int* get_partner_status_ptr();
void set_data_index_ptr(int *ptr);
void set_data_index(int index);
void set_first_call(int call);
void set_probe(data_item* probe);
void set_partner_status_ptr(int* ptr);
void set_partner_status(int status);
void increment_index();
char* get_head();

void trace_flow(char* message);
void shm_error(char *error);
void set_item_name();
void debug_item(data_item* item);

void unmap_link(data_item* item);
void unmap_index(int* index);
void unmap_semaphore(int* semaphore);
void increment_name();

data_item* reset_and_get_first();
data_item* get_next(data_item* item);
data_item* get_last();

int open_and_confirm(char* name, int o_flags, int flags);
data_item* standard_item_init(data_item* new_item);
data_item* create_new_item();
void set_item_data(data_item* item, char* snd_addr, char* rcv_addr, int jitt, int loss, int srtt);
void add_item_to_list(data_item* new_item);
data_item* map_existing_link(char* name);

data_link* map_to_ptr(data_item* item);
data_link* add_link_to_list(data_link* item, data_link* head);
int list_contains_addr(addr_link* list, char* addr);

void fill_with_chars(char c, int count);
void printf_std_bar();
void print_list_header();
void print_list_entry(char* snd_addr, char* rcv_addr, int jitt, int loss, long long srtt);
int mam_get_pos_weight(int pos);
unsigned int mam_parse_number_from_char(char* c, int lsb, int msb);
char* mam_make_ipv4_readable(char* readable_addr, char* addr);

void set_snd_addr_for_item(data_item* item, char* snd_addr);
void set_rcv_addr_for_item(data_item* item, char* rcv_addr);
void set_jitt_for_item(data_item* item, int jitt);
void set_loss_for_item(data_item* item, int loss);
void set_srtt_for_item(data_item* item, int srtt);

void setup_index();
void get_index();
void setup_semaphore();
void get_semaphore();

void create_and_add_item_to_list(char* snd_addr, char* rcv_addr, int jitt, int loss, long long srtt);
int remove_item_from_list(char* snd_addr, char* rcv_addr);

void reset_iterator();
data_item* reset_iterator_and_get_first();
data_item* iterate_next();

int get_list_size();
int entry_exists(char* snd_addr, char* rcv_addr,int size);
void print_list();

void setup_state();
void get_state();
void delete_state();

data_item* get_best_loss();
data_item* get_best_srtt();
data_item* get_best_jitt();

data_link* get_subset_by_snd(char* snd_addr);
data_link* get_subset_by_rcv(char* rcv_addr);
data_link* get_subset_by_addr_list(addr_link* snd_list, addr_link* rcv_list);

int  get_subset_size(data_link* list);

data_link* get_link_with_best_loss(data_link* list);
data_link* get_link_with_best_srtt(data_link* list);
data_link* get_link_with_best_jitt(data_link* list);

void print_subset(data_link* list);


#endif

/**********************************************************************/
/* - Global data -                                                    */
/**********************************************************************/

#define TRACE_ITEM_DETAILS 0
#define TRACE_FLOW 0
#define TRACE_ERROR 0

#define FD_ERROR -1
#define HIGHEST_VALUE INT_MAX

int*        DATA_INDEX;
int*        SEMAPHORE;
char*       INDEX_NAME = "/INDEX";
char*       HEAD = "/0";
char*       PREFIX = "/";
char*       SEMAPHORE_NAME = "/SEMAPHORE";
char        MEM_NAME[NAME_SIZE] = {'/', '0'};
int         FIRST_CALL = 1;
data_item*  PROBE = NULL;

data_item* map_existing_link(char* name);
int addrcmp(char* snd_addr, char* rcv_addr, int size);

/**********************************************************************/
/*                                                                    */
/* - PRIVATE FUNCTIONS -                                              */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Wrappers for global data -                                       */
/**********************************************************************/

char* get_mem_name()                  { return MEM_NAME;               }
char* get_semaphore_name()            { return SEMAPHORE_NAME;         } 
char* get_index_name()                { return INDEX_NAME;             }
char* get_prefix()                    { return PREFIX;                 }
data_item* get_probe()                { return PROBE;                  }
int get_first_call()                  { return FIRST_CALL;             }
int get_data_index()                  { return *DATA_INDEX;            }
int get_partner_status()              { return *SEMAPHORE;             }
int* get_data_index_ptr()             { return DATA_INDEX;             }
int* get_partner_status_ptr()         { return SEMAPHORE;              }
void set_data_index_ptr(int *ptr)     { DATA_INDEX = ptr;              }
void set_data_index(int index)        { *DATA_INDEX = index;           }
void set_first_call(int call)         { FIRST_CALL = call;             }
void set_probe(data_item* probe)      { PROBE = probe;                 }
void set_partner_status_ptr(int* ptr) { SEMAPHORE = ptr;               }
void set_partner_status(int status)   { *SEMAPHORE = status;           }
void increment_index()                { *DATA_INDEX = *DATA_INDEX + 1; }
char* get_head()                      { return HEAD;                   }    // PUBLIC


/**********************************************************************/
/* - Private functions -                                              */
/**********************************************************************/

void trace_flow(char* message) { printf("\n  %s", message); fflush(stdout); }

void shm_error(char *error)
{
	printf("\n    ERROR: %s", error);
}

void set_item_name() 
{
	sprintf(get_mem_name(), "%s%d", get_prefix(), get_data_index());
}

void debug_item(data_item* item) {
	printf("\n    NEW ITEM:");
	printf("\n      HAS_NEXT:  %d", item->is_next);
	printf("\n      ITEM_NAME: %s", item->item_name);
	printf("\n      NEXT_NAME: %s", item->next_name);
	printf("\n      SND_ADDR:  %s", item->snd_addr);
	printf("\n      RCV_ADDR:  %s", item->rcv_addr);
	printf("\n      LOSS:      %d", item->loss);
	printf("\n      JITTER:    %d", item->jitt);
	printf("\n      SRTT:      %llu", item->srtt);
}

void unmap_link(data_item* item) 
{
	if (TRACE_FLOW)                               { trace_flow("ENTERING: unmap_link"); }
	char name[NAME_SIZE];
	strcpy(name, item->item_name); 
	if (munmap(item, sizeof(data_item)) != 0)     { shm_error  ("munmap");                }
	if (shm_unlink(name) != 0)                    { shm_error  ("shm_unlink");            }
	if (TRACE_FLOW)                               { trace_flow ("LEAVING: unmap_link");   }
}

void unmap_index(int* index) 
{
	if (TRACE_FLOW)                               { trace_flow ("ENTERING: unmap_index"); }
	if (munmap(index, sizeof(int)) != 0)          { shm_error  ("munmap");                }
	if (shm_unlink(get_index_name()) != 0)        { shm_error  ("shm_unlink");            }
	if (TRACE_FLOW)                               { trace_flow ("LEAVING: unmap_index");  }
}

void unmap_semaphore(int* semaphore) 
{
	if (TRACE_FLOW)                               { trace_flow ("ENTERING: unmap_semaphore"); }
	if (munmap(semaphore, sizeof(int)) != 0)      { shm_error  ("munmap");                }
	if (shm_unlink(get_semaphore_name()) != 0)    { shm_error  ("shm_unlink");            }
	if (TRACE_FLOW)                               { trace_flow ("LEAVING: unmap_semaphore");  }
}

void increment_name() 
{
	increment_index();
}

/**********************************************************************/
/* - Auxiliary to iterator -                                          */
/**********************************************************************/

data_item* reset_and_get_first()
{
	return map_existing_link(get_head());
}

data_item* get_next(data_item* item)
{
	if(item->is_next == 1) { printf("\n get_next");fflush(stdout); return map_existing_link(item->next_name); }
	return NULL;
}

data_item* get_last()
{
	data_item* item = reset_and_get_first();
	while(item != NULL && item->is_next) { fflush(stdout); item = get_next(item); }
	return item;
}

/**********************************************************************/
/* - Auxiliary to add, including setters -                            */
/**********************************************************************/

int open_and_confirm(char* name, int o_flags, int flags) {
	if(TRACE_FLOW)                               { trace_flow("ENTERING: open_and_confirm");   }
	int fd = shm_open(name, o_flags, flags);
	if(TRACE_ERROR && fd == FD_ERROR)            { shm_error("fd");                            }
	if(TRACE_FLOW)                               { trace_flow("LEAVING: open_and_confirm");    }
	return fd;
}

data_item* standard_item_init(data_item* new_item) 
{
	if(TRACE_FLOW)                               { trace_flow("ENTERING: standard_item_init"); }
	new_item->is_next = 0; 
	strcpy(new_item->item_name, get_mem_name());
	if(TRACE_FLOW)                               { trace_flow("LEAVING: standard_item_init");  }
	return new_item;
}   

data_item* create_new_item()
{
	if(TRACE_FLOW) { trace_flow("ENTERING: create_new_item"); }
	set_item_name();
	increment_name();
	int fd = open_and_confirm(get_mem_name(), O_CREAT | O_RDWR, 0666);
	if(ftruncate(fd, sizeof(data_item))) { shm_error("truncate"); }
	data_item* new_item = standard_item_init(mmap(NULL, sizeof(data_item), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)); 
	close(fd);
	if(TRACE_FLOW) { trace_flow("LEAVING: create_new_item"); }
	return new_item;
}

void set_item_data(data_item* item, char* snd_addr, char* rcv_addr, int jitt, int loss, int srtt)
{
	if(strcmp(snd_addr, NO_NEW_ADDR_VALUE)) { memcpy(item->snd_addr, snd_addr, LARGEST_KNOWN_FIELD);}
	if(strcmp(rcv_addr, NO_NEW_ADDR_VALUE)) { memcpy(item->rcv_addr, rcv_addr, LARGEST_KNOWN_FIELD);}
	if(jitt     != NO_NEW_VALUE) 			{ item->jitt     = jitt;   							    }
	if(srtt     != NO_NEW_VALUE) 			{ item->srtt     = srtt;   							    }
	if(loss     != NO_NEW_VALUE) 			{ item->loss     = loss;   							    }
}

int override_item_data(char* snd_addr, char* rcv_addr, int jitt, int loss, long long srtt, int size)
{
	data_item* item = reset_and_get_first();
	while(item != NULL)
	{
		if (addrcmp(item->snd_addr,snd_addr,size) && addrcmp(item->rcv_addr, rcv_addr, size))
		{
			set_item_data(item, NO_NEW_ADDR_VALUE, NO_NEW_ADDR_VALUE, jitt, loss, srtt);
			return 1;
		}
		item = get_next(item);
	}
	return 0;
}

void add_item_to_list(data_item* new_item)
{
	if(TRACE_FLOW) { trace_flow("ENTERING: add_item_to_list"); }
	new_item->is_next = 0;
	strcpy(new_item->next_name, "");
	if(strcmp(get_head(), get_mem_name()) != 0)
	{
		data_item* parent = get_last();
		parent->is_next = 1;
		strcpy(parent->next_name, new_item->item_name);
	}
	if(TRACE_FLOW) { trace_flow("LEAVING: add_item_to_list"); }
}

/**********************************************************************/
/* - Fetch item by name -                                             */
/**********************************************************************/

data_item* map_existing_link(char* name) 
{
	if(TRACE_FLOW) { trace_flow("ENTERING: map_existing_link"); }
	int fd = open_and_confirm(name, O_RDWR, 0);
	if(fd == FD_ERROR) { return NULL; }
	if(ftruncate(fd, sizeof(data_item))) { shm_error("truncate"); }
	data_item* ret = mmap(NULL, sizeof(data_item), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); 
	close(fd);
	if(TRACE_FLOW) { trace_flow("LEAVING: map_existing_link"); }
	return ret; 
}

/**********************************************************************/
/* - Linked list auxiliary -                                          */
/**********************************************************************/

data_link* map_to_ptr(data_item* item) 
{
	data_link* new_link = malloc(sizeof(data_link));
	
	memcpy(new_link->snd_addr, item->snd_addr, LARGEST_KNOWN_FIELD);
	memcpy(new_link->rcv_addr, item->rcv_addr, LARGEST_KNOWN_FIELD); 
	new_link->jitt      = item->jitt;
	new_link->loss      = item->loss;
	new_link->srtt      = item->srtt;
	new_link->next      = NULL;
	return new_link;
}

data_link* add_link_to_list(data_link* item, data_link* head) 
{
	item->next = head;
	return item;
}

int list_contains_addr(addr_link* list, char* addr) 
{
	addr_link*  probe = list;
	while(probe != NULL) 
	{
		if(strcmp(probe->addr, addr) == 0 ) { return 1; }
		probe = probe->next;
	}
	return 0;
}

/**********************************************************************/
/* - Print auxiliary -                                                */
/**********************************************************************/
int mam_get_pos_weight(int pos)
{
	int weight = 1;
	while(pos-- > 0) { weight *= 2; }
	return weight;
}

unsigned int mam_parse_number_from_char(char* c, int lsb, int msb)
{
	//if(TRACE_FLOW) { log_trace("ENTERING: parse_number_from_char"); }
	unsigned int i = 0, limit = msb - lsb, number = 0, c_index = 0;
	while(i <= limit)
	{
		if(i % 8 == 0 && i != 0) { c++; c_index = 0; }
		int c_mask = mam_get_pos_weight(c_index + lsb);
		if((*c & c_mask) == c_mask) { number += mam_get_pos_weight(i); }
		i++; c_index++;
	}
	//if(TRACE_FLOW) { log_trace("LEAVING: parse_number_from_char"); }
	return number;
}

char* mam_make_ipv4_readable(char* readable_addr, char* addr)
{
	sprintf(readable_addr, "%u.%u.%u.%u", 
	                             mam_parse_number_from_char(&addr[0], 0, 7),
	                             mam_parse_number_from_char(&addr[1], 0, 7),
	                             mam_parse_number_from_char(&addr[2], 0, 7),
	                             mam_parse_number_from_char(&addr[3], 0, 7));
	return readable_addr;
}

void fill_with_chars(char c, int count)
{
	while(count-- > 0) { printf("%c", c); }
}

void printf_std_bar()
{
	printf("\n "); 
	fill_with_chars('=', 68);
}

void print_list_header()
{
	printf("\n%18s%18s%11s%11s%11s", "snd_addr", "rcv_addr", "jitter", "loss", "srtt");
}

void print_list_entry(char* snd_addr, char* rcv_addr, int jitt, int loss, long long srtt)
{
	char snd_ipv4[20];
	char rcv_ipv4[20];
	
	printf("\n%18s%18s%11d%11d%11llu", mam_make_ipv4_readable(snd_ipv4, snd_addr), mam_make_ipv4_readable(rcv_ipv4, rcv_addr), jitt, loss, srtt);
}

/**********************************************************************/
/* - Changing single values in item -                                 */
/**********************************************************************/

void set_snd_addr_for_item(data_item* item, char* snd_addr) { set_item_data(item, snd_addr, NO_NEW_ADDR_VALUE, NO_NEW_VALUE, NO_NEW_VALUE, NO_NEW_VALUE); }
void set_rcv_addr_for_item(data_item* item, char* rcv_addr) { set_item_data(item, NO_NEW_ADDR_VALUE, rcv_addr, NO_NEW_VALUE, NO_NEW_VALUE, NO_NEW_VALUE); }
void set_jitt_for_item(data_item* item, int jitt)           { set_item_data(item, NO_NEW_ADDR_VALUE, NO_NEW_ADDR_VALUE, jitt, NO_NEW_VALUE, NO_NEW_VALUE);     }
void set_loss_for_item(data_item* item, int loss)           { set_item_data(item, NO_NEW_ADDR_VALUE, NO_NEW_ADDR_VALUE, NO_NEW_VALUE, loss, NO_NEW_VALUE);     }
void set_srtt_for_item(data_item* item, int srtt)           { set_item_data(item, NO_NEW_ADDR_VALUE, NO_NEW_ADDR_VALUE, NO_NEW_VALUE, NO_NEW_VALUE, srtt);     }

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
/* - PUBLIC FUNCTIONS -                                               */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - State -                                                          */
/**********************************************************************/

void setup_index() 
{
	if(TRACE_FLOW) { trace_flow("ENTERING: setup_index"); }
	int fd = open_and_confirm(get_index_name(), O_CREAT | O_RDWR, 0666);
	if(ftruncate(fd, sizeof(int))) { shm_error("truncate"); }
	set_data_index_ptr(mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)); 
	set_data_index(0);
	close(fd);
	if(TRACE_FLOW) { trace_flow("LEAVING: setup_index"); }
}

void get_index() 
{
	if(TRACE_FLOW) { trace_flow("ENTERING: get_index"); }
	int fd = open_and_confirm(get_index_name(), O_RDWR, 0);
	if(ftruncate(fd, sizeof(int))) { shm_error("truncate"); }
	set_data_index_ptr(mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)); 
	close(fd); 
	if(TRACE_FLOW) { trace_flow("LEAVING: get_index"); }
}

void setup_semaphore()
{
	if(TRACE_FLOW) { trace_flow("ENTERING: setup_semaphore"); }
	int fd = open_and_confirm(get_semaphore_name(), O_CREAT | O_RDWR, 0666);
	if(ftruncate(fd, sizeof(int))) { shm_error("truncate"); }
	set_partner_status_ptr(mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
	set_partner_status(0);
	close(fd);
	if(TRACE_FLOW) { trace_flow("LEAVING: setup_semaphore"); }
}

void get_semaphore() //get_semaphore
{
	if(TRACE_FLOW) { trace_flow("ENTERING: get_sem"); }
	int fd = open_and_confirm(get_semaphore_name(), O_RDWR, 0);
	if(ftruncate(fd, sizeof(int))) { shm_error("truncate"); }
	set_partner_status_ptr(mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)); 
	close(fd); 
	if(TRACE_FLOW) { trace_flow("LEAVING: get_sem"); }
}

/**********************************************************************/
/* - Public utilities -                                               */
/**********************************************************************/

void create_and_add_item_to_list(char* snd_addr, char* rcv_addr, int jitt, int loss, long long srtt)
{
	if(TRACE_FLOW) { trace_flow("ENTERING: create_and_add_item_to_list"); }
	data_item* item = create_new_item();
	set_item_data(item, snd_addr, rcv_addr, jitt, loss, srtt);
	add_item_to_list(item);
	if(TRACE_ITEM_DETAILS) { debug_item(item); }
	if(TRACE_FLOW) { trace_flow("LEAVING: create_and_add_item_to_list"); }
}

int remove_item_from_list(char* snd_addr, char* rcv_addr)
{
	data_item* item = reset_and_get_first(), * prev = item, * target = NULL;
	while(item != NULL)
	{
		if(strcmp(item->snd_addr, snd_addr) == 0 && strcmp(item->rcv_addr, rcv_addr) == 0) //If match, then remove
		{ 
			target = item;
			while(item->is_next) { prev = item; item = get_next(item); }
					
			memcpy(target->snd_addr , item->snd_addr, LARGEST_KNOWN_FIELD);
			memcpy(target->rcv_addr , item->rcv_addr, LARGEST_KNOWN_FIELD);
			target->jitt     = item->jitt;
			target->loss     = item->loss;
			target->srtt     = item->srtt;
			
			prev->is_next = 0;  
			strcpy(prev->next_name, "");
			unmap_link(item);
			set_data_index(get_data_index() - 1);
			return 1;
		}
		prev = item;
		item = get_next(item);
	}
	return 0;
}

/**********************************************************************/
/* - Iterator -                                                       */
/**********************************************************************/

void reset_iterator() { set_probe(map_existing_link(get_head())); }

data_item* reset_iterator_and_get_first() 
{ 
	reset_iterator(); 
	return get_probe(); 
}

data_item* iterate_next()
{
	if(get_probe()->is_next)
	{
		set_probe(map_existing_link(get_probe()->next_name));
		return get_probe();
	}
	return NULL;
}

/**********************************************************************/
/* - Status retreival -                                               */
/**********************************************************************/

int get_list_size()
{
	int size = 0;
	data_item* item = reset_and_get_first();
	while(item != NULL)
	{
		size++;
		item = get_next(item);
	}
	return size;
}
/*
int entry_exists(char* snd_addr, char* rcv_addr) 
{	
	data_item* item = reset_and_get_first();
	while(item != NULL)
	{
		if(strcmp(item->snd_addr, snd_addr) == 0 && strcmp(item->rcv_addr, rcv_addr) == 0 ) { return 1; }
		item = get_next(item);
	}
	return 0;
}*/
int addrcmp(char* snd_addr, char* rcv_addr, int size)
{
	if(TRACE_FLOW) { trace_flow("ENTERING: addrcmp"); }
	int i = 0;
	for(i = 0; i < size; i++)
	{
		if (snd_addr[i] != rcv_addr[i]) { return 0; }
	}
	if(TRACE_FLOW) { trace_flow("Leaving: addrcmp"); }
	return 1;
}

int entry_exists(char* snd_addr, char* rcv_addr, int size) 
{	
	data_item* item = reset_and_get_first();
	char snd[LARGEST_KNOWN_FIELD], rcv[LARGEST_KNOWN_FIELD];
	while(item != NULL)
	{
		memcpy(snd, item->snd_addr, LARGEST_KNOWN_FIELD);
		memcpy(rcv, item->rcv_addr, LARGEST_KNOWN_FIELD);
		if(addrcmp(snd, snd_addr, size) && addrcmp(rcv, rcv_addr, size) ) { return 1; }
		item = get_next(item);
	}
	return 0;
}

/*data_item* get_data_item(char* snd_addr, char* rcv_addr) 
{
	data_item* item = reset_and_get_first();
	while(item != NULL)
	{
		if(strcmp(item->snd_addr, snd_addr) == 0 && strcmp(item->rcv_addr, rcv_addr) == 0 ) { return item; }
		item = get_next(item);
	}
	return NULL;
}*/

void print_list()
{
	if(TRACE_FLOW) { trace_flow("ENTERING: print_list"); }
	data_item* item = reset_and_get_first();
	printf_std_bar();
	print_list_header();
	printf_std_bar();
	while(item != NULL)
	{
		print_list_entry(item->snd_addr, item->rcv_addr, item->jitt, item->loss, item->srtt);
		item = get_next(item);
	}
	printf_std_bar();
	if(TRACE_FLOW) { trace_flow("LEAVING: print_list"); }
}

/**********************************************************************/
/* - Meta functions -                                                 */
/**********************************************************************/

void setup_state()
{
	if(get_first_call()) { setup_index(); setup_semaphore(); set_first_call(0); }
}

void get_state()
{
	if(get_first_call()) { get_index(); get_semaphore(); set_first_call(0); }
}

void delete_state() 
{
	if(TRACE_FLOW) { trace_flow("ENTERING: delete_state"); }
	data_item* item = reset_and_get_first();
	while(item != NULL) 
	{
		data_item* next = get_next(item);
		unmap_link(item);
		item = next;
	}
	unmap_index(get_data_index_ptr());
	unmap_semaphore(get_partner_status_ptr());
	if(TRACE_FLOW) { trace_flow("LEAVING: delete_state"); }
}

/**********************************************************************/
/* - Find -                                                           */
/**********************************************************************/

data_item* get_best_loss()
{
	data_item* item = reset_and_get_first(), * lowest = item;
	while(item != NULL) 
	{
		if(item->loss < lowest->loss) { lowest = item; }
		item = get_next(item);
	}
	return lowest;
}

data_item* get_best_srtt()
{
	data_item* item = reset_and_get_first(), * lowest = item;
	while(item != NULL) 
	{
		if(item->srtt < lowest->srtt) { lowest = item; }
		item = get_next(item);
	}
	return lowest;
}

data_item* get_best_jitt()
{
	data_item* item = reset_and_get_first(), * lowest = item;
	while(item != NULL) 
	{
		if(item->jitt < lowest->jitt) { lowest = item; }
		item = get_next(item);
	}
	return lowest;
}

/**********************************************************************/
/* - End of std public part -                                         */
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
/* - RETREIVING SUBSETS, INCLUDING HELPERS -                          */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Get subset -                                                     */
/**********************************************************************/

data_link* get_subset_by_snd(char* snd_addr)
{
	data_item* item = reset_and_get_first();
	data_link* head = NULL;
	while(item != NULL) 
	{
		if(strcmp(item->snd_addr, snd_addr) == 0) { head = add_link_to_list(map_to_ptr(item), head); }
		item = get_next(item);
	}
	return head;
}

data_link* get_subset_by_rcv(char* rcv_addr)
{
	data_item* item = reset_and_get_first();
	data_link* head = NULL;
	while(item != NULL) 
	{
		if(strcmp(item->rcv_addr, rcv_addr) == 0) { head = add_link_to_list(map_to_ptr(item), head); }
		item = get_next(item);
	}
	return head;
}

data_link* get_subset_by_addr_list(addr_link* snd_list, addr_link* rcv_list)
{
	data_item* item = reset_and_get_first();
	data_link* head = NULL;
	while(item != NULL) 
	{
		if(list_contains_addr(snd_list, item->snd_addr) && list_contains_addr(rcv_list, item->rcv_addr)) 
		{ 
			head = add_link_to_list(map_to_ptr(item), head); 
		}
		item = get_next(item);
	}
	return head;	
}

/**********************************************************************/
/* - Get subset status -                                              */
/**********************************************************************/

int  get_subset_size(data_link* list)
{
	if(list != NULL) { return 1 + get_subset_size(list->next); }
	return 0;
}

/**********************************************************************/
/* - Find -                                                           */
/**********************************************************************/

data_link* get_link_with_best_loss(data_link* list)
{
	data_link* probe = list, * ret = list;
	while(probe != NULL) 
	{
		if(probe->loss < ret->loss) { ret = probe; }
		probe = probe->next;
	}
	return ret;
}

data_link* get_link_with_best_srtt(data_link* list)
{
	data_link* probe = list, * ret = list;
	while(probe != NULL) 
	{
		if(probe->srtt < ret->srtt) { ret = probe; }
		probe = probe->next;
	}
	return ret;	
}

data_link* get_link_with_best_jitt(data_link* list)
{
	data_link* probe = list, * ret = list;
	while(probe != NULL) 
	{
		if(probe->jitt < ret->jitt) { ret = probe; }
		probe = probe->next;
	}
	return ret;	
}

/**********************************************************************/
/* - Print given subset -                                             */
/**********************************************************************/

void print_subset(data_link* list)
{
	printf_std_bar();
	print_list_header();
	printf_std_bar();
	data_link* probe = list;
	while(probe != NULL) 
	{
		print_list_entry(probe->snd_addr, probe->rcv_addr, probe->jitt, probe->loss, probe->srtt);
		probe = probe->next;
	}
	printf_std_bar();
}

/**********************************************************************/
/* - End -                                                            */
/**********************************************************************/
