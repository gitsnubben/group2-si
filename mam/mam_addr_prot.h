
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
void set_item_data(data_item* item, int snd_addr, int rcv_addr, int jitt, int loss, int srtt);
void add_item_to_list(data_item* new_item);
data_item* map_existing_link(char* name);

data_link* map_to_ptr(data_item* item);
data_link* add_link_to_list(data_link* item, data_link* head);
int list_contains_addr(addr_link* list, unsigned int addr);

void fill_with_chars(char c, int count);
void printf_std_bar();
void print_list_header();
void print_list_entry(unsigned int snd_addr, unsigned int rcv_addr, int jitt, int loss, float srtt);

void set_snd_addr_for_item(data_item* item, int snd_addr);
void set_rcv_addr_for_item(data_item* item, int rcv_addr);
void set_jitt_for_item(data_item* item, int jitt);
void set_loss_for_item(data_item* item, int loss);
void set_srtt_for_item(data_item* item, int srtt);

void setup_index();
void get_index();
void setup_semaphore();
void get_semaphore();

void create_and_add_item_to_list(int snd_addr, int rcv_addr, int jitt, int loss, int srtt);
int remove_item_from_list(unsigned int snd_addr, unsigned int rcv_addr);

void reset_iterator();
data_item* reset_iterator_and_get_first();
data_item* iterate_next();

int get_list_size();
int entry_exists(unsigned int snd_addr, unsigned int rcv_addr);
void print_list();

void setup_state();
void get_state();
void delete_state();

data_item* get_best_loss();
data_item* get_best_srtt();
data_item* get_best_jitt();

data_link* get_subset_by_snd(unsigned int snd_addr);
data_link* get_subset_by_rcv(unsigned int rcv_addr);
data_link* get_subset_by_addr_list(addr_link* snd_list, addr_link* rcv_list);

int  get_subset_size(data_link* list);

data_link* get_link_with_best_loss(data_link* list);
data_link* get_link_with_best_srtt(data_link* list);
data_link* get_link_with_best_jitt(data_link* list);

void print_subset(data_link* list);
