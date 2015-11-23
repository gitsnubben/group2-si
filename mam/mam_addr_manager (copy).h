#ifndef MAM_ADDR_MANAGER
#define MAM_ADDR_MANAGER

#define NAME_SIZE 15
#define NO_NEW_VALUE -1
#define NO_VALUE -1

//Used internally; linking via shared memory mapping
typedef struct data_item {
	unsigned int snd_addr;
	unsigned int rcv_addr;
	int jitt;
	int loss;
	int srtt;
	char next_name[NAME_SIZE];  //Name of child entry, if is_next
	char item_name[NAME_SIZE];  //Name of entry itself
	int is_next;
} data_item;


//Used externally; linking via pointers
typedef struct data_link {
	unsigned int snd_addr;
	unsigned int rcv_addr;
	int jitt;
	int loss;
	int srtt;
	struct data_link* next; 
} data_link;


//Used as parameter when retreiving subset
typedef struct addr_link {
	unsigned int addr;
	struct addr_link* next; 
} addr_link;


//Meta functions; setup/delete is to be called by owner first, get by all others
void setup_state();
void get_state();
void delete_state();
void setup_semaphore();
void get_semaphore();
void set_partner_status(int status);
int  get_partner_status();


//Create and modify shared list
void create_and_add_item_to_list (int snd_addr, int rcv_addr, int jitt, int loss, int srtt);
void add_item_to_list            (data_item* new_item);
int  remove_item_from_list       (unsigned int snd_addr, unsigned int rcv_addr);


//Used to get status of entire shared list
data_item* get_best_loss ();  
data_item* get_best_srtt ();  
data_item* get_best_jitt ();
void       print_list    ();  
int        get_list_size ();
int        entry_exists  (unsigned int snd_addr, unsigned int rcv_addr);  


//Used to get subset, and status of given subset
data_link* get_subset_by_snd       (unsigned int snd_addr);
data_link* get_subset_by_rcv       (unsigned int rcv_addr);
data_link* get_subset_by_addr_list (addr_link* snd_list, addr_link* rcv_list);
data_link* get_link_with_best_loss (data_link* list);  
data_link* get_link_with_best_srtt (data_link* list);  
data_link* get_link_with_best_jitt (data_link* list);
void       print_subset            (data_link* list);
int        get_subset_size         (data_link* list);   


#endif
