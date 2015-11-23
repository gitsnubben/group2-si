#ifndef MAM_ADDR_MANAGER
#define MAM_ADDR_MANAGER

#define NAME_SIZE 15
#define NO_NEW_VALUE -1
#define NO_NEW_ADDR_VALUE "-1"
#define NO_VALUE -1

#define LARGEST_KNOWN_FIELD 20

//Used internally; linking via shared memory mapping
typedef struct data_item {
	char snd_addr[LARGEST_KNOWN_FIELD];
	char rcv_addr[LARGEST_KNOWN_FIELD];
	int jitt;
	int loss;
	int srtt;
	char next_name[NAME_SIZE];  //Name of child entry, if is_next
	char item_name[NAME_SIZE];  //Name of entry itself
	int is_next;
} data_item;


//Used externally; linking via pointers
typedef struct data_link {
	char snd_addr[LARGEST_KNOWN_FIELD];
	char rcv_addr[LARGEST_KNOWN_FIELD];
	int jitt;
	int loss;
	int srtt;
	struct data_link* next; 
} data_link;


//Used as parameter when retreiving subset
typedef struct addr_link {
	char addr[LARGEST_KNOWN_FIELD];
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
void create_and_add_item_to_list (char* snd_addr, char* rcv_addr, int jitt, int loss, int srtt);
void add_item_to_list            (data_item* new_item);
int  remove_item_from_list       (char* snd_addr, char* rcv_addr);
//data_item* get_data_item         (char* snd_addr, char* rcv_addr);
int override_item_data(char* snd_addr, char* rcv_addr, int jitt, int loss, int srtt, int size);


//Used to get status of entire shared list
data_item* get_best_loss ();  
data_item* get_best_srtt ();  
data_item* get_best_jitt ();
void       print_list    ();  
int        get_list_size ();
int        entry_exists  (char* snd_addr, char* rcv_addr, int size);  


//Used to get subset, and status of given subset
data_link* get_subset_by_snd       (char* snd_addr);
data_link* get_subset_by_rcv       (char* rcv_addr);
data_link* get_subset_by_addr_list (addr_link* snd_list, addr_link* rcv_list);
data_link* get_link_with_best_loss (data_link* list);  
data_link* get_link_with_best_srtt (data_link* list);  
data_link* get_link_with_best_jitt (data_link* list);
void       print_subset            (data_link* list);
int        get_subset_size         (data_link* list);   


#endif
