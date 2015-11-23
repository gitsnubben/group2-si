typedef struct ip_entry *ip_entry_ptr;
typedef struct p_data *p_data_ptr;


typedef struct ip_entry {
	int addr;
	ip_entry_ptr next;
}ip_entry;

typedef struct {
	ip_entry *head;
}ip_list;

typedef struct {
	int data;
	p_data_ptr next;
}p_entry;

typedef struct {
	p_entry *head;
}p_data;

p_data *setup_connection(ip_list *list);
int run_sniffer();
