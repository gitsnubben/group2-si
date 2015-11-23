#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>      
#include <fcntl.h>
#include "mam_addr_manager.h"

int status = 1;
data_link* head;

addr_link snd1;
addr_link snd2;
addr_link rcv1;
addr_link rcv2;

/**********************************************************************/
/* - Test for existance -                                             */
/**********************************************************************/

void test_existance(char* snd_addr, char* rcv_addr, int outcome) 
{
	if(entry_exists(snd_addr, rcv_addr) != outcome && outcome) 
	{ 
		status = 0; 
		printf("\n COULD NOT FIND (%s, %s)!", snd_addr, rcv_addr); 
	} 
	
	if(entry_exists(snd_addr, rcv_addr) != outcome && !outcome) 
	{ 
		status = 0; 
		printf("\n FOUND (%s, %s)!", snd_addr, rcv_addr); 
	} 
}

/**********************************************************************/
/* - Test list size -                                                 */
/**********************************************************************/

void test_list_size(int size) 
{
	if(get_list_size() != size) 
	{ 
		status = 0; 
		printf("\n BAD LIST SIZE: %d\\%d!", get_list_size(), size); 
	} 
}

/**********************************************************************/
/* - Test subset size -                                               */
/**********************************************************************/

void test_subset_size(data_link* subset, int size) 
{
	if(get_subset_size(subset) != size) 
	{ 
		status = 0; 
		printf("\n BAD SUBSET SIZE: %d\\%d!", get_subset_size(subset), size); 
	} 
}

/**********************************************************************/
/* - Test subset attributes -                                         */
/**********************************************************************/

void test_subset_jitt(data_link* subset, int jitt) 
{
	if(get_link_with_best_jitt(subset)->jitt != jitt) 
	{ 
		status = 0; 
		printf("\n UNEXPECTED BEST JITT: %d\\%d!", get_link_with_best_jitt(subset)->jitt, jitt); 
	} 
}

void test_subset_loss(data_link* subset, int loss) 
{
	if(get_link_with_best_loss(subset)->loss != loss) 
	{ 
		status = 0; 
		printf("\n UNEXPECTED BEST LOSS: %d\\%d!", get_link_with_best_loss(subset)->loss, loss); 
	} 
}

void test_subset_srtt(data_link* subset, int srtt) 
{
	if(get_link_with_best_srtt(subset)->srtt != srtt) 
	{ 
		status = 0; 
		printf("\n UNEXPECTED BEST SRTT: %d\\%d!", get_link_with_best_srtt(subset)->srtt, srtt); 
	} 
}

/**********************************************************************/
/* - Test deletion -                                                  */
/**********************************************************************/

void test_deletion(char* snd_addr, char* rcv_addr, int outcome) 
{
	if(remove_item_from_list(snd_addr, rcv_addr) != outcome && outcome)
	{
		status = 0; 
		printf("\n COULD NOT REMOVE (%s, %s)!", snd_addr, rcv_addr);  
	}
	if(remove_item_from_list(snd_addr, rcv_addr) != outcome && !outcome)
	{
		status = 0; 
		printf("\n COULD REMOVE (%s, %s)!", snd_addr, rcv_addr);  
	}
}

/**********************************************************************/
/* - Main -                                                           */
/**********************************************************************/

int main() 
{
	setup_state();
	
	memcpy(snd1.addr,"1000", LARGEST_KNOWN_FIELD);
	snd1.next = &snd2;
	memcpy(snd2.addr , "1001", LARGEST_KNOWN_FIELD);
	
	memcpy(rcv1.addr, "2000", LARGEST_KNOWN_FIELD);
	rcv1.next = &rcv2;
	memcpy(rcv2.addr, "2001", LARGEST_KNOWN_FIELD);

	//Removing non-existing items
	test_deletion("1000", "2002", 0);  test_list_size(0);  
	test_deletion("1000", "2000", 0);  test_list_size(0);  
	test_deletion("1000", "2003", 0);  test_list_size(0);  
	test_deletion("1000", "2001", 0);  test_list_size(0);  
	

	//Adding and removing first-, last-, and middle item
	test_list_size(0);
	
	create_and_add_item_to_list("1000", "2000", 111, 234, 321);   test_list_size(1);
	create_and_add_item_to_list("1000", "2001", 110, 233, 322);   test_list_size(2);
	create_and_add_item_to_list("1000", "2002", 111, 232, 323);   test_list_size(3);
	create_and_add_item_to_list("1000", "2003", 112, 231, 320);   test_list_size(4);
	
	test_existance("1000", "2000", 1);   test_existance("1001", "2000", 0);
	test_existance("1000", "2001", 1);   test_existance("1001", "2001", 0);
	test_existance("1000", "2002", 1);   test_existance("1001", "2002", 0);
	test_existance("1000", "2003", 1);   test_existance("1001", "2003", 0);
	
	print_list();  test_deletion("1000", "2002", 1);  test_list_size(3);  //Removing middle
	print_list();  test_deletion("1000", "2000", 1);  test_list_size(2);  //Removing first
	print_list();  test_deletion("1000", "2003", 1);  test_list_size(1);  //Removing last
	print_list();  test_deletion("1000", "2001", 1);  test_list_size(0);  //Removing first & last
	
	
	//Removing non-existing items
	test_deletion("1000", "2002", 0);  test_list_size(0);  
	test_deletion("1000", "2000", 0);  test_list_size(0);  
	test_deletion("1000", "2003", 0);  test_list_size(0);  
	test_deletion("1000", "2001", 0);  test_list_size(0);  


	//List will now be empty again
	print_list();
	test_list_size(0); 
	test_subset_size(get_subset_by_snd("1000"), 0);  test_subset_size(get_subset_by_rcv("2000"), 0);
	test_subset_size(get_subset_by_snd("1001"), 0);  test_subset_size(get_subset_by_rcv("2001"), 0);
	test_subset_size(get_subset_by_snd("1002"), 0);  test_subset_size(get_subset_by_rcv("2002"), 0);
	test_subset_size(get_subset_by_snd("1003"), 0);  test_subset_size(get_subset_by_rcv("2003"), 0);
	test_subset_size(get_subset_by_snd("1004"), 0);  test_subset_size(get_subset_by_rcv("2004"), 0);
	test_subset_size(get_subset_by_snd("1005"), 0);  test_subset_size(get_subset_by_rcv("2005"), 0);
	test_subset_size(get_subset_by_snd("1006"), 0);  test_subset_size(get_subset_by_rcv("2006"), 0);
	test_subset_size(get_subset_by_snd("1007"), 0);  test_subset_size(get_subset_by_rcv("2007"), 0);
	
	test_existance("1000", "2000", 0);   test_existance("1001", "2000", 0);
	test_existance("1000", "2001", 0);   test_existance("1001", "2001", 0);
	test_existance("1000", "2002", 0);   test_existance("1001", "2002", 0);
	test_existance("1000", "2003", 0);   test_existance("1001", "2003", 0);
	test_existance("1000", "2004", 0);   test_existance("1001", "2004", 0);
	
	test_existance("1002", "2005", 0);   test_existance("1002", "2000", 0);
	test_existance("1003", "2005", 0);   test_existance("1001", "2006", 0);
	test_existance("1004", "2005", 0);   test_existance("1004", "2006", 0);
	test_existance("1005", "2005", 0);   test_existance("1005", "2006", 0);
	test_existance("1006", "2005", 0);   test_existance("1006", "2006", 0);
	
	
	//List will now contain 15 entries
	create_and_add_item_to_list("1000", "2000", 111, 234, 321);
	create_and_add_item_to_list("1000", "2001", 110, 233, 322);
	create_and_add_item_to_list("1000", "2002", 111, 232, 323);
	create_and_add_item_to_list("1000", "2003", 112, 231, 320);
	create_and_add_item_to_list("1000", "2004", 113, 230, 321);
	
	create_and_add_item_to_list("1001","2000", 123, 222, 301);
	create_and_add_item_to_list("1001", "2001", 122, 221, 302);
	create_and_add_item_to_list("1001", "2002", 121, 220, 303);
	create_and_add_item_to_list("1001", "2003", 120, 221, 304);
	create_and_add_item_to_list("1001", "2004", 121, 222, 300);
	
	create_and_add_item_to_list("1002", "2005", 134, 210, 310);
	create_and_add_item_to_list("1003", "2005", 134, 211, 314);
	create_and_add_item_to_list("1004", "2005", 133, 212, 313);
	create_and_add_item_to_list("1005", "2005", 132, 213, 312);
	create_and_add_item_to_list("1006", "2005", 130, 214, 311);

	test_list_size(15); print_list();
	
	head = get_subset_by_snd("1000");  test_subset_jitt(head, 110);  test_subset_loss(head, 230);  test_subset_srtt(head, 320);   print_subset(head);
	head = get_subset_by_snd("1001");  test_subset_jitt(head, 120);  test_subset_loss(head, 220);  test_subset_srtt(head, 300);   print_subset(head); 
	head = get_subset_by_snd("1002");  test_subset_jitt(head, 134);  test_subset_loss(head, 210);  test_subset_srtt(head, 310);   print_subset(head); 
	head = get_subset_by_snd("1003");  test_subset_jitt(head, 134);  test_subset_loss(head, 211);  test_subset_srtt(head, 314);   print_subset(head); 
	head = get_subset_by_snd("1004");  test_subset_jitt(head, 133);  test_subset_loss(head, 212);  test_subset_srtt(head, 313);   print_subset(head); 
	head = get_subset_by_snd("1005");  test_subset_jitt(head, 132);  test_subset_loss(head, 213);  test_subset_srtt(head, 312);   print_subset(head); 
	head = get_subset_by_snd("1006");  test_subset_jitt(head, 130);  test_subset_loss(head, 214);  test_subset_srtt(head, 311);   print_subset(head);

	head = get_subset_by_rcv("2000");  test_subset_jitt(head, 111);  test_subset_loss(head, 222);  test_subset_srtt(head, 301);   print_subset(head);
	head = get_subset_by_rcv("2001");  test_subset_jitt(head, 110);  test_subset_loss(head, 221);  test_subset_srtt(head, 302);   print_subset(head); 
	head = get_subset_by_rcv("2002");  test_subset_jitt(head, 111);  test_subset_loss(head, 220);  test_subset_srtt(head, 303);   print_subset(head); 
	head = get_subset_by_rcv("2003");  test_subset_jitt(head, 112);  test_subset_loss(head, 221);  test_subset_srtt(head, 304);   print_subset(head); 
	head = get_subset_by_rcv("2004");  test_subset_jitt(head, 113);  test_subset_loss(head, 222);  test_subset_srtt(head, 300);   print_subset(head); 
	head = get_subset_by_rcv("2005");  test_subset_jitt(head, 130);  test_subset_loss(head, 210);  test_subset_srtt(head, 310);   print_subset(head); 
	
	print_subset(get_subset_by_rcv("2006"));
	
	printf("\n Combining 1001 - 2000, 2001");         test_subset_size(get_subset_by_addr_list(&snd2, &rcv1), 2);  print_subset(get_subset_by_addr_list(&snd2, &rcv1));      
	printf("\n Combining 1001 - 2001");               test_subset_size(get_subset_by_addr_list(&snd2, &rcv2), 1);  print_subset(get_subset_by_addr_list(&snd2, &rcv2)); 
	printf("\n Combining 1000, 1001 - 2000, 2001");   test_subset_size(get_subset_by_addr_list(&snd1, &rcv1), 4);  print_subset(get_subset_by_addr_list(&snd1, &rcv1));    
	printf("\n Combining 1000, 1001 - 2001");         test_subset_size(get_subset_by_addr_list(&snd1, &rcv2), 2);  print_subset(get_subset_by_addr_list(&snd1, &rcv2)); 
	
	test_subset_size(get_subset_by_snd("1000"), 5);  test_subset_size(get_subset_by_rcv("2000"), 2);
	test_subset_size(get_subset_by_snd("1001"), 5);  test_subset_size(get_subset_by_rcv("2001"), 2);
	test_subset_size(get_subset_by_snd("1002"), 1);  test_subset_size(get_subset_by_rcv("2002"), 2);
	test_subset_size(get_subset_by_snd("1003"), 1);  test_subset_size(get_subset_by_rcv("2003"), 2);
	test_subset_size(get_subset_by_snd("1004"), 1);  test_subset_size(get_subset_by_rcv("2004"), 2);
	test_subset_size(get_subset_by_snd("1005"), 1);  test_subset_size(get_subset_by_rcv("2005"), 5);
	test_subset_size(get_subset_by_snd("1006"), 1);  test_subset_size(get_subset_by_rcv("2006"), 0);
	test_subset_size(get_subset_by_snd("1007"), 0);  test_subset_size(get_subset_by_rcv("2007"), 0);

	test_existance("1000", "2000", 1);   test_existance("1001", "2000", 1);
	test_existance("1000", "2001", 1);   test_existance("1001", "2001", 1);
	test_existance("1000", "2002", 1);   test_existance("1001", "2002", 1);
	test_existance("1000", "2003", 1);   test_existance("1001", "2003", 1);
	test_existance("1000", "2004", 1);   test_existance("1001", "2004", 1);
	
	test_existance("1002", "2005", 1);   test_existance("1002", "2000", 0);
	test_existance("1003", "2005", 1);   test_existance("1001", "2006", 0);
	test_existance("1004", "2005", 1);   test_existance("1004", "2006", 0);
	test_existance("1005", "2005", 1);   test_existance("1005", "2006", 0);
	test_existance("1006", "2005", 1);   test_existance("1006", "2006", 0);

	printf("\n Removing last!");        test_deletion("1006", "2005", 1);  test_list_size(14);  print_list();  //Removing last         
	printf("\n Removing last again!");  test_deletion("1006", "2005", 0);  test_list_size(14);                 //Removing last again
	printf("\n Removing last!");        test_deletion("1005", "2005", 1);  test_list_size(13);  print_list();  //Removing last
	printf("\n Removing last again!");  test_deletion("1005", "2005", 0);  test_list_size(13);                 //Removing last again
	printf("\n Removing mid!");         test_deletion("1001", "2003", 1);  test_list_size(12);  print_list();  //Removing mid
	printf("\n Removing mid again!");   test_deletion("1001", "2003", 0);  test_list_size(12);                 //Removing mid again
	printf("\n Removing mid!");         test_deletion("1001", "2004", 1);  test_list_size(11);  print_list();  //Removing mid
	printf("\n Removing mid again!");   test_deletion("1001", "2004", 0);  test_list_size(11);                 //Removing mid again
	printf("\n Removing first!");       test_deletion("1000", "2000", 1);  test_list_size(10);  print_list();  //Removing first
	printf("\n Removing first again!"); test_deletion("1000", "2000", 0);  test_list_size(10);                 //Removing first again
	printf("\n Removing first!");       test_deletion("1002", "2005", 1);  test_list_size(9);   print_list();  //Removing first
	printf("\n Removing first again!"); test_deletion("1002", "2005", 0);  test_list_size(9);                  //Removing first again
	
	print_list();
	
	//List will now be empty again
	delete_state();
	print_list();
	test_list_size(0); 
	
	test_subset_size(get_subset_by_snd("1000"), 0);  test_subset_size(get_subset_by_rcv("2000"), 0);
	test_subset_size(get_subset_by_snd("1001"), 0);  test_subset_size(get_subset_by_rcv("2001"), 0);
	test_subset_size(get_subset_by_snd("1002"), 0);  test_subset_size(get_subset_by_rcv("2002"), 0);
	test_subset_size(get_subset_by_snd("1003"), 0);  test_subset_size(get_subset_by_rcv("2003"), 0);
	test_subset_size(get_subset_by_snd("1004"), 0);  test_subset_size(get_subset_by_rcv("2004"), 0);
	test_subset_size(get_subset_by_snd("1005"), 0);  test_subset_size(get_subset_by_rcv("2005"), 0);
	test_subset_size(get_subset_by_snd("1006"), 0);  test_subset_size(get_subset_by_rcv("2006"), 0);
	test_subset_size(get_subset_by_snd("1007"), 0);  test_subset_size(get_subset_by_rcv("2007"), 0);

	test_existance("1000", "2000", 0);   test_existance("1001", "2000", 0);
	test_existance("1000", "2001", 0);   test_existance("1001", "2001", 0);
	test_existance("1000", "2002", 0);   test_existance("1001", "2002", 0);
	test_existance("1000", "2003", 0);   test_existance("1001", "2003", 0);
	test_existance("1000", "2004", 0);   test_existance("1001", "2004", 0);
	
	test_existance("1002", "2005", 0);   test_existance("1002", "2000", 0);
	test_existance("1003", "2005", 0);   test_existance("1001", "2006", 0);
	test_existance("1004", "2005", 0);   test_existance("1004", "2006", 0);
	test_existance("1005", "2005", 0);   test_existance("1005", "2006", 0);
	test_existance("1006", "2005", 0);   test_existance("1006", "2006", 0);
	
	
	//Removing non-existing items
	test_deletion("1000", "2002", 0);  test_list_size(0);  
	test_deletion("1000", "2000", 0);  test_list_size(0);  
	test_deletion("1000", "2003", 0);  test_list_size(0);  
	test_deletion("1000", "2001", 0);  test_list_size(0);
	

	if(!status) { printf("\n ERROR!\a\a\a\n ERROR!\a\a\a\n ERROR!\a\a\a\n"); }
	else        { printf("\n Tests passed\n");                               }
	
	return 0;
}

/**********************************************************************/
/* - End -                                                            */
/**********************************************************************/
