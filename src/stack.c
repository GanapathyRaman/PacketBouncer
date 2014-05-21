#include "bouncer.h"

struct Node *Head = NULL;

struct Node *searchClientTCPList(unsigned short sport, u_int32_t client_address) {
   struct Node *cur_ptr;  

   if(Head == NULL) {
      return NULL;
   }
  
   cur_ptr = Head; 
   
   while(cur_ptr != NULL) {
      if(cur_ptr->src_port == sport && client_address == cur_ptr->address) {
         return cur_ptr;
      }
      cur_ptr=cur_ptr->Next;  
   }  
   return NULL;  
}  

void addTCPtoList(unsigned short sport, unsigned short dport, u_int32_t address, int is_data_connection) {  
   struct Node *temp;  

   temp=(struct Node *)malloc(sizeof(struct Node));  
   temp->src_port = sport;  
   temp->dummy_port = dport;  
   temp->address = address;
   temp->fin_count = 2;
   temp->is_data_connection = is_data_connection;
   if (is_data_connection == 1) {
      temp->is_active = 0;
   } else {
      temp->is_active = 1;
   }
  
   if (Head == NULL) {  
      Head=temp;  
      Head->Next=NULL;  
   }  
   else {  
      temp->Next=Head;  
      Head=temp; 
   }
     
}  

struct Node *searchServerTCPList(unsigned short dport){
   struct Node *cur_ptr; 

   if(Head == NULL) {
      return NULL;
   }

   cur_ptr = Head; 
   while(cur_ptr != NULL) {
      if(cur_ptr->dummy_port == dport) {
         return cur_ptr;
      }
      cur_ptr=cur_ptr->Next;  
   }  
   printf("Not active connection found\n");
   return NULL;    
} 

/*struct Node *searchClientFTPList(char *client_address, unsigned short clientFTPPort) {
   struct Node *cur_ptr; 

   if(Head == NULL) {
      return NULL;
   }

   cur_ptr = Head; 
   while(cur_ptr != NULL) {
      if((!strcmp(client_address, cur_ptr->address)) && (cur_ptr->client_ftp_port == clientFTPPort)) {
         return cur_ptr;
      }
      cur_ptr=cur_ptr->Next;  
   }  
   printf("No active FTP data connection found\n");
   return NULL;   
}

struct Node *searchForClientFTPPort (unsigned short dummy_data_port) {
   struct Node *cur_ptr; 

   if(Head == NULL) {
      return NULL;
   }

   cur_ptr = Head; 
   while(cur_ptr != NULL) {
      if(cur_ptr->dummy_data_port == dummy_data_port) {
         return cur_ptr;
      }
      cur_ptr=cur_ptr->Next;  
   }  
   printf("No active FTP data connection found\n");
   return NULL;   
}*/

void displayList() {
   /*struct Node *temp;

   temp =  Head;
   printf("\nActive Connections:\n");
   printf("-------------------\n");
   while(temp != NULL) {
      printf("Client IP: %u\t Source Port: %u\t Dummy Port: %u\n", temp->address, temp->src_port, temp->dummy_port);
      printf(" ||\n");
      printf(" ||\n");
      printf(" \\/\n");
      temp = temp->Next;
   }
   printf("NULL\n\n");*/
}

void delTCPfromList (struct Node *del) {
   struct Node *cur_ptr, *temp;
   
   if(Head == NULL) {
      return;
   }

   if (del == Head) {
      temp = Head;
      Head = Head->Next;
      free(temp);
      temp = NULL;
      return;
   }
   cur_ptr = Head;

   while(cur_ptr->Next != NULL) {  
      if(cur_ptr->Next == del) {
         printf("Connection to be deleted FOUND\n");
         temp = cur_ptr->Next;
         cur_ptr->Next = temp->Next;
         free(temp);
         temp = NULL;
         return;
      }
      cur_ptr=cur_ptr->Next;
   }
}

void dealloc_all_TCP_Connections() {
   struct Node *cur_ptr, *temp;

   printf("Deallocating all Active TCP Connections\n");
   if (Head == NULL) {
      return;
   }

   cur_ptr = Head;
   while(cur_ptr != NULL) {
      temp = cur_ptr;
      cur_ptr = cur_ptr->Next;
      free(temp);
   }
   cur_ptr = NULL;
   temp = NULL;
   Head = NULL;
}

void Segmentation_Fault_Handler (int signum)
{
   printf("\n*** Alert: SEGMENTAION FAULT OCCURED\n");
   printf("Caught Signal No: %d\n",signum);
   dealloc_all_TCP_Connections();
   displayList();
   exit(signum);
}

void Interrupt_Handler (int signum)
{
   printf("\n\n*** Alert: CTRL+C was pressed\n");
   printf("Caught Signal No: %d\n",signum);
   dealloc_all_TCP_Connections();
   displayList();
   exit(signum);
}
