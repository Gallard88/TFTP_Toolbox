

// *******************************************************************************************

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>

// *******************************************************************************************
// *******************************************************************************************
int ListenSocket;

#define TFTP_BUF_SIZE	(512+2+2)
#define MYPORT    "69"

struct TFTP_Con {
  struct sockaddr_storage address;
  int fp;
  unsigned write:1;
  time_t activity_time;
  int block_number;
  char buf[TFTP_BUF_SIZE];
  int data_length;
};

struct TFTP_Con **ConnectionList;
int Max_Connections;
int NoAct_Timeout;	// seconds

// *******************************************************************************************
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// *******************************************************************************************
struct TFTP_Con *TFTP_CreateNewConnection(struct sockaddr_storage *address) {
  struct TFTP_Con *ptr = NULL;
  int i;

  // create new connection in array.
  for ( i = 0; i < Max_Connections; i ++ ) {
    if ( ConnectionList[i] == NULL ) {
      ptr = malloc(sizeof (struct TFTP_Con));
      ConnectionList[i] = ptr;
      break;
    }
  }
  if ( ptr == NULL )
    return NULL;

  // parse data for information
  ptr->address = *address;

  return ptr;
}

// *******************************************************************************************
void CloseConnection(int index)
{
  struct TFTP_Con *ptr;

  ptr = ConnectionList[index];
  if ( ptr ) {
    ConnectionList[index] = NULL;

    if ( ptr->fp >= 0 )
      close(ptr->fp);
    free(ptr);
  }
}

// *******************************************************************************************
void Connection_RunTimers(void)
{
  struct TFTP_Con *ptr;
  int current_time, i;

  current_time = time(NULL);

  for ( i = 0; i < Max_Connections; i ++ ) {
    ptr = ConnectionList[i];
    if ( ptr == NULL )
      continue;
    if ( ( current_time - ptr->activity_time ) > NoAct_Timeout) {
      // no activity close connection.
      printf("Closing con, timeout\n");
      CloseConnection(i);
    }
    if ( ptr->fp == -1 ) {
      // no activity close connection.
      printf("Closing con\n");
      CloseConnection(i);
    }
  }
}

// *******************************************************************************************
void System_Shutdown(void)
{
  close(ListenSocket);
}

// *******************************************************************************************
struct TFTP_Con *TFTP_FindConnection(struct sockaddr_storage *address) {
  struct TFTP_Con *ptr;
  int i;

  for ( i = 0; i < Max_Connections; i ++ ) {
    ptr = ConnectionList[i];
    if ( ptr == NULL )
      continue;
    if ( memcmp(&ptr->address, address, sizeof(struct sockaddr_storage)) == 0 ) {
      printf("Match Addr\n");
      return ptr;
    }
  }
  printf("No Match\n");
  return NULL;
}

// *******************************************************************************************
/*
void TFTP_SendData(struct TFTP_Con *ptr)
{
  ptr->data_length = read( ptr->fp , ptr->buf, 512) + 4;
  sendto(ListenSocket, ptr->buf, ptr->data_length, 0, ptr->address.ai_addr, ptr->address.ai_addrlen);
}
*/
// *******************************************************************************************
void TFTP_SendAck(int block_number, struct sockaddr_storage *address)
{
  char buf[4];

  buf[0] = 0;
  buf[1] = 4;
  buf[2] = (block_number / 256);
  buf[3] = (block_number % 256);
  sendto(ListenSocket, buf, 4, 0, (const struct sockaddr *) address, sizeof(struct sockaddr));
  printf("Ack: %d\n", block_number);
}

// *******************************************************************************************
int TFTP_NewReadRequest(char *data, struct sockaddr_storage *address)
{
  struct TFTP_Con *ptr;
  char filename[256];
  int fp;

  strcpy(filename, data);
  printf("New Read Rq: %s\n", filename);

  fp = open(filename, O_RDONLY );
  if ( fp >= 0 ) {
    ptr = TFTP_CreateNewConnection(address);
    if ( ptr == NULL ) {
      printf("TFTP_NewReadRequest() Malloc\n");
      close(fp);
      return -1;
    }
    ptr->block_number = 1;
    ptr->fp = fp;
    return 0;
  }
  return -1;
}

// *******************************************************************************************
int TFTP_NewWriteRequest(char *data, struct sockaddr_storage *address)
{
  struct TFTP_Con *ptr;
  char filename[256];
  int fp;

  strcpy(filename, data+2);
  printf("New Write Rq: %s\n", filename);

  fp = open(filename, O_WRONLY );
  if ( fp >= 0 ) {
    ptr = TFTP_CreateNewConnection(address);
    if ( ptr == NULL ) {
      printf("TFTP_NewWriteRequest() Malloc\n");
      close(fp);
      return -1;
    }
    ptr->block_number = 0;
    ptr->fp = fp;
    ptr->write = 1;	// singal that this connection is a WRQ type.
    TFTP_SendAck(ptr->block_number,  address);
    return 0;
  } else {
    printf("File failed to open\n");
  }
  return -1;
}

// *******************************************************************************************
void TFTP_ProcessPacket(int opcode, char *data, int length, struct sockaddr_storage *address)
{
  struct TFTP_Con *ptr;
  int block_number, rv;

  ptr = TFTP_FindConnection(address);
  if ( ptr == NULL )
    return ;

  block_number = (data[0] * 256) | data[1];
  if ( block_number != ptr->block_number ) {
    printf("Error, brown trousers time\n");

  } else {
    if ( ptr->write ) {
      rv = write( ptr->fp, data+2, length -2);
      printf("Block %d written: %d\n", block_number, rv);
      ptr->block_number++;

      if ( length < (512+2) ) {
        // sub size packet, enf of file.
        close(ptr->fp);
        ptr->fp = -1;
      }
      // Send Ack.
      TFTP_SendAck(ptr->block_number, address);

    } else {
      // make sure its an ack.
    }
  }
}

// *******************************************************************************************
int main( int argc, char *argv[] )
{
  struct addrinfo hints, *servinfo, *p;
  struct timeval timeout;
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  fd_set ReadFD;
  char packet_buff[TFTP_BUF_SIZE], s[256];
  int bytes, rv;
  int opcode;

  // ------------------------------------
  // Set up Syslog.

  // ------------------------------------
  // set up UDP listner.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }
  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((ListenSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("listener: socket");
      continue;
    }
    if (bind(ListenSocket, p->ai_addr, p->ai_addrlen) == -1) {
      close(ListenSocket);
      perror("listener: bind");
      continue;
    }
    break;
  }
  if (p == NULL) {
    fprintf(stderr, "listener: failed to bind socket\n");
    return 2;
  }
  freeaddrinfo(servinfo);

  // ------------------------------------
  // Set up Client Array.
  if ( Max_Connections <= 0 )
    Max_Connections = 25;
  if ( NoAct_Timeout <= 0 )
    NoAct_Timeout = 120;

  ConnectionList = malloc( sizeof(struct TFTP_Con) * Max_Connections);
  if ( ConnectionList == NULL ) {
    fprintf(stderr, "ConnectionList: malloc()\n");
    return -1;
  }

  memset(ConnectionList, 0, sizeof(struct TFTP_Con) * Max_Connections);

  // ------------------------------------
  // set up signal handlers.

  // ------------------------------------
  printf("Starting main program\n");

  // Main Loop.
  while ( 1 ) {
    FD_ZERO(&ReadFD);

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    FD_SET(ListenSocket, &ReadFD);

    if ( select(ListenSocket+1, &ReadFD, NULL, NULL, &timeout) > 0 ) {
      printf("listener: waiting to recvfrom...\n");
      while ( FD_ISSET(ListenSocket, &ReadFD) ) {
        // read out packet.
        addr_len = sizeof(struct sockaddr);
        bytes = recvfrom(ListenSocket, packet_buff, TFTP_BUF_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);
        if ( bytes == -1) {
          perror("recvfrom");
          exit(1);
        }
        if ( bytes == 0 ) {
          continue;
        }
        printf("Rec Packet (%d) %s\n", bytes, inet_ntop(their_addr.ss_family,get_in_addr((struct sockaddr *)&their_addr),s, sizeof( s)));
        opcode = packet_buff[1];
	
        switch ( opcode ) {

        case 1:	// read request
          printf("New Read\n");
          TFTP_NewReadRequest(packet_buff, &their_addr);
          break;

        case 2:	// write request
          printf("New Write\n");
          TFTP_NewWriteRequest(packet_buff, &their_addr);
          break;

        case 3:	// Data
        case 4:	// Ack
        default:	// error
          printf("New Other\n");
          TFTP_ProcessPacket(opcode, packet_buff+2, bytes-2, &their_addr);
          break;
        }
      }
    }
    Connection_RunTimers();
  }
  return 0;
}

// *******************************************************************************************
// *******************************************************************************************

