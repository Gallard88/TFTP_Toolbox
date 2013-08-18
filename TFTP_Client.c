/*
** talker.c -- a datagram "client" demo
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

//	***************************************************************************
#define TFTP_BUF_SIZE	(512+2+2)
#define TFTP_DATA	3
#define TFTP_ACK	4
#define TFTP_OP_ERROR	5

#define SERVERPORT "69" // the port users will be connecting to
int GetFile;
int FileHandle;
char DataBuf[TFTP_BUF_SIZE];
int BlockNumber;
int SocketFd;

//	***************************************************************************
int main(int argc, char *argv[])
{
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  struct timeval timeout;
  fd_set ReadFD;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  int length, opcode;

  // -----------------------------
  if (argc != 4 ) {
    fprintf(stderr,"usage: TFTPClient hostname [put|get] filename\n");
    exit(1);
  }

  // -----------------------------
  // -----------------------------
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  if ((rv = getaddrinfo(argv[1], SERVERPORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    exit( -1);
  }

  // loop through all the results and make a socket
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((SocketFd = socket(p->ai_family, p->ai_socktype,
                           p->ai_protocol)) == -1) {
      perror("talker: socket");
      continue;
    }
    break;
  }

  if (p == NULL) {
    fprintf(stderr, "talker: failed to bind socket\n");
    exit (-2);
  }

  // -----------------------------
  // Set up initial packet.
  DataBuf[0] = 0;
  if ( strcmp("get", argv[2]) == 0 ) {
    mode_t mode;

    printf("Get\n");
    mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    FileHandle = open(argv[3], O_WRONLY | O_CREAT, mode);
    GetFile = 1;
    DataBuf[1] = 1;
  } else {
    printf("Put\n");
    FileHandle = open(argv[3], O_RDONLY);
    GetFile = 0;
    DataBuf[1] = 2;
  }
  if ( FileHandle < 0 ) {
    fprintf(stderr, "Failed to open file %s\n", argv[3]);
    exit(-1);
  }
  strcpy(DataBuf+2, argv[3]);
  length = 2 + strlen(argv[3]);
  DataBuf[length] = 0;
  length++;
  strcat(&DataBuf[length], "netascii");
  length += strlen("netascii");
  DataBuf[length] = 0;
  length++;

  // -----------------------------

  if ( sendto(SocketFd, DataBuf, length, 0, p->ai_addr, p->ai_addrlen) == -1) {
    perror("talker: sendto");
    exit(1);
  }

  while ( 1 ) {
    FD_ZERO(&ReadFD);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    FD_SET(SocketFd, &ReadFD);

    rv = select (SocketFd+1, &ReadFD, NULL, NULL , &timeout );
    if ( rv < 0 ) {
      printf("select() = %d\n", rv);
      return -1;
    }
    if ( FD_ISSET(SocketFd, &ReadFD) ) {
      printf("packet ready\n");
      length = recvfrom(SocketFd, DataBuf, TFTP_BUF_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);
      opcode = DataBuf[1];
      printf("Bytes: %d, %d\n", length, opcode);
      if ( opcode == TFTP_OP_ERROR ) {
	printf("Error\n");
      } else {
	if ( GetFile ) {
	  // sever sends file, we write to disk.
	  if ( opcode != TFTP_DATA ) {
	    printf("Bad opcode\n");
	    return -1;
	  }
	  printf("Write to disk\n");
	    
	    
	} else {
	  // we send file, server writes to disk.
	  if ( opcode != TFTP_ACK ) {
	    printf("Bad opcode\n");
	    return -1;
	  }
	  printf("Read from disk\n");
	}
      }
    }    
  }

  freeaddrinfo(servinfo);
  printf("talker: sent %d bytes to %s\n", length, argv[1]);
  close(SocketFd);
  return 0;
}

//	***************************************************************************
//	***************************************************************************


