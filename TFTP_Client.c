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
#define TFTP_BUF_SIZE			(512+2+2)
#define TFTP_DATA_SIZE			512
#define TFTP_HEADER_SIZE		4
#define TFTP_ACK_SIZE		4
#define TFTP_DATA	3
#define TFTP_ACK	4
#define TFTP_OP_ERROR	5

#define SERVERPORT "69" // the port users will be connecting to
int GetFile;
int FileHandle;
char DataBuf[TFTP_BUF_SIZE];
char readBuf[TFTP_BUF_SIZE];
int readLength;
int Client_BlockNum;
int SocketFd;
int Busy;
struct servent *Servent;
//	***************************************************************************
/*
struct TFTP_Con
{
int mode:3;
char data_buf[TFTP_BUF_SIZE];
char read_buf[TFTP_BUF_SIZE];
int read_length;
int file;
struct sockaddr_storage addr;
};
*/
//	***************************************************************************
int TFTP_WriteData(char *buf, int length)
{
  int rv;

  if ( FileHandle >= 0 ) {
    rv = write(FileHandle, buf, length);
    if ( rv == length ) {
      return 0;
    }
    perror("TFTP_WriteData\n");
  }
  return -1;
}

//	***************************************************************************
int TFTP_ReadData(char *buf)
{
  int rv;

  if ( FileHandle >= 0 ) {
    rv = read(FileHandle, buf, TFTP_DATA_SIZE);
    if ( rv > 0 ) {
      return rv;
    }
    perror("TFTP_ReadData\n");
  }
  return -1;
}


//	***************************************************************************
void TFTP_AckPacket(int block, struct sockaddr_storage *address)
{
  char buf[TFTP_ACK_SIZE];
  int rv;

  buf[0] = 0;
  buf[1] = TFTP_ACK;
  buf[2] = block / 256;
  buf[3] = block % 256;
  printf("ACL: %d\n", block);

  rv = sendto(SocketFd, buf, TFTP_ACK_SIZE, 0, (const struct sockaddr *) address, sizeof(struct sockaddr));
  if ( rv != TFTP_ACK_SIZE )
    printf("write error\n");
}

//	***************************************************************************
int main(int argc, char *argv[])
{
  struct sockaddr_in s_in;
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  struct timeval timeout;
  fd_set ReadFD;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  int length, opcode;
  int packet_blocknum;
  int port;

// -----------------------------
  if (argc != 4 ) {
    fprintf(stderr,"usage: TFTP_Client hostname [put|get] filename\n");
    exit(1);
  }

// -----------------------------
  Servent = getservbyname("tftp","udp");
  if (Servent == NULL ) {
    perror("getservbyname()");
    exit(0);
  }
  port = Servent->s_port;

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

  bzero((char *)&s_in, sizeof(s_in));
  s_in.sin_family = AF_UNSPEC;

  if (bind(SocketFd, (struct sockaddr *)&s_in, sizeof(s_in)) < 0 ) {
    perror("bind:");
    exit(-1);
  }


// -----------------------------
// Set up initial packet.
  DataBuf[0] = 0;
  if ( strcmp("get", argv[2]) == 0 ) {

    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    FileHandle = open(argv[3], O_WRONLY | O_CREAT, mode);
    Client_BlockNum = 1;
    GetFile = 1;
    DataBuf[1] = 1;
    printf("Get\n");

  } else {
    printf("Sending \"%s\" to %s\n", argv[3], argv[1]);
    FileHandle = open(argv[3], O_RDONLY);
    Client_BlockNum = -1;
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

  Busy = 1;
  while ( Busy ) {
    FD_ZERO(&ReadFD);
    FD_SET(SocketFd, &ReadFD);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    rv = select (SocketFd+1, &ReadFD, NULL, NULL , &timeout );
    if ( rv < 0 ) {
      printf("select() = %d\n", rv);
      return -1;
    }
    if ( rv == 0 ) {
      printf("Timeout\n");
      return -1;
    }

    if ( FD_ISSET(SocketFd, &ReadFD) ) {

      length = recvfrom(SocketFd, DataBuf, TFTP_BUF_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);
      opcode = DataBuf[1];
//      printf("Bytes: %d, %d\n", length, opcode);
      if ( opcode == TFTP_OP_ERROR ) {
        printf("Error\n");

      } else {

        packet_blocknum = ((int)DataBuf[2] * 256) + DataBuf[3];

        if ( GetFile ) {
          // sever sends file, we write to disk.
          if ( opcode != TFTP_DATA ) {
            printf("Bad opcode found\n");
            return -1;
          }
          if ( packet_blocknum != Client_BlockNum ) {
            printf("Write to disk\n");
            TFTP_WriteData(DataBuf+4, length - 4);
          }
          TFTP_AckPacket(packet_blocknum, &their_addr);
          Client_BlockNum = packet_blocknum;

        } else {
          // we send file, server writes to disk.
          if ( opcode != TFTP_ACK ) {
            printf("Bad opcode found\n");
            return -1;
          }
          if ( packet_blocknum != Client_BlockNum ) {
            readLength = TFTP_ReadData(readBuf+4);
            if ( readLength < TFTP_DATA_SIZE ) {
              close(FileHandle);
              FileHandle = -1;
              Busy = 0;
            }
            Client_BlockNum = packet_blocknum;
            packet_blocknum++;
            readBuf[0] = 0;
            readBuf[1] = TFTP_DATA;
            readBuf[2] = packet_blocknum / 256;
            readBuf[3] = packet_blocknum % 256;
          }
          rv = sendto(SocketFd, readBuf, readLength + TFTP_HEADER_SIZE, 0, p->ai_addr, p->ai_addrlen);
          if ( rv < 0 ) {
            perror("Send Packet");
          }
        }
      }
    }
  }
  printf("Transfer complete\n");
  freeaddrinfo(servinfo);
  close(SocketFd);
  return 0;
}

//	***************************************************************************
//	***************************************************************************


