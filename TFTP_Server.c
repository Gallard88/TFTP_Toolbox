

// *******************************************************************************************

#include <stdio.h>
#include <syslog.h>
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

#define TFTP_BUF_SIZE	(512+2+2)
#define MYPORT    "69"
#define TFTP_RRQ		1
#define TFTP_WRQ		2
#define TFTP_DATA		3
#define TFTP_ACK		4
#define TFTP_ERROR		5

#define ACT_TIMEOUT		2

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
int TFTP_NewReadRequest(char *data, struct sockaddr_storage *address)
{
//  fd_set readFD;
//  struct timeval timeout;
//  struct sockaddr_storage their_addr;
//  socklen_t addr_len;
//  time_t start_time;
  int rrq_socket;
  int fp;
//  int opcode, packet_block, last_block;
//  char packet_buff[TFTP_BUF_SIZE];
//  int bytes, rv, diff;
  char client_name[256];

  inet_ntop(address->ss_family,get_in_addr((struct sockaddr *)address),client_name, sizeof (client_name));
  syslog(LOG_ERR,"RRQ: %s, %s", client_name, data+2);
  printf("New Read Rq: %s\n", data+2);

  if ((rrq_socket = socket(AF_UNSPEC, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    syslog(LOG_ERR,"WRQ: listner: socket");
    return -1;
  }

  fp = open(data + 2, O_RDONLY );
  if ( fp < 0 )
    return -1;
  /*
    last_block = 1;
    start_time = time(NULL);

    do
    {

      rv = sendto(rrq_socket, buf, 4, 0, (const struct sockaddr *) address, sizeof(struct sockaddr));


      FD_ZERO(&readFD);
      FD_SET(wrq_socket, &readFD);
      timeout.tv_sec = ACT_TIMEOUT;
      timeout.tv_usec = 0;

      if ( select(wrq_socket+1, &readFD, NULL, NULL, &timeout) > 0 ) {
        if ( FD_ISSET(wrq_socket, &readFD) ) {

      syslog(LOG_ERR,"Transfer from %s complete, %d bytes in %d seconds", client_name, (last_block*512)+(bytes-2), diff);

    }
    while ( 1 );
  */
  return -1;
}

// *******************************************************************************************
void TFTP_SendAck(int block_number, int sock, struct sockaddr_storage *address)
{
  char buf[4];

  buf[0] = 0;
  buf[1] = 4;
  buf[2] = (block_number / 256);
  buf[3] = (block_number % 256);
  sendto(sock, buf, 4, 0, (const struct sockaddr *) address, sizeof(struct sockaddr));
  printf("A: %d\n", block_number);
}

// *******************************************************************************************
int TFTP_NewWriteRequest(char *data, struct sockaddr_storage *address)
{
  fd_set readFD;
  struct timeval timeout;
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  time_t start_time;
  mode_t mode;
  int wrq_socket;
  int fp;
  int opcode, packet_block, last_block;
  char packet_buff[TFTP_BUF_SIZE];
  int bytes, rv, diff;
  char client_name[256];
  int errors = 1;

  // ------------------------------------
  // set up UDP listner.
  if ((wrq_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    syslog(LOG_ERR,"WRQ: listner: socket");
    perror("WRQ: Listner");
    return -1;
  }

  inet_ntop(address->ss_family,get_in_addr((struct sockaddr *)address),client_name, sizeof (client_name));
  syslog(LOG_ERR,"WRQ: %s, %s", client_name, data+2);
  mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
  fp = open(data+2, O_WRONLY | O_CREAT, mode );
  if ( fp < 0 )
    return -1;

  last_block = 0;
  start_time = time(NULL);
  TFTP_SendAck(last_block, wrq_socket, address);

  while ( 1 ) {
    FD_ZERO(&readFD);
    FD_SET(wrq_socket, &readFD);
    timeout.tv_sec = ACT_TIMEOUT;
    timeout.tv_usec = 0;

    if ( select(wrq_socket+1, &readFD, NULL, NULL, &timeout) > 0 ) {
      if ( FD_ISSET(wrq_socket, &readFD) ) {

        // read out packet.
        addr_len = sizeof(struct sockaddr);
        bytes = recvfrom(wrq_socket, packet_buff, TFTP_BUF_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);
        if ( bytes <= 0 ) {
          syslog(LOG_ERR,"recvfrom: %d", bytes);
          break;
        }
        printf("Data: %d\n", bytes);
        opcode = packet_buff[1];
        if ( opcode == TFTP_DATA ) {
          packet_block = (packet_buff[2] * 256) | packet_buff[3];
          if ( packet_block != last_block ) {
            errors = 5;		// so we don't allow more than 3 consecutive errors.
						printf("Write\n");
            rv = write( fp, packet_buff+4, bytes -4);
            last_block++;

            if (( bytes < TFTP_BUF_SIZE) || ( rv < 0 )) {
              // sub size packet, end of file.
              diff = time(NULL) - start_time;
              if ( diff == 0 )
                diff = 1;
              syslog(LOG_ERR,"Transfer from %s complete, %d bytes in %d seconds", client_name, (last_block*512)+(bytes-2), diff);
              TFTP_SendAck(last_block, wrq_socket, address);
              break;
            }
            TFTP_SendAck(last_block, wrq_socket, address);
            continue;
          } else {
						printf("Pack: %d / %d\n", packet_block, last_block);
					}
        } else if ( opcode == TFTP_ERROR ) {
					printf("Opcode: Error\n");
          syslog(LOG_ERR,"Some sort of error :(");
          break;
        } else {
					printf("Opcode: %d\n", opcode);
				}
      } else {
        syslog(LOG_ERR,"Timeout: Block %d", last_block);
        TFTP_SendAck(last_block, wrq_socket, address);
      }
    }
    if ( errors ) {
      errors--;
    } else {
      syslog(LOG_ERR,"Too many errors, closing connection");
      break;
    }
    printf("Error: %d\n", errors);
    TFTP_SendAck(last_block, wrq_socket, address);
  }
  printf("Close child\n");
  close(fp);
  close(wrq_socket);
  return 0;
}

// *******************************************************************************************
int main( int argc, char *argv[] )
{
  int ListenSocket;
  struct addrinfo hints, *servinfo, *p;
  struct timeval timeout;
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  fd_set ReadFD;
  char packet_buff[TFTP_BUF_SIZE];
  int bytes, rv;
  int opcode;
  pid_t pid;

  // ------------------------------------
  // Set up Syslog.
  openlog("TFTP_Server", LOG_PID, LOG_USER);
  syslog(LOG_ERR,"TFTP_Server online");

  // ------------------------------------
  // set up UDP listner.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0) {
    syslog(LOG_ERR,"getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }
  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((ListenSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      syslog(LOG_ERR,"listner: socket");
      continue;
    }
    if (bind(ListenSocket, p->ai_addr, p->ai_addrlen) == -1) {
      close(ListenSocket);
      syslog(LOG_ERR,"listner: bind");
      continue;
    }
    break;
  }
  if (p == NULL) {
    syslog(LOG_ERR,"listner: failed to bind socket");
    return 2;
  }
  freeaddrinfo(servinfo);

  // ------------------------------------
  // set up signal handlers.

  // ------------------------------------
  // Main Loop.
  while ( 1 ) {
    FD_ZERO(&ReadFD);

    timeout.tv_sec = ACT_TIMEOUT;
    timeout.tv_usec = 0;
    FD_SET(ListenSocket, &ReadFD);

    if ( select(ListenSocket+1, &ReadFD, NULL, NULL, &timeout) > 0 ) {
      if ( FD_ISSET(ListenSocket, &ReadFD) ) {
        // read out packet.
        addr_len = sizeof(struct sockaddr);
        bytes = recvfrom(ListenSocket, packet_buff, TFTP_BUF_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);
        if ( bytes < 0) {
          syslog(LOG_ERR,"recvfrom: %d", bytes);
          exit(1);
        }
        if ( bytes == 0 ) {
          continue;
        }

        opcode = packet_buff[1];

        if ( opcode == TFTP_RRQ ) {
          pid = fork();
          if ( pid == 0 ) { // child
            printf("Forked RRQ\n");
            return TFTP_NewReadRequest(packet_buff, &their_addr);

          } else if ( pid < 0 ) {
            printf("Failed to fork\n");
            return -1;

          } else {
            printf("Created a child\n");
          }

        } else if ( opcode == TFTP_WRQ ) {
          pid = fork();
          if ( pid == 0 ) { // child
            printf("Forked WRQ\n");
            return TFTP_NewWriteRequest(packet_buff, &their_addr);

          } else if ( pid < 0 ) {
            printf("Failed to fork\n");
            return -1;

          } else {
            printf("Created a child\n");
          }
        }
      }
    }
  }
  return 0;
}

// *******************************************************************************************
// *******************************************************************************************

