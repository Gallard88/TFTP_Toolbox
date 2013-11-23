

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
#define TFTP_ACK_SIZE	(2+2)
#define TFTP_DATA_SIZE	(512)
#define MYPORT    "69"
#define TFTP_RRQ		1
#define TFTP_WRQ		2
#define TFTP_DATA		3
#define TFTP_ACK		4
#define TFTP_ERROR		5

#define ACT_TIMEOUT		2

// *******************************************************************************************
const char Default_Dir[] = "/tmp/";
char SystemDir[TFTP_BUF_SIZE*2];

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
void TFTP_Send_Error(int sock, int error_type, struct sockaddr_storage *address)
{
  char buf[TFTP_BUF_SIZE];

  buf[0] = 0;
  buf[1] = TFTP_DATA;
  buf[2] = 0;
  buf[3] = error_type;
  switch ( error_type ) {
  case 0 :
    strncpy(buf+4, "Not defined", TFTP_BUF_SIZE-4);
    break;

  case 1:
    strncpy(buf+4, "File not found", TFTP_BUF_SIZE-4);
    break;

  case 2:
    strncpy(buf+4, "Access violation", TFTP_BUF_SIZE-4);
    break;

  case 3:
    strncpy(buf+4, "Disk full or allocation exceeded", TFTP_BUF_SIZE-4);
    break;

  case 4:
    strncpy(buf+4, "Illegal TFTP operation", TFTP_BUF_SIZE-4);
    break;

  case 5:
    strncpy(buf+4, "Unknown transfer ID", TFTP_BUF_SIZE-4);
    break;

  case 6:
    strncpy(buf+4, "File already exists", TFTP_BUF_SIZE-4);
    break;

  case 7:
    strncpy(buf+4, "No such user", TFTP_BUF_SIZE-4);
    break;

  default:
    return;

  }
  sendto(sock, buf, strlen(buf+4)+5, 0, (const struct sockaddr *) address, sizeof(struct sockaddr));
}

// *******************************************************************************************
int TFTP_NewReadRequest(char *data, struct sockaddr_storage *address)
{
  fd_set readFD;
  struct timeval timeout;
  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  time_t start_time;
  char rec_buff[TFTP_ACK_SIZE], send_buff[TFTP_BUF_SIZE];
  char filename[TFTP_BUF_SIZE*2];
  int rrq_socket;
  int fp;
  int opcode, packet_block = 0, last_block = 1;
  int packet_length = 0, rv, diff;
  char client_name[256];
  int errors = 5;	// allow no more than 5 errors per trasnfer.

  if ((rrq_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    syslog(LOG_ERR,"RRQ: listner: socket");
    return -1;
  }

  inet_ntop(address->ss_family,get_in_addr((struct sockaddr *)address),client_name, sizeof (client_name));
  if ( strstr(data+2, "..") != NULL ) {
    syslog(LOG_ERR,"RRQ: %s, invalid filename %s", client_name, data+2);
    TFTP_Send_Error(rrq_socket, 2, address);
    return -1;
  }

  strcpy(filename, SystemDir);
  strcat(filename, data+2 );

  fp = open(filename, O_RDONLY );
  if ( fp < 0 ) {
    syslog(LOG_ERR,"RRQ: file doesn't exist");
    TFTP_Send_Error(rrq_socket, 1, address);
    return -1;
  } else {
    syslog(LOG_ERR,"RRQ: %s, %s", client_name, data+2);
  }

  start_time = time(NULL);

  do {
    if ( last_block != packet_block ) {
      // create data packet.
      send_buff[0] = 0;
      send_buff[1] = TFTP_DATA;
      send_buff[2] = (last_block / 256);
      send_buff[3] = (last_block % 256);
      packet_length = read(fp, send_buff+4, TFTP_DATA_SIZE);
      if ( packet_length < 0 ) {
        syslog(LOG_ERR,"RRQ: Read error: %d", packet_length );
        break;
      }
      packet_length += 4;
      last_block++;
    }

    rv = sendto(rrq_socket, send_buff, packet_length, 0, (const struct sockaddr *) address, sizeof(struct sockaddr));
    if ( rv < 0 ) {
      syslog(LOG_ERR,"RRQ: sendto: %d", rv );
      break;
    }

    FD_ZERO(&readFD);
    FD_SET(rrq_socket, &readFD);
    timeout.tv_sec = ACT_TIMEOUT;
    timeout.tv_usec = 0;

    if ( select(rrq_socket+1, &readFD, NULL, NULL, &timeout) > 0 ) {

      if ( FD_ISSET(rrq_socket, &readFD) ) {
        addr_len = sizeof(struct sockaddr);
        rv = recvfrom(rrq_socket, rec_buff, TFTP_ACK_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);

        opcode = rec_buff[1];
        if ( opcode == TFTP_ACK ) {
          packet_block = (rec_buff[2] * 256) | rec_buff[3];
          if ( packet_length < TFTP_BUF_SIZE ) {
            diff = time(NULL) - start_time;
            if ( diff == 0 )
              diff = 1;
            syslog(LOG_ERR,"RRQ: Transfer from %s complete, %d bytes in %d seconds", client_name, (last_block*512)+(packet_length-4), diff);
            break;
          }
          continue;
        } else if ( opcode == TFTP_ERROR ) {
          syslog(LOG_ERR,"RRQ: Error %d: %s", rec_buff[3], rec_buff+4);
          break;
        }
      }
    }
    if ( errors ) {
      errors--;
    } else {
      syslog(LOG_ERR,"RRQ: Too many errors, closing connection");
      break;
    }
  } while ( 1 );
  close(fp);
  close(rrq_socket);
  return 0;
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
  int opcode, packet_block, last_block = 0;
  char packet_buff[TFTP_BUF_SIZE];
  char filename[TFTP_BUF_SIZE*2];
  int bytes, rv, diff;
  char client_name[256];
  int errors = 5;	// allow no more than 5 errors per trasnfer.

  // ------------------------------------
  // set up UDP listner.
  if ((wrq_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    syslog(LOG_ERR,"WRQ: listner: socket");
    return -1;
  }

  inet_ntop(address->ss_family,get_in_addr((struct sockaddr *)address),client_name, sizeof (client_name));

  if ( strstr(data+2, "..") != NULL ) {
    syslog(LOG_ERR,"WRQ: %s, invalid filename %s", client_name, data+2);
    TFTP_Send_Error(wrq_socket, 2, address);
    return -1;
  }
  strcpy(filename, SystemDir);
  strcat(filename, data+2 );
  syslog(LOG_ERR,"WRQ: %s, %s", client_name, data+2);
  mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
  fp = open(filename, O_WRONLY | O_CREAT, mode );
  if ( fp < 0 ) {
    syslog(LOG_ERR,"WRQ: failed to open file for writing");
    TFTP_Send_Error(wrq_socket, 3, address);
    return -1;
  }

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
          syslog(LOG_ERR,"WRQ: recvfrom: %d", bytes);
          break;
        }
        opcode = packet_buff[1];
        if ( opcode == TFTP_DATA ) {
          packet_block = (packet_buff[2] * 256) | packet_buff[3];
          if ( packet_block != last_block ) {
            rv = write( fp, packet_buff+4, bytes -4);
            last_block++;

            if (( bytes < TFTP_BUF_SIZE) || ( rv < 0 )) {
              // sub size packet, end of file.
              diff = time(NULL) - start_time;
              if ( diff == 0 )
                diff = 1;
              syslog(LOG_ERR,"WRQ: Transfer from %s complete, %d bytes in %d seconds", client_name, (last_block*512)+(bytes-2), diff);
              TFTP_SendAck(last_block, wrq_socket, address);
              break;
            }
            TFTP_SendAck(last_block, wrq_socket, address);
            continue;
          }
        } else if ( opcode == TFTP_ERROR ) {
          syslog(LOG_ERR,"WRQ: Error %d: %s", packet_buff[3], packet_buff+4);
          break;
        }
      } else {
        syslog(LOG_ERR,"WRQ: Timeout: Block %d", last_block);
        TFTP_SendAck(last_block, wrq_socket, address);
      }
    }
    if ( errors ) {
      errors--;
    } else {
      syslog(LOG_ERR,"WRQ: Too many errors, closing connection");
      break;
    }
    TFTP_SendAck(last_block, wrq_socket, address);
  }
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
  if ( daemon( 1, 0 ) < 0 ) { // keep dir
    syslog(LOG_ERR,"daemonise failed");
    return -1;
  }

  // ------------------------------------
  if ( argc == 2 ) {
    strncpy(SystemDir, argv[1], sizeof(SystemDir) - TFTP_BUF_SIZE);
    if ( SystemDir[strlen(SystemDir)-1] != '/') {
      strcat(SystemDir, "/");
    }
  } else {
    strcpy(SystemDir, Default_Dir);
  }
  syslog(LOG_ERR,"Directory set: %s", SystemDir);

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
            return TFTP_NewReadRequest(packet_buff, &their_addr);

          } else if ( pid < 0 ) {
            syslog(LOG_ERR,"RRQ: Fork error");
            return -1;
          }
        } else if ( opcode == TFTP_WRQ ) {
          pid = fork();
          if ( pid == 0 ) { // child
            return TFTP_NewWriteRequest(packet_buff, &their_addr);

          } else if ( pid < 0 ) {
            syslog(LOG_ERR,"WRQ: Fork error");
            return -1;
          }
        }
      }
    }
  }
  close(ListenSocket);
  return 0;
}

// *******************************************************************************************
// *******************************************************************************************

