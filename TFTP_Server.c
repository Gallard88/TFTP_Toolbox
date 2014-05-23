/*
 TFTP Server
 Copyright (c) 2013 Thomas BURNS

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
*/
// *******************************************************************************************
#define _GNU_SOURCE

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>

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

#define ACT_TIMEOUT		5

// *******************************************************************************************
struct Transaction {
  int socket;
  struct sockaddr_storage *address;
  char client_name[256];

  int errors;

  int file;
  time_t start_time;
  int byte_count;
};

// *******************************************************************************************
typedef int (*TFTP_Handle)(struct Transaction *trans, char *data);
static void *get_in_addr(struct sockaddr *sa);

// *******************************************************************************************
const char DefaultDir[] = "/tmp/";
char *SystemDir;
sig_atomic_t child_exit_status;

// *******************************************************************************************
int Trans_SetupSocket(struct Transaction *t, struct sockaddr_storage *address)
{
  t->address = address;
  // now we create a new socket, to connect to the client via the port it sent the first packet from.
  if ((t->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    syslog(LOG_ERR,"listner: socket");
    return -1;
  }

  inet_ntop(address->ss_family,get_in_addr((struct sockaddr *)address),t->client_name, sizeof (t->client_name));
  return 0;
}

// *******************************************************************************************
static void PrintTransactionTime(struct Transaction *t)
{
  int diff = time(NULL) - t->start_time;

  if ( diff == 0 )
    diff = 1;
  syslog(LOG_ERR,"%s: Transfer complete, %d bytes in %d seconds", t->client_name, t->byte_count, diff);
  int rate = t->byte_count / diff;

  if ( rate > 1000000 ) {
    syslog(LOG_ERR,"%d MB/s", rate);
  } else if ( rate > 1000 ) {
    syslog(LOG_ERR,"%d kB/s", rate);
  } else {
    syslog(LOG_ERR,"%d B/s", rate);
  }
}

// *******************************************************************************************
static int RunErrorHandler(struct Transaction *t)
{
  if ( t->errors ) {
    t->errors--;
    syslog(LOG_ERR,"Errors encountered");
    return 0;
  } else {
    syslog(LOG_ERR,"Too many errors, closing connection");
    return -1;
  }
}

// *******************************************************************************************
void clean_up_child_process (int signal_number)
{
  // Clean up the child process.
  int status;
  wait (&status);
  // Store its exit status in a global variable.
  child_exit_status = status;
}

// *******************************************************************************************
static int OpenFile(const char *name, int write)
{
  char *filename, *path;
  int fp;

  if ( strstr(name, "..") != NULL ) {
    syslog(LOG_NOTICE, ".. Violation");
    return -1;
  }

  int rv = asprintf(&filename, "%s%s", SystemDir, name);
  if (( rv < 0 ) || ( filename == NULL )) {
    syslog(LOG_NOTICE, "Filename == NULL");
    return -1;
  } else {
    path = filename;
    while ( *path != 0 ) {
      if ( *path == '\\') {
        *path = '/';
      }
      path++;
    }
  }

  if ( write != 0 ) {
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    fp = open(filename, O_WRONLY | O_CREAT, mode );
  } else {
    fp = open(filename, O_RDONLY );
  }
  if ( fp < 0 ) {
    syslog(LOG_ERR,"File %s doesn't exist", name);
  }
  free(filename);
  return fp;
}

// *******************************************************************************************
// get sockaddr, IPv4 or IPv6:
static void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// *******************************************************************************************
const char *ErrorMsg[] = {
  "Not defined",
  "File not found",
  "Access violation",
  "Disk full or allocation exceeded",
  "Illegal TFTP operation",
  "Unknown transfer ID",
  "File already exists"
  "No such user"
};

// *******************************************************************************************
void TFTP_Send_Error(struct Transaction *t, int error_type)
{
  char buf[TFTP_BUF_SIZE];

  buf[0] = 0;
  buf[1] = TFTP_DATA;
  buf[2] = 0;
  buf[3] = error_type;
  strcpy(buf+4, ErrorMsg[error_type]);
  sendto(t->socket, buf, strlen(buf+4)+5, 0, (const struct sockaddr *) t->address, sizeof(struct sockaddr));
}

// *******************************************************************************************
int TFTP_NewReadRequest(struct Transaction *trans, char *data)
{
  fd_set readFD;
  struct timeval timeout;
  char rec_buff[TFTP_ACK_SIZE], send_buff[TFTP_BUF_SIZE];
  uint16_t packet_block = 0, last_block = 1;
  int packet_length = 0;

  do {
    if ( last_block != packet_block ) {
      // create data packet.
      send_buff[0] = 0;
      send_buff[1] = TFTP_DATA;
      send_buff[2] = (last_block / 256);
      send_buff[3] = (last_block % 256);
      packet_length = read(trans->file, send_buff+4, TFTP_DATA_SIZE);
      if ( packet_length < 0 ) {
        syslog(LOG_ERR,"%s: Read error: %d", trans->client_name, packet_length );
        break;
      }
      trans->byte_count += packet_length;
      packet_length += 4;
      last_block++;
    }

    int rv = sendto(trans->socket, send_buff, packet_length, 0, (const struct sockaddr *) trans->address, sizeof(struct sockaddr));
    if ( rv < 0 ) {
      syslog(LOG_ERR,"%s: sendto: %d", trans->client_name, rv );
      break;
    }

    FD_ZERO(&readFD);
    FD_SET(trans->socket, &readFD);
    timeout.tv_sec = ACT_TIMEOUT;
    timeout.tv_usec = 0;

    // listen for data, but with a time out so we can detect problems
    if ( select(trans->socket+1, &readFD, NULL, NULL, &timeout) > 0 ) {

      if ( FD_ISSET(trans->socket, &readFD) ) {

        socklen_t addr_len = sizeof(struct sockaddr);
        struct sockaddr_storage their_addr;
        rv = recvfrom(trans->socket, rec_buff, TFTP_ACK_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);

        int opcode = rec_buff[1];
        if ( opcode == TFTP_ACK ) {
          packet_block = (rec_buff[2] * 256) | rec_buff[3];
          if ( packet_length < TFTP_BUF_SIZE ) {
            PrintTransactionTime(trans);
            break;
          }
          continue;
        } else if ( opcode == TFTP_ERROR ) {
          syslog(LOG_ERR,"%s: Error %d: %s", trans->client_name, rec_buff[3], rec_buff+4);
          break;
        }
      }
    }
    if ( RunErrorHandler(trans) < 0 ) {
      break;
    }
  } while ( 1 );
  return 0;
}

// *******************************************************************************************
void TFTP_SendAck(struct Transaction *t, int block_number)
{
  char buf[4];

  buf[0] = 0;
  buf[1] = 4;
  buf[2] = (block_number / 256);
  buf[3] = (block_number % 256);
  sendto(t->socket, buf, 4, 0, (const struct sockaddr *) t->address, sizeof(struct sockaddr));
}

// *******************************************************************************************
int TFTP_NewWriteRequest(struct Transaction *trans, char *data)
{
  fd_set readFD;
  struct timeval timeout;
  uint16_t packet_block, last_block = 0;
  char packet_buff[TFTP_BUF_SIZE];

  TFTP_SendAck(trans, last_block);
  while ( 1 ) {
    FD_ZERO(&readFD);
    FD_SET(trans->socket, &readFD);
    timeout.tv_sec = ACT_TIMEOUT;
    timeout.tv_usec = 0;

    // listen on socket, but with a time out so we can detect problems.
    if ( select(trans->socket+1, &readFD, NULL, NULL, &timeout) > 0 ) {
      if ( FD_ISSET(trans->socket, &readFD) ) {

        // read out packet.
        socklen_t addr_len = sizeof(struct sockaddr);
        struct sockaddr_storage their_addr;
        int bytes = recvfrom(trans->socket, packet_buff, TFTP_BUF_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);

        if ( bytes <= 0 ) {
          syslog(LOG_ERR,"%s: recvfrom: %d", trans->client_name, bytes);
          break;
        }
        int opcode = packet_buff[1];
        if ( opcode == TFTP_DATA ) {
          packet_block = (packet_buff[2] * 256) | packet_buff[3];
          if ( packet_block != last_block ) {
            int rv = write( trans->file, packet_buff+4, bytes -4);
            trans->byte_count += bytes - 4;
            last_block++;

            TFTP_SendAck(trans, last_block);
            if (( bytes < TFTP_BUF_SIZE) || ( rv < 0 )) {
              // sub size packet, end of file.
              PrintTransactionTime(trans);
              return -1;
            }
            continue;
          }
        } else if ( opcode == TFTP_ERROR ) {
          syslog(LOG_ERR,"%s: Error %d: %s", trans->client_name, packet_buff[3], packet_buff+4);
          return -1;
        }
      } else {
        syslog(LOG_ERR,"%s: Timeout: Block %d", trans->client_name, last_block);
        TFTP_SendAck(trans, last_block);
      }
    }
    if ( RunErrorHandler(trans) < 0 ) {
      return -1;
    }
    TFTP_SendAck(trans, last_block);
  }
  return 0;
}

// *******************************************************************************************
/**
 *	TFTP is a curious protocol.
 *  The inital connection is made on port 69 via UDP.
 *  The server response with a packet sent back to client:port,
 *  BUT the packet is sent from a different port on the server
 *  The entire transfer then takes place between these two ports
 *  Leaving port 69 exclusively to listen for new incoming connections.
 *
 *  This server starts up, and begins listening on port 69.
 *  When a connection is established, it forks a child and that child handles
 *  the transfer. once the transfer is complete/terminated, the child returns
 *  ending the process.
 */

int main( int argc, char *argv[] )
{
  struct Transaction trans;
  int ListenSocket;
  struct addrinfo hints, *servinfo, *p;
  struct timeval timeout;
  struct sockaddr_storage their_addr;
  fd_set ReadFD;
  struct sigaction sigchld_action;
  char packet_buff[TFTP_BUF_SIZE];
  int rv;
  const char *dir;

  // ------------------------------------
  // Handle SIGCHLD by calling clean_up_child_process.
  memset (&sigchld_action, 0, sizeof (sigchld_action));
  sigchld_action.sa_handler = &clean_up_child_process;
  sigaction (SIGCHLD, &sigchld_action, NULL);

  // ------------------------------------
  // Set up Syslog.
  openlog("TFTP Server", LOG_PID, LOG_USER);
  syslog(LOG_NOTICE,"TFTP Server online");

  // ------------------------------------
  // Daemonise the program.
  if ( daemon( 1, 0 ) < 0 ) { // keep dir
    syslog(LOG_ERR,"daemonise failed");
    return -1;
  }

  // ------------------------------------
  // here we define what directory we want to use.
  // if the user has supplied one, we use that, other wise we use the default.

  dir = ( argc >= 2 )? argv[1]: DefaultDir;
  rv = asprintf(&SystemDir, "%s", dir);
  if (( SystemDir == NULL ) || ( rv < 0 )) {
    syslog(LOG_ERR, "SystemDir == NULL");
    return -1;
  } else {
    if ( SystemDir[strlen(SystemDir)-1] != '/' ) {
      strcat(SystemDir, "/");
    }
  }
  syslog(LOG_NOTICE,"Directory set: %s", SystemDir);

  // ------------------------------------
  // set up UDP listner.
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // either IPv4 or IPv6
  hints.ai_socktype = SOCK_DGRAM; // UDP
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
        socklen_t addr_len = sizeof(struct sockaddr);
        int bytes = recvfrom(ListenSocket, packet_buff, TFTP_BUF_SIZE, 0,(struct sockaddr *)&their_addr, &addr_len);
        if ( bytes < 0) {
          // error, close the program
          syslog(LOG_ERR,"recvfrom: %d", bytes);
          exit(1);
        } else if ( bytes == 0 ) {
          continue;
        }
        // The child handles that transfer, before exiting,
        // The parent process goes back to listening for the next connection.
        pid_t pid = fork();
        if ( pid > 0 ) { // parent
          continue;
        } else if ( pid < 0 ) {
          syslog(LOG_ERR,"Fork error");
          return -1;
        }

        memset(&trans, 0, sizeof(struct Transaction));

        // Here we begin decoing the received packet and setting up the client
        if (Trans_SetupSocket(&trans, &their_addr) < 0 ) {
          continue;
        }

        // open the file...
        trans.file = OpenFile((const char *) packet_buff+2, 1);
        if ( trans.file < 0 ) {
          TFTP_Send_Error(&trans, 1);
          return -1;
        }

        syslog(LOG_NOTICE,"%s: \"%s\"", trans.client_name, packet_buff+2);
        trans.errors = 5;  // max number of re-transmissions per transaction.
        trans.start_time = time(NULL);

        // here we choose what function to run based on the opcode of the recieved packet.
        int opcode = packet_buff[1];
        if ( opcode == TFTP_RRQ ) {
          rv = TFTP_NewReadRequest(&trans, packet_buff);
        } else if ( opcode == TFTP_WRQ ) {
          rv = TFTP_NewWriteRequest(&trans, packet_buff);
        } else {
          syslog(LOG_NOTICE,"%s: Bad opecode: %d ", trans.client_name, opcode);
          rv = -1;
        }
        close(trans.file);
        close(trans.socket);
        return rv;
      }
    }
  }
  free(SystemDir);
  close(ListenSocket);
  return 0;
}

// *******************************************************************************************
// *******************************************************************************************

