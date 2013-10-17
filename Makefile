all: TFTP_Server TFTP_Client

FLAGS=-Wall -O2

TFTP_Server: TFTP_Server.o
	gcc $(FLAGS) TFTP_Server.o -o TFTP_Server

TFTP_Server.o: TFTP_Server.c
	gcc -c $(FLAGS) TFTP_Server.c

TFTP_Client: TFTP_Client.o
	gcc $(FLAGS) TFTP_Client.o -o TFTP_Client

TFTP_Client.o: TFTP_Client.c
	gcc -c $(FLAGS) TFTP_Client.c

style: *.c
	astyle -A4 -s2 *.c
	rm *.orig

install: TFTP_Server TFTP_Client 
	install TFTP_Server /usr/local/bin
	install TFTP_Client /usr/local/bin
	
uninstall: TFTP_Server TFTP_Client 
	rm /usr/local/bin/TFTP_Server 
	rm /usr/local/bin/TFTP_Client 

clean:
	rm -rf *o *~ TFTP_Server TFTP_Client
