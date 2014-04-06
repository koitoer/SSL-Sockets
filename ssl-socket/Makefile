CC = gcc

Aplicacion: server cliente

server: server.o
	$(CC) -o server server.o -L/usr/local/ssl/include/ -L/usr/local/ssl/lib -lssl -lcrypto -lnsl -ldl

server.o: server.c 
	$(CC) -c server.o server.c

cliente: cliente.o
	$(CC) -o cliente cliente.o -L/usr/local/ssl/include/ -L/usr/local/ssl/lib -lssl -lcrypto -lnsl -ldl

cliente.o: cliente.c
	$(CC) -c cliente.o cliente.c

cipher:
	/usr/local/ssl/bin/openssl ciphers -v 'ALL:!ADH:@STRENGTH'

clean:
	rm *.o
