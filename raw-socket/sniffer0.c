#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

int main(){
int fd = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
char buffer[8192]; 
int i =0 ;
int bytes = 0;
while ((bytes = read (fd, buffer, 8192)) > 0){
 	printf ("Paquete capturado %s \n", buffer+sizeof(struct iphdr)+sizeof(struct tcphdr));
	printf ("Contenido : \n");
	printf ("Hexadecimal \n");
	for(i = 0 ; i< bytes ; i++)
		printf("%x",buffer[i]);
	printf ("\nEntendible \n");
	 for(i = 0 ; i< bytes ; i++)
                printf("%c",buffer[i]);
	printf("\nSiguiente -------------------------------------- \n");
	}
	
}
