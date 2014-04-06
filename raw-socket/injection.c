#include <stdio.h>
#include <string.h>
#include<linux/if_ether.h>
	/*Libreria de los sockets*/
#include <sys/socket.h>	
#include <netinet/in.h>	
	/*Para obtener datos de capa 3 */
#include <netinet/ip.h>
	/*Para obtener datos de capa 4 */
        /*Usaremos la estructura BSD para TCP hdr */
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <unistd.h>

	/*Puerto al cual se va a enviar el paquete */
#define P 22 

int i=0;

/* Recordemos que al no tener el stack TCP/IP */
/* implementado tendremos que hacer el checksum */
/* manualmente con ayuda de esta funcion */
unsigned short csum (unsigned short *buf, int nwords){
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
  sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}


int main (int argc, char **argv){
  int one = 1;
  const int *val = &one;
  printf ("Iniciamos envio de paquetes \n");
  /*Creamos el socket crudo, el cual implementara TCP/IP */
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);	

  /*Creamos un buffer que contendra las cabeceras, IP y TCP */ 
  /*ademas del payload */
  char datagram[4096];	

  /*En est caso iremos del protocolo mas bajo al mas alto 
  por lo que empezaremos con IP , al crear una estuctura ip */
  struct ip *iph = (struct ip *) datagram ;

  /*Usaremos una estuctura de socket para el envio de paquetes */ 
  struct sockaddr_in sin;

  /*Usaremos la familia INET al tener que salir por la red */
  sin.sin_family = AF_INET;

  /*Se escoge un puerto destino al que se enviaran los paquetes*/
  sin.sin_port = htons (P);

  /*Escogemos la ip destino de nuestros paquetes */
  sin.sin_addr.s_addr = inet_addr ("132.248.59.1");

  /*Ponemos el buffer con los headers en cero */
  memset (datagram, 0, 4096);

  /* Hasta esta parte podran pensar que no hemos hecho nada diferente 
  ya que se usa una estructura sockaddr_in para elegir destino y todo 
  parece ser lo mismo, pero ahora tendremos el control de los campos
  de las cabeceras IP y TCP, para enviarlos por la red */
  /* Por lo que empezamos a rellenarlos manualmente */

  /*--------------------------------------------*/
  /* HEADER IP */
  iph->ip_hl = 5;
  /* Se escoge la version de IPv4 */
  iph->ip_v = 4;
  /* Se escoge el Type of Service */
  iph->ip_tos = 0;
  /* Se da la longitud de la cabecera IP */
  iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
  printf("Esta es la longitud ip_len %d \n" ,iph->ip_len);
  /* Identificador del paquete */
  iph->ip_id = htonl (54321);	
  /* Se da el offset del paquete */
  iph->ip_off = 0;
  /* Ponemos el timetolive */
  iph->ip_ttl = 255;
  /* Se esocge el protocolo a usar */
  iph->ip_p = 6; // 6 al ser TCP /etc/protocol
  /* Momentaneamente pones el checksum a cero */
  iph->ip_sum = 0;	
  /* Se escoge la ip origen, si claro pondremos la que queramos XD */
  /* Pero si queremos salir por la red, el proxy isp no permitira
  cualquier direccion en este campo */
  iph->ip_src.s_addr = inet_addr ("192.168.1.70");
  /* Se define la ip destino mediante la estructura definida anteriormente*/
  iph->ip_dst.s_addr = sin.sin_addr.s_addr;

  /*--------------------------------------------*/
  /* HEADER TCP */
  /*Ahora crearemos la estrutura tcp */
   struct tcphdr *tcph = (struct tcphdr *)(datagram +  iph->ip_hl*4 );
   printf("Esta es la longitud struct ip  %d \n" ,sizeof(*iph));
   printf("Esta es la longitud struct tcphdr %d \n" ,sizeof(*tcph));
  /* Se da el puerto origen del paquete */
  tcph->th_sport = htons (45521);
   /* Se da el puerto destino del paquete */
  tcph->th_dport = htons (P);
  /* Se da el numero de secuencia del paquete */
  tcph->th_seq = random();
  /* Numero de la secuencia ACK */
  tcph->th_ack = 0x00000000;
  tcph->th_x2 = 0; 
  /* Se da el offset de la cabecera TCP (5*4) */
  tcph->th_off = 5;
  /* Ponemos para la peticion de una conexion */
  tcph->th_flags = TH_SYN;	
  /* Indicamos el tamano de la ventana */
  tcph->th_win = 0x018f;	
  /* Si ponemos el checksum TCP a cero aunque digan que 
  el stack lo rellena en lo personal no me funciono, por
  lo que tuve que hacer el checksum */
  tcph->th_sum = 0x60fa;
  tcph->th_urp = 0;



  /*Se da el checksum del paquete y se incluye en el campo */
  iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);
  printf("Checksum ip %x \n" ,iph->ip_sum);

   /* Al usar IP_HDRINCL le decimos que estamos
 	incluyendo el header IP en el paquete */
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
      printf ("Error: No se modifico el socket \n");
  while (i!=10){
     i++;
      if (sendto (s,datagram,(iph->ip_len),0,(struct sockaddr *) &sin,sizeof (sin)) < 0)
	printf ("Paquete no se a podido enviar\n");
      else
	printf ("Paquete enviado \n");
    }

  return 0;
}
