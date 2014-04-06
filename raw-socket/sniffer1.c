#include<stdio.h>
#include<string.h>
#include<stdlib.h>
	/* Libreria de los sockets */
#include<sys/socket.h>
#include<features.h>
#include<linux/if_packet.h>
#include<errno.h>
	/* Libreria de los sockets */
#include<sys/ioctl.h>
	/* Libreria de control de interfaces */
#include<net/if.h>
	/* Libreria de los paquetes ethernet*/
#include<linux/if_ether.h>
	/* Libreria de los paquetes ip*/
#include<linux/ip.h>
	/* Libreria de los paquetes tcp*/
#include<linux/tcp.h>
	/* Libreria de definiciones de protocolos*/
#include<netinet/in.h>
	/* Libreria para decodificar unsigned char */
#include<ctype.h>

void header();
int obtenerData(unsigned char *, int);
int obtenerHTCP(unsigned char *, int);
void obtenerHIP(unsigned char *, int);
void obtenerHEthernet(unsigned char *, int);
int socketif(char *, int, int);
void impresionHex(unsigned char *, int);
void impresionASCII(unsigned char *, int);
void impresionFormatoIP(unsigned char *, int);

int main(int argc, char **argv){
	/* Nuestro futuro raw_socket */
	int rsock; 
	int len;
	/* Numero de paquetes a recibir */
	int paquetes;
	/* Bandera para la impresion o no de datos */
	int validacion=0;
	int packet = 0;
        /* Buffer de lectura de la informacion recibida */
	unsigned char p_buffer[2048];
        /* Estructura que ligara el socket con la interfaz */
	struct sockaddr_ll p_info;
        /* Definimos tamano del buffer */
	int p_size = sizeof(p_info);
	if(argc !=3){
		printf("Uso %s <interfaz> <no_paqutes> \n",argv[0]);
		exit(-1);
	}
	/* Se crea un socket crudo para protocolo IP */
	rsock = creaSocket(ETH_P_IP);
	/* Se inicia el proceso */
	header();
	/* Se une el socket a un interfaz de la maquina */
	socketif(argv[1], rsock, ETH_P_IP);
	/* Decimos el numero de paquetes a capturar */
	paquetes = atoi(argv[2]);
	/* Empezamos la captura de n numero de paquetes */
	while(paquetes--){
		/* Recibimos paquetes a travez del socket crudo del protocolo IP */
		/* Y los pasamos los datos al buffer, ademas de su informacion a la estructura p_info*/
		if((len = recvfrom(rsock, p_buffer, 2048, 0, (struct sockaddr*)&p_info, &p_size)) == -1){
			perror("Ha habido un error en la captura ");
			exit(-1);
		}else{
			printf("-------- Paquete Capturado No. %d ------------ \n",packet++);
			/* Una vez capturado obtendremos la informacion */
			/* Obtenemos el header ethernet capa 2         */
			obtenerHEthernet(p_buffer, len);
			/* Obtenemos el header ip capa 3               */
                        obtenerHIP(p_buffer, len);
			/* Obtenemos el header tcp capa 4               */
                        validacion = obtenerHTCP(p_buffer, len);
			if(validacion == 1)
				obtenerData(p_buffer, len);
			printf("-------- END Paquete Capturado No. %d --------- \n\n",paquetes);
		}//fin del else
		bzero(p_buffer,sizeof(p_buffer));
	}//fin del while
	
	
	return 0;
}


int creaSocket(int protocol){
	int rsocket;
	if((rsocket = socket(PF_PACKET, SOCK_RAW, htons(protocol)))== -1){
		perror("Error al crear el socket crudo");
		exit(-1);
	}
	return rsocket;
}

void header(){
	printf("Sniffer ! \n");
	printf("-----------------------------------------------\n");
}


int socketif(char *interfaz, int rsock, int protocol){
	/* Ahora en vez de ligar el socket con un puerto */
	/* La ligaremos con una interfaz 		 */
	struct sockaddr_ll sll;
	struct ifreq ifr;
	bzero(&sll, sizeof(sll));
	/* Limpiamos la estructura de datos de la interfaz */
	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name,interfaz);
	/* Cargamos datos de la interfaz a la estructura ifr */
        if((ioctl(rsock, SIOCGIFINDEX, &ifr)) == -1){
                printf("No se puede obtener la interfaz !\n");
                exit(-1);
        }
	/* Impresion de propiedades de la interfaz */
	/* Obtenemos las flags de la interfaz */
 	if((ioctl(rsock, SIOCGIFFLAGS,&ifr)) < 0){
                perror("Error : Al obtener banderas de la interfaz ");
        }
        
	int flags=0;
        flags = ifr.ifr_flags;
        
	/* Checamos si la interfaz esta activa */
        if((flags & IFF_UP) != 0)
                printf("Dispositivo arriba [UP] \n");
	else{
		printf("El dispositivo no existe no esta arriba \n ");
		exit(-1);
	}
	
	/* Checamos si la interfaz esta en modo promisuo */
	if((flags & IFF_PROMISC) != 0)
                printf("Dispositivo en modo Promiscuo \n");

	printf("La interfaz de captura es %s \n" ,interfaz);

	/*Obtenemos la direccion MAC */
	if((ioctl(rsock,SIOCGIFHWADDR,&ifr)) < 0){
		perror("Error : Al obtener MAC address ");
		exit(-1);
	}
	printf("La MAC de la interfaz es : ");
	impresionHex(ifr.ifr_hwaddr.sa_data,6);

	/*Obtenemos la direccion IP */
        if((ioctl(rsock,SIOCGIFADDR,&ifr)) < 0){
                perror("Error : Al obtener direccion IP  ");
                exit(-1);
        }
        printf("La Direccion IP de la interfaz es : " );
        impresionFormatoIP(&ifr.ifr_addr.sa_data[2],4);

	/*Obtenemos la mascara de red */
        if((ioctl(rsock,SIOCGIFNETMASK,&ifr)) < 0){
                perror("Error : Al obtener la mascara de red");
                exit(-1);
        }
        printf("La Mascara de red de la interfaz es : " );
        impresionFormatoIP(&ifr.ifr_netmask.sa_data[2],4);

	/*Obtenemos la direccion de broadcast */	
        if((ioctl(rsock,SIOCGIFBRDADDR,&ifr)) < 0){
                perror("Error : Al obtener la direccion de broadcast");
                exit(-1);
        }
        printf("La direccion de broadcasr de la interfaz es : " );
        impresionFormatoIP(&ifr.ifr_broadaddr.sa_data[2],4);

	/*Obtenemos el indice de la interfaz */
	if((ioctl(rsock, SIOCGIFINDEX, &ifr)) == -1){
                printf("No se puede obtener la interfaz !\n");
                exit(-1);
        }

	/* Siempre AF_PACKET */
	sll.sll_family = AF_PACKET;
	/* Definimos el indice al cual se ligara el socket */
	sll.sll_ifindex = ifr.ifr_ifindex;
	/* Definimos el protocolo que se manejara */
	sll.sll_protocol = htons(protocol); 
	/*Ligamos el socket a la interfaz */
	if((bind(rsock, (struct sockaddr *)&sll, sizeof(sll)))== -1){
		perror("Error al unir el socket con la interfaz\n");
		exit(-1);
	}

	printf("\n-----------------------------------------------");
	return 1;	
}


void impresionHex(unsigned char *p, int num){
	while(num--){
		printf("%.2X ", *p);
		p++;
	}
	printf("\n");
}

void impresionASCII(unsigned char *p, int num){
	while(num--){
		printf("%c", toascii(*p));
		p++;
	}
	printf("\n");
}

void impresionFormatoIP(unsigned char *p, int num){
        while(num--){
                printf("%d", *p);
		if(num!=0)
			printf(".");
                p++;
        }
        printf("\n");
}

void obtenerHEthernet(unsigned char *packet, int len){
	/* Creamos una estructura de tipo ethhdr */
	/* para vaciar los datos y castearlos    */
	struct ethhdr *h_ethernet;
	/* Hacemos el ordenamiento siempre y cuando tengamos suficientes bytes */
	if(len > sizeof(struct ethhdr)){
		h_ethernet = (struct ethhdr *)packet;
		/* Ahora obtenemos los datos importantes que seria */
		/* MAC ORIGEN,MAC DESTINO y PROTOCOLO DE RED*/
		printf("Protocolo de red : ");
		impresionHex((void *)&h_ethernet->h_proto, 2);
		printf("MAC Destino : ");
		impresionHex(h_ethernet->h_dest, 6);
		printf("MAC Origen : ");
		impresionHex(h_ethernet->h_source, 6);
	}else
		printf("HETHERNET : Paquete de tamano insuficiente \n");

}



void obtenerHIP(unsigned char *packet, int len){
	struct ethhdr *h_ethernet;
	struct iphdr *h_ip;

	h_ethernet = (struct ethhdr *)packet;
	/* Confirmamos que se trata da un paquete IP */
	/* revisando el campo h_proto de la estructura */
	/* ethhdr */

	if(ntohs(h_ethernet->h_proto) == ETH_P_IP){
		/* Confirmamos la existencia de suficientes bytes */
		if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr))){
			h_ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
			printf("IP Destino: %s\n", (char *)inet_ntoa(h_ip->daddr));
			printf("IP Origen : %s\n", (char *)inet_ntoa(h_ip->saddr));
		}else
			printf("HIP : Paquete de tamano insuficiente \n");
	}else
		printf("Este no es un paquete IP \n ");
}


int obtenerHTCP(unsigned char *packet, int len){
	struct ethhdr *h_ethernet;
	struct iphdr *h_ip;
	struct tcphdr *h_tcp;

	/*Verificamos que haya suficientes bytes para castear los headers */
	if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))){
		h_ethernet = (struct ethhdr *)packet;
		/*Verificamos se trate de un paquete IP */
		if(ntohs(h_ethernet->h_proto) == ETH_P_IP){
			h_ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
			/*Verificamos se trata del protocolo TCP */
			if(h_ip->protocol == IPPROTO_TCP){
				/* Apuntamos a la cabecera tcp */
				h_tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + h_ip->ihl*4 );
				printf("Source Port: %d\n", ntohs(h_tcp->source));
				printf("Dest Port: %d\n", ntohs(h_tcp->dest));
			return 1;
			}else
				printf("No es un paquete TCP\n");
		}else
			printf("No es un paquete IP\n");	
	}else
		printf("HTCP : Paquete de tamano insuficiente \n");
	return 0;
}




int obtenerData(unsigned char *packet, int len){
	struct ethhdr *h_ethernet;
	struct iphdr *h_ip;
	struct tcphdr *h_tcp;
	unsigned char *data;
	int data_len;

	if(len > (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))){
		/*Apuntamos y casteamos al header ip */
		h_ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
		/* Apuntamos al inicio de la parte de los datos */
		data = (packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
		/*La longitud de datos es la longitud de todo el paquete ip, menos el 
			tamano del header ip y header tcp */
		data_len = ntohs(h_ip->tot_len) - h_ip->ihl*4 - sizeof(struct tcphdr);
		if(data_len){
			printf("Longitud de datos : %d\n", data_len);
			printf("Datos : \n");
			impresionHex(data, data_len);
			printf("\n");		
			return 1;	
		}else{
			printf("No hay datos en los paquetes\n");
			return 0;
		}
	}else{
		printf("DATOS : Paquete de tamano insuficiente \n");
		return 0;
	} 	
}

