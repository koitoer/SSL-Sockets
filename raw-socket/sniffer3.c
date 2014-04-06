#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<features.h>
#include<linux/if_packet.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<linux/if_ether.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<netinet/in.h>
#include<netinet/ip_icmp.h>
#include<net/if_arp.h>
#include<ctype.h>

#define DHCP_UDP_OVERHEAD       (20 + /* IP header */                   \
                                8)   /* UDP header */
#define DHCP_SNAME_LEN          64
#define DHCP_FILE_LEN           128
#define DHCP_FIXED_NON_UDP      236
#define DHCP_FIXED_LEN          (DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
                                                /* Everything but options. */
#define BOOTP_MIN_LEN           300

#define DHCP_MTU_MAX            1500
#define DHCP_MTU_MIN            576

#define DHCP_MAX_OPTION_LEN     (DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN     (DHCP_MTU_MIN - DHCP_FIXED_LEN)

struct dhcp_packet {
 u_int8_t  op;          /* 0: Message opcode/type */
        u_int8_t  htype;        /* 1: Hardware addr type (net/if_types.h) */
        u_int8_t  hlen;         /* 2: Hardware addr length */
        u_int8_t  hops;         /* 3: Number of relay agent hops from client */
        u_int32_t xid;          /* 4: Transaction ID */
        u_int16_t secs;         /* 8: Seconds since client started looking */
        u_int16_t flags;        /* 10: Flag bits */
        struct in_addr ciaddr;  /* 12: Client IP address (if already in use) */
        struct in_addr yiaddr;  /* 16: Client IP address */
        struct in_addr siaddr;  /* 18: IP address of next server to talk to */
        struct in_addr giaddr;  /* 20: DHCP relay agent IP address */
        unsigned char chaddr [16];      /* 24: Client hardware address */
        char sname [DHCP_SNAME_LEN];    /* 40: Server name */
        char file [DHCP_FILE_LEN];      /* 104: Boot filename */
        unsigned char options [DHCP_MAX_OPTION_LEN];
                                /* 212: Optional parameters
                          (actual length dependent on MTU). */
};

u_int32_t sequencedhcp = 0x0000;
int dhcphase = 0;

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
	int rsock; 
	int len;
	int paquetes;
	int validacion=0;
	int packet = 0;
	unsigned char p_buffer[2048];
	struct sockaddr_ll p_info;
     	int p_size = sizeof(p_info);
	if(argc !=3){
		printf("Uso %s <interfaz> <no_paqutes> \n",argv[0]);
		exit(-1);
	}
	rsock = creaSocket(ETH_P_ALL);
	header();
	socketif(argv[1], rsock, ETH_P_ALL);
	paquetes = atoi(argv[2]);
	while(paquetes--){
		if((len = recvfrom(rsock, p_buffer, 2048, 0, (struct sockaddr*)&p_info, &p_size)) == -1){
			perror("Ha habido un error en la captura ");
			exit(-1);
		}else{
			printf("-------- Paquete Capturado No. %d ------------ \n",packet++);
			obtenerHEthernet(p_buffer, len);
			obtenerHIP(p_buffer, len);
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
	struct sockaddr_ll sll;
	struct ifreq ifr;
	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name,interfaz);

        if((ioctl(rsock, SIOCGIFINDEX, &ifr)) == -1){
                printf("No se puede obtener la interfaz !\n");
                exit(-1);
        }

 	if((ioctl(rsock, SIOCGIFFLAGS,&ifr)) < 0){
                perror("Error : Al obtener banderas de la interfaz ");
        }
        
	int flags=0;
        flags = ifr.ifr_flags;
        
      if((flags & IFF_UP) != 0)
                printf("Dispositivo arriba [UP] \n");
	else{
		printf("El dispositivo no existe no esta arriba \n ");
		exit(-1);
	}
	
	if((flags & IFF_PROMISC) != 0)
                printf("Dispositivo en modo Promiscuo \n");

	printf("La interfaz de captura es %s \n" ,interfaz);

	if((ioctl(rsock,SIOCGIFHWADDR,&ifr)) < 0){
		perror("Error : Al obtener MAC address ");
		exit(-1);
	}
	printf("La MAC de la interfaz es : ");
	impresionHex(ifr.ifr_hwaddr.sa_data,6);

        if((ioctl(rsock,SIOCGIFADDR,&ifr)) < 0){
                perror("Error : Al obtener direccion IP  ");
                exit(-1);
        }
        printf("La Direccion IP de la interfaz es : " );
        impresionFormatoIP(&ifr.ifr_addr.sa_data[2],4);

        if((ioctl(rsock,SIOCGIFNETMASK,&ifr)) < 0){
                perror("Error : Al obtener la mascara de red");
                exit(-1);
        }
        printf("La Mascara de red de la interfaz es : " );
        impresionFormatoIP(&ifr.ifr_netmask.sa_data[2],4);
	
        if((ioctl(rsock,SIOCGIFBRDADDR,&ifr)) < 0){
                perror("Error : Al obtener la direccion de broadcast");
                exit(-1);
        }
        printf("La direccion de broadcasr de la interfaz es : " );
        impresionFormatoIP(&ifr.ifr_broadaddr.sa_data[2],4);

	if((ioctl(rsock, SIOCGIFINDEX, &ifr)) == -1){
                printf("No se puede obtener la interfaz !\n");
                exit(-1);
        }


	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol); 
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
	struct ethhdr *h_ethernet;
	if(len > sizeof(struct ethhdr)){
		h_ethernet = (struct ethhdr *)packet;
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
	struct ether_arp *h_arp;
	struct iphdr *h_ip;
	int j =0 ;

	h_ethernet = (struct ethhdr *)packet;
	if(ntohs(h_ethernet->h_proto) == ETH_P_IP){
		if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr))){
			h_ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
			printf("IP Destino: %s\n", (char *)inet_ntoa(h_ip->daddr));
			printf("IP Origen : %s\n", (char *)inet_ntoa(h_ip->saddr));
		}else
			printf("HIP : Paquete de tamano insuficiente \n");
	}else if(ntohs(h_ethernet->h_proto) == ETH_P_ARP){
			h_arp = (struct ether_arp*)(packet + sizeof(struct ethhdr));
			printf("ARP Sender ");
	}else{
		printf("Este no es un paquete que se tenga conocimiento \n ");
		printf("Protocolo %d ", ntohs(h_ethernet->h_proto));
	}
}


int obtenerHTCP(unsigned char *packet, int len){
	struct ethhdr *h_ethernet;
	struct iphdr *h_ip;
	struct tcphdr *h_tcp;
	struct udphdr *h_udp;
	struct icmphdr *icmp;
	struct dhcp_packet *dhcp;

	if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))){
		h_ethernet = (struct ethhdr *)packet;
		if(ntohs(h_ethernet->h_proto) == ETH_P_IP){
			h_ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
			if(h_ip->protocol == IPPROTO_TCP){
				printf("Protocolo TCP \n");
				h_tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + h_ip->ihl*4 );
				printf("Source Port: %d\n", ntohs(h_tcp->source));
				printf("Dest Port: %d\n", ntohs(h_tcp->dest));
				return 1;
			}else if (h_ip->protocol == IPPROTO_UDP){
				printf("Protocolo UDP \n");
				h_udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + h_ip->ihl*4 );	
				printf("Source Port: %d\n", ntohs(h_udp->source));
                                printf("Dest Port: %d\n", ntohs(h_udp->dest));
				if(ntohs(h_udp->dest) == 67 || ntohs(h_udp->source) == 67 ){
				     printf("Mensajes DHCP \n");
					dhcp = (struct dhcp_packet*) (packet + sizeof(struct ethhdr) + h_ip->ihl*4 + sizeof(struct udphdr));
					printf("TRANSACTION ID %x \n", dhcp->xid);
					if (dhcp->op == 1 && sequencedhcp == dhcp->xid)
						printf("DHCP REQUEST \n ");
					else if (dhcp->op == 1 ){
						printf("DHCP DISCOVER \n");
						sequencedhcp = dhcp->xid; 	
						printf("Este es el proceso %x \n",  dhcp->xid);
					}
                                        else if (dhcp->op == 2 && dhcphase !=0){
                                                printf("DHCP ACK \n");
                                                sequencedhcp = 0x00000000 ;
                                                dhcphase = 0;
                                        }
					else if (dhcp->op == 2){
                                                printf("DHCP OFFER \n");
						dhcphase ++ ;
					}
				}
				return 1;
			}else if (h_ip->protocol == IPPROTO_ICMP){
				printf("Protocolo ICMP \n");
				icmp =  (struct icmphdr*)(packet +  h_ip->ihl*4);
				if ( icmp->type == ICMP_INFO_REQUEST )
					printf(" ICMP peticion desde %s \n", (char *)inet_ntoa(h_ip->saddr));
				else if ( icmp->type == ICMP_ECHO )
					printf(" ICMP echo desde %s \n", (char *)inet_ntoa(h_ip->daddr));
				else if ( icmp->type == ICMP_ECHOREPLY )
					printf(" ICMP echoreply desde %s \n", (char *)inet_ntoa(h_ip->daddr));
				else if ( icmp->type == ICMP_DEST_UNREACH )
					printf(" ICMP destino inalcanzable desde %s \n", (char *)inet_ntoa(h_ip->saddr));
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
		h_ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
		data = (packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
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
