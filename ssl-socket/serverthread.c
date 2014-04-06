#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>		
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h> 	
#include <openssl/err.h>
#include <pthread.h>			
	/* Libreria de POXIS thread */
#define FAIL   -1
#define NUM_THREADS     5



/*Estructura que se usara como argumento*/
struct thread_data{
   int  thread_id;
   /* Identidificador de hilo */
   SSL *message;
   /* Estado ssl de la conexion */
};



/*--- CrearSocket ----------------------------------*/
/*Crea un socket normal para implementarle SSL -----*/

int CrearSocket(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
        perror("Error al ligar el socket");
        abort();
    }
    if ( listen(sd, 10) != 0 ) {
        perror("Error en el listen");
        abort();
    }
    return sd;
}

/*--- IniciarCTXServidor ---------------------------*/
/*Inicializa el servidor y crea el contexto server -*/

SSL_CTX* IniciarCTXServidor(void) {
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();		
    SSL_load_error_strings();			
    method = SSLv2_server_method();		
    ctx = SSL_CTX_new(method);			
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (SSL_CTX_set_cipher_list(ctx, "DES-CBC3-MD5") == 1) {
        printf("Si se pudo establecer \n");
    } else {
        printf("No se pudo establecer \n");
    }
    return ctx;
}

/*--- CargarCertificados ---------------------------*/
/*Carga los certificados del servidor y CA   -------*/

void CargarCertificados(SSL_CTX* ctx, char* CertFile, char* KeyFile) {

    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
        printf("No se pudo usar el archivo de certificado \n");
        ERR_print_errors_fp(stderr);
        abort();
    } else {
        printf("Certificado cargado \n");
    }

    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
        printf("No se pudo usar el archivo de llave \n");
        ERR_print_errors_fp(stderr);
        abort();
    } else {
        printf("Llave cargada. \n");
    }

    if ( !SSL_CTX_check_private_key(ctx) ) {
        printf("No se pudo usar el archivo de certificado \n");
        fprintf(stderr, "La llave primaria no corresponde al certificado publico \n");
        abort();
    } else {struct thread_data{
   int  thread_id;
   int  sum;
   char *sslsocket;
};

        printf("Certificado y Llave validos. \n");
    }
}


/*--- MostrarCertificados --------------------------*/
/*Imprime los certificados -------------------------*/

void MostrarCertificados(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	
    if ( cert != NULL ) {
        printf("Certificados del servidor:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);   
        printf("Emisor: %s\n", line);
        free(line);
        X509_free(cert);					     
    } else {
        printf("No hay certificados.\n");
    }
}


/*--- Servidor ---------- --------------------------*/
/*Realizar el procedimiento servicio ---------------*/

void *Servidor(void *threadarg)	{	
    char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho="Esto solo es el mensaje de mi servidor SSL multihilo";

   /*Estructura donde se guardan los parametros de los threads */
   struct thread_data *my_data;
   int taskid;
   
    /*Parser de los datos de la estructura a variables */
    my_data = (struct thread_data *) threadarg;
    taskid = my_data->thread_id;
    SSL *ssl = my_data->sslsocket;


    printf("Inicia Servidor \n");
    if ( SSL_accept(ssl) == FAIL ) {			
        printf("Hubo un error en el SSL_accept \n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("SSL_accept fue exitoso \n");
        MostrarCertificados(ssl);					
        bytes = SSL_read(ssl, buf, sizeof(buf));	
        if ( bytes > 0 ) {
            buf[bytes] = 0;
            printf("Mensaje cliente: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf);		
	    sleep(5);
            SSL_write(ssl, reply, strlen(reply));	
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);			
    SSL_free(ssl);				
    close(sd);					
}





/*--- Main -----------------------------------------*/
/*Se encarga de crear el servidor ------------------*/

int main(int count, char *strings[]) {
    pthread_t threads[NUM_THREADS];		/* Arreglo de hilos */
    struct thread_data thread_data_array[NUM_THREADS];
    int t=0;
    int rc;
    SSL_CTX *ctx;		
    int server;			
    char *portnum;		
    SSL_library_init();		

    if ( count != 2 ) {
        printf("Uso: %s <portnum>\n", strings[0]);
        exit(0);
    }
    portnum = strings[1];
    ctx = IniciarCTXServidor();      
    CargarCertificados(ctx, "serv.pem", "serv.key");		
    server = CrearSocket(atoi(portnum));			
    printf("Esperando por conexiones [%d] \n", server);
    printf("Inicia a aceptar conexiones \n");
    while (1) {
	struct sockaddr_in addr;
	SSL *ssl;
        int len = sizeof(addr);
        int client = accept(server, (struct sockaddr*)&addr, &len);  
        printf("Connection: %d:%d\n",
        	inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));  

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);		  
        if (!SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL)) {
            fprintf(stderr,"Certificado Invalido\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        }	


        ssl = SSL_new(ctx);
		 /*Se crea contexto*/
        SSL_set_fd(ssl, client);	
	  t++;
		/*Se da numero de pthread */
	  thread_data_array[t].thread_id = t;
		/*Se le da el id del thread al thread */
   	  thread_data_array[t].message = ssl;
		/*Se le da el asigna el contexto de la conexion al thread */
        rc = pthread_create(&threads[t], NULL, Servlet, (void *) &thread_data_array[t]);
		/*Se crea el hilo y se le manda la estructura rellenada previamente */
    }
    close(server);			
    SSL_CTX_free(ctx);			
}
