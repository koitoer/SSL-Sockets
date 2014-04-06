#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>		
	/* Libreria para los socket*/
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h> 	
	/* Libreria de openssl para la funcionalidad y contextos */
#include <openssl/err.h>	
	/* Libreria de openssl para errores */
#define FAIL    -1


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
		/* Carga los ciphers de cifrado */
    SSL_load_error_strings();			
		/* Carga los mensajes de error de SSL */
    method = SSLv2_server_method();		
		/* Crea una instancia del metodo servidor en SSLv2 */
    ctx = SSL_CTX_new(method);			
		/* Crea el contexto para el metodo de servidor */
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* Se elige la suite que se desea usar, en este caso "DES-CBC3-SHA"*/
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
	/* Asigan el certificado al contexto */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
        printf("No se pudo usar el archivo de certificado \n");
        ERR_print_errors_fp(stderr);
        abort();
    } else {
        printf("Certificado cargado \n");
    }
    /* Asigna la llave primaria al contexto */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
        printf("No se pudo usar el archivo de llave \n");
        ERR_print_errors_fp(stderr);
        abort();
    } else {
        printf("Llave cargada. \n");
    }
    /* Se hace una verificacion de la llave */
    if ( !SSL_CTX_check_private_key(ctx) ) {
        printf("No se pudo usar el archivo de certificado \n");
        fprintf(stderr, "La llave primaria no corresponde \n");
        abort();
    } else {
        printf("Certificado y Llave validos. \n");
    }
}

/*--- MostrarCertificados --------------------------*/
/*Imprime los certificados -------------------------*/

void MostrarCertificados(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	
	/* Mapeo de los certificados a X509 */
    if ( cert != NULL ) {
        printf("Certificados del servidor:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  
		/* Obtencion del subject */
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);   
		/* Obtencion del emisor */
        printf("Emisor: %s\n", line);
        free(line);
        X509_free(cert);					     
		/* Se liberan los datos del certificado */
    } else {
        printf("No hay certificados.\n");
    }
}

/*--- Servidor ---------- --------------------------*/
/*Realizar el procedimiento servicio ---------------*/

void Servidor(SSL* ssl)	{	
	/* Proporciona la funcionalidad del servidor */
    char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho="Esto solo es un mensaje ISO01|EOF";

    printf("Inicia Servidor \n");
    if ( SSL_accept(ssl) == FAIL ) {			
		/* Se hace el accept - SSL */
        printf("Hubo un error en el SSL_accept \n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("SSL_accept fue exitoso \n");
        MostrarCertificados(ssl);					
		/* Obtiene e imprime los certificados */
        bytes = SSL_read(ssl, buf, sizeof(buf));	
		/* Espera una peticion del cliente */
        if ( bytes > 0 ) {
            buf[bytes] = 0;
            printf("Mensaje cliente: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf);		
			/* Imprime peticion del cliente */
	    sleep(15);
            SSL_write(ssl, reply, strlen(reply));	
			/* Envia una respuesta al cliente */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);			
	/* Obtiene la conexion del socket */
    SSL_free(ssl);				
	/* Libera el estado SSL del cliente*/
    close(sd);					
	/* Cierra la conexion al cliente*/
}

/*--- Main  ----------------------------------------*/
/*Se encarga de crear el servidor ------------------*/

int main(int count, char *strings[]) {
    SSL_CTX *ctx;		
	/* Se crean un contexto para implementarse */
    int server;			
	/* Se va a usar para el socket del servidor */
    char *portnum;		
	/* Se usa como el numero de puerto */
    SSL_library_init();		
	/* Inicializacion de las librerias SSL !IMPORTANTE" */

    if ( count != 2 ) {
        printf("Uso: %s <portnum>\n", strings[0]);
        exit(0);
    }
    portnum = strings[1];
    ctx = IniciarCTXServidor();      
	/* Se inicializa el SSL para el contexto Server */
    CargarCertificados(ctx, "server.pem", "server.key");		
	/* Carga los certificados del servidor*/
    server = CrearSocket(atoi(portnum));			
	/* Crea el socket normal para el servidor */
    printf("Esperando por conexiones [%d] \n", server);
    printf("Inicia a aceptar conexiones \n");
    while (1) {
	struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  
		/* Esta en estado de aceptar conexiones */
        printf("Connection: %d:%d\n",
        	inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));  
		/* Muestra los datos del usuario que se conecta */

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);		  
		/*Verifica el certificado del servidor*/
        if (!SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL)) {
            fprintf(stderr,"Certificado Invalido\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        }	
	/*Se hace una verificacion del certificado mediante la CA */

        ssl = SSL_new(ctx);         	
		/* Se obtiene el nuevo estado SSL con su contexto*/
        SSL_set_fd(ssl, client);	
		/* Se asigna el socket al estado SSL para cliente */
        Servidor(ssl);			
		/* Proporciona la funcionalidad del servidor  (servicio) */
    }
    close(server);			
	/* Cierra el socket del servidor */
    SSL_CTX_free(ctx);			
	/* Libera la conexion */
}
