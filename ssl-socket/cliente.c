#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>		/* Libreria para los socket*/
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h> 	/* Libreria de openssl para la funcionalidad y contextos */
#include <openssl/err.h>	/* Libreria de openssl para errores */
#define FAIL    -1

/*---------------------------------------------------------------------*/
/*--- CrearSocket - Se crea el socket y se conecta al servidor   ---*/
/*---------------------------------------------------------------------*/
int CrearSocket(const char *hostname, int port) {

    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL ) {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- IniciarCTXCliente - Inicializa el motor SSL para el cliente             ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* IniciarCTXCliente(void) {
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();               /* Carga los ciphers de cifrado */
    SSL_load_error_strings();                   /* Carga los mensajes de error de SSL */
    method = SSLv2_client_method();             /* Crea una instancia del metodo cliente en SSLv2 */
    ctx = SSL_CTX_new(method);                  /* Crea el contexto para el metodo de cliente */

   /* Se elige la suite que se desea usar, en este caso "DES-CBC3-SHA"*/
    if (SSL_CTX_set_cipher_list(ctx, "DES-CBC3-MD5") == 1) {
        printf("Si se pudo establecer \n");
    } else {
        printf("No se pudo establecer \n");
    }
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
  
    /* Asigan el certificado al contexto */
    if ( SSL_CTX_use_certificate_file(ctx, "cliente.pem", SSL_FILETYPE_PEM) <= 0 ) {
        printf("No se pudo usar el archivo de certificado \n");
        ERR_print_errors_fp(stderr);
        abort();
    } else {
        printf("Se uso el certificado. \n");
    }
    /* Asigna la llave primaria al contexto */
    if ( SSL_CTX_use_PrivateKey_file(ctx, "cliente.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    } else {
        printf("Se uso el certificado. \n");
    }
    /* Se hace una verificacion de la llave */
    if ( !SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    } else {
        printf("Coincidieron certificado y llave. \n");
    }
    return ctx;
}
/*---------------------------------------------------------------------*/
/*--- MostrarCertificados - imprime los certificados.                       ---*/
/*---------------------------------------------------------------------*/
void MostrarCertificados(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Mapeo de los certificados a X509 */
    if ( cert != NULL ) {
        printf("Certificados del servidor:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  /* Obtencion del subject */
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);   /* Obtencion del emisor */
        printf("Emisor: %s\n", line);
        free(line);
        X509_free(cert);					     /* Se liberan los datos del certificado */
    } else {
        printf("No hay certificados.\n");
    }
}
/*---------------------------------------------------------------------*/
/*--- main - Crea el contexto SSL y se conecta                      ---*/
/*---------------------------------------------------------------------*/
int main(int count, char *strings[]) {
    SSL_CTX *ctx;		/* Se usara para crear un contexo SSL */
    int server;			/* Se usara como descriptor de archivo del socket del server */
    SSL *ssl;			/* Se usara para la parte de SSL */
    char buf[1024];		/* Se usara para mandar un mensaje al server */
    int bytes;			/* Se usara para definir el numero de bytes enviados al server */
    char *hostname, *portnum;	/* Se usara para dar el hostname y numero de puerto del socket */

    SSL_library_init();		/* Inicializacion de las librerias de openssl */
    if ( count != 3 ) {
        printf("uso: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
        hostname = strings[1];
        portnum = strings[2];

    ctx = IniciarCTXCliente();		/* Inicio del contexto de SSL */
    server = CrearSocket(hostname, atoi(portnum));   /* Se hace la conexion al servidor con socket normal */
    ssl = SSL_new(ctx);                                 /* Crea el estado de la conexion SSL */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);   	
        if (!SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL)) {
                        fprintf(stderr,"Certificado Invalido\n");
                ERR_print_errors_fp(stderr);
                exit(1);
        }
	 /*Se hace una verificacion del certificado mediante la CA */

    SSL_set_fd(ssl, server);                          /* Se asigna el socket al estado SSL para conectarse al server */
    if ( SSL_connect(ssl) == FAIL ) {                 /* Se realiza la conexion */
        ERR_print_errors_fp(stderr);
    } else {
        printf("Lista de ciphers: \"%s\" \n", SSL_get_cipher_list(ssl, 200));
        char *msg = "Mesaje enviado desde el cliente \n Hola server";
        printf("Conectado con cifrado \"%s\"\n", SSL_get_cipher(ssl));
        printf("Valor del verify: [%ld] \n", SSL_get_verify_result(ssl));
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            printf("No se valido como X509_V_OK \n");
        } else {
            printf("Validado como X509 \n");
        }

        MostrarCertificados(ssl);                                 /* Impresion de los certificados */
        SSL_write(ssl, msg, strlen(msg));               /* Envio del mensaje al servidor por medio del socket ssl*/
        bytes = SSL_read(ssl, buf, sizeof(buf));        /* Obtiene el mensaje del servidor */
        buf[bytes] = 0;
        printf("Recibido: \"%s\"\n", buf);
        SSL_free(ssl);                                  /* Libera el estado de la conexion */
    }
    close(server);                                      /* Cierra el socket */
    SSL_CTX_free(ctx);                                  /* Libera el contexto */
}

