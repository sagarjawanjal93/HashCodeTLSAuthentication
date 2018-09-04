//SSL-Client.c
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
#include "math.h"
 
#define FAIL    -1
 
#include <mcrypt.h>

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

int encrypt(
    void* buffer,
    int buffer_len, /* Because the plaintext could include null bytes*/
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

int decrypt(
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

void display(char* ciphertext, int len){
  int v;
  for (v=0; v<len; v++){
    printf("%d ", ciphertext[v]);
  }
  printf("\n");
}
 
 
   
void hash(char data[]) {
    // The secret key for hashing
    const char key[] = "12345678";
 
    // The data that we're going to hash
    //char data[] = "hello world";
    
    // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
    // Change the length accordingly with your choosen hash engine.     
    unsigned char* result;
    unsigned int len = 20;
 
    result = (unsigned char*)malloc(sizeof(char) * len);
 
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
 
    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
   	 
    //HMAC_Update(&ctx, (unsigned char*)&data, strlen(data));
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_cleanup(&ctx);
 
    printf("HMAC digest: ");
 
    for (int i = 0; i != len; i++)
        printf("%02x", (unsigned int)result[i]);
 
    printf("\n");
 
    //free(result);
 
  //	  return result;
}
 
 
 
void tostring(char str[], int num)

{

    int i, rem, len = 0, n;

 

    n = num;

    while (n != 0)

    {

        len++;

        n /= 10;

    }

    for (i = 0; i < len; i++)

    {

        rem = num % 10;

        num = num / 10;

        str[len - (i + 1)] = rem + '0';

    }

    str[len] = '\0';

} 
 

int toint(char str[])

{

    int len = strlen(str);

    int i, num = 0;

 

    for (i = 0; i < len; i++)

    {

        num = num + ((str[len - (i + 1)] - '0') * pow(10, i));

    }

 

   return num;

}

int n,g,y;

long long int power(int a,int b,int mod)
{
 long long int t;
 if(b==1)
  return a;
 t=power(a,b/2,mod);
 if(b%2==0)
  return (t*t)%mod;
 else
  return (((t*t)%mod)*a)%mod;
}

long long int calculateKey(int a,int x,int n)
{
 return power(a,x,n);
}



int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
 
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
 
int main(int count, char *strings[])
{   SSL_CTX *ctx;
	char ka[1024],a[1024];
	int ka1;
    int server,a2,ret;
    SSL *ssl ,*ssl1;
    char buf[1024],buf1[1024];
    int bytes,bytes1;
    char *hostname, *portnum;
    
    
    MCRYPT td, td2;
  char * plaintext = "sagar jawanjal";
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = "0123456789abcdef";
  int keysize = 16; /* 128 bits */
  char* buffer;
  int buffer_len = 16;

  buffer = calloc(1, buffer_len);
 
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
 
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
   
   
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
   
   // ssl1 = SSL_new(ctx);      /* create new SSL connection state */
    //SSL_set_fd(ssl1, server);
   
   
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   char *msg = "Hello-Server";
    	
 
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
      
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        
         bytes = SSL_read(ssl,ka, sizeof(ka));
        buf1[bytes] = 0;
      	int  result = toint(ka);
       printf("Received: \"%s\"\n",ka);
         printf("Received: \"%d\"\n",result);
         
        
         printf("Enter the value of n and g : ");
 	    scanf("%d%d",&n,&g);
            
            printf("Enter the value of y for the second person : ");
 		scanf("%d",&y);
 		a2=power(g,y,n);
            
           tostring(a,a2);
           
           printf("%s %d",a, a2);
            
            SSL_write(ssl,a,sizeof(a));
         
         printf("Common secret-key for client is : %lld\n",power(result,y,n));
         
        
         int p=power(result,y,n);
          tostring(a,p);
         
         printf("%s%d",a,p);
         SSL_write(ssl,a,sizeof(a));
         
          printf("\nOTP SENT:----->VERIFICATION ");
         hash(a);
         
         
         printf("\n\n%s",a);
 	
 	printf("size=%d",sizeof(buffer));	
 	
 	
         SSL_read(ssl,buffer,16);
         
         strcat(a,key);
         printf("cipher:  "); display(buffer , buffer_len);
         
         decrypt(buffer, buffer_len, IV, a, keysize);
	 printf("decrypt: %s\n", buffer);
         
        //SSL_write(ssl, msg1, strlen(msg1));
        
        SSL_free(ssl);        /* release connection state */
    	//SSL_free(ssl1);
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
