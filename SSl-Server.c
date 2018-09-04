//SSL-Server.c
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <math.h> 
#include <stdlib.h>
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



 char a[1024],rec[1024];
 int p;char ka[1024],has1[1024];
  
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
   	 
    
   // HMAC_Update(&ctx, (unsigned char*)&data, strlen(data));
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_cleanup(&ctx);
 
    printf("HMAC digest: ");
 
    for (int i = 0; i != len; i++)
        printf("%02x", (unsigned int)result[i]);
 
    printf("\n");
 
    //free(result);
 
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

 
 
 int n,g,x;
 
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
 
int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;
 
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
     	printf("3");
}
 
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
 
}
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
     	printf("2");
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
 
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    
    char common_key[1024];
    
    int a1,ret;
    int sd, bytes;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
    
    MCRYPT td, td2;
  char * plaintext = "sagar jawanjal";
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = "0123456789abcdef";
  int keysize = 16; /* 128 bits */
  char* buffer;
  int buffer_len = 16;

  buffer = calloc(1, buffer_len);
    
    		
 	
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf);   /* construct reply */
            SSL_write(ssl, "hello-client", strlen(reply)); /* send reply */
            
            printf("Enter the value of n and g : ");
 	    scanf("%d%d",&n,&g);
            
            printf("Enter the value of x for the first person : ");
 		scanf("%d",&x);
 		a1=power(g,x,n);
            
           tostring(a,a1);
           
           printf("%s %d",a, a1);
            
            SSL_write(ssl,a,sizeof(a));
            
            SSL_read(ssl,ka, sizeof(ka));
      
      		int  result = toint(ka);
      		 printf("Received: \"%s\"\n",ka);
     		    printf("Received: \"%d\"\n",result);
     		    
     		     p=power(result,x,n);
         
         printf("Common secret-key for server is : %lld\n",p);
            
             SSL_read(ssl,has1, sizeof(has1));
         
        
          //tostring(a,p);
        tostring(a,p);
         printf("%s",has1);
         
        hash(has1);
        hash(a);
         if (strcmp(a,has1) == 0)
       {
  	    printf("Client Authenticated.\n"); 
   	
   	}else{
   	    printf("Client Not Authenticated.\n");
   					   }


//====================================================================================================================================


  strncpy(buffer, plaintext, buffer_len);

  printf("==C==\n");
  printf("plain:   %s\n", plaintext);
  
  strcat(a,key);
  printf("%s",a);
  
  encrypt(buffer, buffer_len, IV, a, keysize);
   printf("cipher:  "); display(buffer , buffer_len);
  char arr[33];
    
    for(int i=0;i<buffer_len;i++)
    {
      //printf("%d ",buffer[i]);
      arr[i]=buffer[i];    
    }
    
    SSL_write(ssl,arr,sizeof(arr));
   
  printf("cipher:  "); display(buffer , buffer_len);
  
  //printf("size=%d",sizeof(buffer));
  
  //decrypt(buffer, buffer_len, IV, key, keysize);
 // printf("decrypt: %s\n", buffer);




 				
         
        
            
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
    
     	//printf("4");
}
 
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server,err;
    char *portnum;
    char *msg = "sagar";
 	printf("1");
 
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
     	printf("12");
    SSL_library_init();
 
 
    portnum = strings[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl,*ssl1;
 
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        
        
        Servlet(ssl);
        
       //  ssl1 = SSL_new(ctx);              /* get new SSL state with context */
        //SSL_set_fd(ssl1, client);      /* set connection socket to SSL state */
        // err=SSL_write(ssl1,msg,strlen(msg));
         //RETURN_SSL(err);
        
        
       // Servlet(ssl1);
       
         //tostring(a,p);
         //printf("%s %d\n",a,p);
         //printf("%s",has1);
      
       //
       //hash(p);
       
       
      
         
       
       
        
         	printf("22");         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
