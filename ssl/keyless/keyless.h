#ifndef __KEYLESS_H__
#define __KEYLESS_H__

#include <openssl/ossl_typ.h>
//#include "kssl.h"

typedef struct
{
	SSL_CTX *ssl_ctx;
	

} KEY_LESS_CTX;

typedef struct 
{
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int fd;
}KEY_LESS_CONNECTION;


extern KEY_LESS_CTX *key_less_ctx;

int KEYLESS_init();
KEY_LESS_CTX* KEY_LESS_CTX_new();
KEY_LESS_CONNECTION* KEY_LESS_CONNECTION_new(KEY_LESS_CTX *kl_ctx, int fd);
int KEY_LESS_CONNECTION_init(KEY_LESS_CONNECTION* kl_conn, KEY_LESS_CTX *kl_ctx, int fd);
void KEY_LESS_CONNECTION_free(KEY_LESS_CONNECTION *kl_conn);
int KEY_LESS_client_new(int *sock);


int kssl_op_rsa_decrypt(KEY_LESS_CONNECTION *kl_conn, RSA *rsa_pubkey, int len, unsigned char *from , unsigned char *to, int padding);
int kssl_op_rsa_sign_md5sha1(KEY_LESS_CONNECTION *kl_conn, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, RSA *rsa_pubkey);
#endif
