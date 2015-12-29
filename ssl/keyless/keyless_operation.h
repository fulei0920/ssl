#ifndef __KEYLESS_OPERATION_H__
#define __KEYLESS_OPERATION_H__

#include <openssl/ossl_typ.h>
#include <openssl/ec.h>
typedef struct 
{
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int fd;
}KEY_LESS_CONNECTION;

int kssl_op_rsa_decrypt(KEY_LESS_CONNECTION *kl_conn, RSA *rsa_pubkey, int len, unsigned char *from , unsigned char *to, int padding);
int kssl_op_rsa_sign(KEY_LESS_CONNECTION *kl_conn, int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, RSA *rsa_pubkey);
int kssl_op_ecdsa_sign(KEY_LESS_CONNECTION *kl_conn, int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, EC_KEY *ecdsa_pubkey);	 


#endif
