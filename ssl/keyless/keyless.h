#ifndef __KEYLESS_H__
#define __KEYLESS_H__

#include <openssl/ossl_typ.h>

typedef struct
{
	SSL_CTX *ssl_ctx;
	
} KEY_LESS_CTX;

extern KEY_LESS_CTX *key_less_ctx;

int KEY_LESS_init();

int KEY_LESS_rsa_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int KEY_LESS_rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int KEY_LESS_ecds_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
#endif
