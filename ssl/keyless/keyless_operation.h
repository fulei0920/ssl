#ifndef __KEYLESS_OPERATION_H__
#define __KEYLESS_OPERATION_H__

void kssl_op_rsa_decrypt(KEY_LESS_CONNECTION *kl_conn, RSA *rsa_pubkey, int len, unsigned char *from , unsigned char *to, int padding);
#endif
