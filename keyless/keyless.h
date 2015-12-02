

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

int KEY_LESS_init();
KEY_LESS_CTX* KEY_LESS_CTX_new();
KEY_LESS_CONNECTION* KEY_LESS_CONNECTION_new(KEY_LESS_CTX *kl_ctx, int fd);
int KEY_LESS_CONNECTION_init(KEY_LESS_CONNECTION* kl_conn, KEY_LESS_CTX *kl_ctx, int fd);
int KEY_LESS_client_new(int *sock);
kssl_op_rsa_decrypt(KEY_LESS_CONNECTION *kl_conn, RSA *rsa_pubkey, int len, unsigned char *from , unsigned char *to, int padding);
kssl_header *kssl(SSL *ssl, kssl_header *k, kssl_operation *r)
void digest_public_rsa(RSA *key, BYTE *digest);
void digest_public_ec(EC_KEY *ec_key, BYTE *digest); 