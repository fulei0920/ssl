#include "crypto.h"

#include "kssl.h"
#include "kssl_helper.h"



void kssl_op_rsa_decrypt(KEY_LESS_CONNECTION *kl_conn, RSA *rsa_pubkey, int len, unsigned char *from , unsigned char *to, int padding)
{
	kssl_operation req, resp;
	kssl_header *h;
	kssl_header decrypt;
	
	decrypt.version_maj = KSSL_VERSION_MAJ;
	decrypt.id = 0x1234567a;
	
	zero_operation(&req);
	req.is_opcode_set = 1;
	req.is_payload_set = 1;
	req.is_digest_set = 1;
	//req.is_ip_set = 1;
	//req.ip = ipv6;
	//req.ip_len = 16;
	req.playload = OPENSSL_malloc(len);
	req.playload_len = len;
	req.digest = OPENSSL_malloc(KSSL_DIGEST_SIZE);
	
	digest_public_rsa(rsa_pubkey, req.digest);
	req.opcode = KSSL_OP_RSA_DECRYPT;
	
	h = kssl(kl_conn->ssl, &decrypt, &req);
	parse_message_payload(h->data, h->length, &resp);
	memcpy(to, resp.playload, resp.playload_len);
	ok(h);
	
	OPENSSL_free(req.payload);
	OPENSSL_free(req.digest);
}


// digest_public_rsa: calculates the SHA256 digest of the
// hexadecimal representation of the public modulus of an RSA
// key. digest must be initialized with at least 32 bytes of
// space.
void digest_public_rsa(RSA *key, BYTE *digest)
{
	// QUESTION: can we use a single EVP_MD_CTX for multiple
	// digests?
	char *hex;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
	hex = BN_bn2hex(key->n);
	EVP_DigestUpdate(ctx, hex, strlen(hex));
	EVP_DigestFinal_ex(ctx, digest, 0);
	EVP_MD_CTX_destroy(ctx);
	OPENSSL_free(hex);
}

// digest_public_ec: calculates the SHA256 digest of the
// hexadecimal representation of the EC public key group and
// point. digest must be initialized with at least 32 bytes of
// space.
void digest_public_ec(EC_KEY *ec_key, BYTE *digest) 
{
	const EC_POINT *ec_pub_key = EC_KEY_get0_public_key(ec_key);
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	char *hex = EC_POINT_point2hex(group, ec_pub_key, POINT_CONVERSION_COMPRESSED, NULL);
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
	EVP_DigestUpdate(ctx, hex, strlen(hex));
	EVP_DigestFinal_ex(ctx, digest, 0);
	EVP_MD_CTX_destroy(ctx);
	OPENSSL_free(hex);
}


