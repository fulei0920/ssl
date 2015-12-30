//#include "crypto.h"
#include "keyless_operation.h"
#include "ossl_typ.h"
#include <openssl/ssl.h>
#include <openssl/rsa.h>
//#include "keyless.h"
#include "kssl.h"
#include "kssl_helpers.h"


static void digest_public_rsa(RSA *key, BYTE *digest);
static void digest_public_ec(EC_KEY *ec_key, BYTE *digest);
static kssl_header *kssl(SSL *ssl, kssl_header *k, kssl_operation *r);
static BYTE rsa_decrypt_padding_to_opcode(int padding);
static BYTE rsa_digest_nid_to_opcode(int digest_nid);
static BYTE ecdsa_digest_nid_to_opcode(int digest_nid);

static unsigned char ipv6[16] = {0x0, 0xf2, 0x13, 0x48, 0x43, 0x01};
static unsigned char ipv4[4] = {127, 0, 0, 1};




int kssl_op_rsa_decrypt(KEY_LESS_CONNECTION *kl_conn, RSA *rsa_pubkey, int len, unsigned char *from , unsigned char *to, int padding)
{
	int opcode;
	kssl_operation req, resp;
	kssl_header *h;
	kssl_header decrypt;

	opcode = rsa_decrypt_padding_to_opcode(padding);
	if(opcode == 0)
	{
		return 0;
	}
	
	decrypt.version_maj = KSSL_VERSION_MAJ;
	decrypt.id = 0x1234567a;
	
	zero_operation(&req);
	req.is_opcode_set = 1;
	req.is_payload_set = 1;
	req.is_digest_set = 1;
	//req.is_ip_set = 1;
	//req.ip = ipv6;
	//req.ip_len = 16;
	req.payload = from;
	req.payload_len = len;
	req.digest = OPENSSL_malloc(KSSL_DIGEST_SIZE);
	
	digest_public_rsa(rsa_pubkey, req.digest);
	req.opcode = opcode;
	
	h = kssl(kl_conn->ssl, &decrypt, &req);
	if(h == NULL)
	{
		OPENSSL_free(req.digest);
		return 0;
	}

	if(parse_message_payload(h->data, h->length, &resp) != KSSL_ERROR_NONE)
	{
		OPENSSL_free(req.digest);
		OPENSSL_free(h->data);
		OPENSSL_free(h);
		return 0;
	}
	
	memcpy(to, resp.payload, resp.payload_len);

	OPENSSL_free(req.digest);
	OPENSSL_free(h->data);
	OPENSSL_free(h);
	
	return resp.payload_len;
}


int kssl_op_rsa_sign(KEY_LESS_CONNECTION *kl_conn, int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, RSA *rsa_pubkey)
{
	int i, rc, len, opcode;
	kssl_header *h;
	kssl_header sign;
	kssl_operation req, resp;
	
	opcode = rsa_digest_nid_to_opcode(type);
	if(opcode == 0)
	{
		return 0; 
	}

	sign.version_maj = KSSL_VERSION_MAJ;
	sign.id = 0x1234567a;
	zero_operation(&req);
	req.is_opcode_set = 1;
	req.is_payload_set = 1;
	req.is_digest_set = 1;
	//req.is_ip_set = 1;
	//req.ip = ipv4;
	//req.ip_len = 4;
	req.digest = OPENSSL_malloc(KSSL_DIGEST_SIZE);
	digest_public_rsa(rsa_pubkey, req.digest);
	req.payload = m;
	req.payload_len = m_len;
	req.opcode = opcode;

	h = kssl(kl_conn->ssl, &sign, &req);
	if(h == NULL)
	{
		OPENSSL_free(req.digest);
		return 0;
	}

	if(parse_message_payload(h->data, h->length, &resp) != KSSL_ERROR_NONE)
	{
		OPENSSL_free(req.digest);
		OPENSSL_free(h->data);
		OPENSSL_free(h);
		return 0;

	}

	memcpy(sigret, resp.payload, resp.payload_len);
	*siglen = resp.payload_len;
	
	OPENSSL_free(req.digest);
	OPENSSL_free(h->data);
	OPENSSL_free(h);

	return *siglen;
}


int kssl_op_ecdsa_sign(KEY_LESS_CONNECTION *kl_conn, int type, const unsigned char *m, unsigned int m_len,
             unsigned char *sigret, unsigned int *siglen, EC_KEY *ecdsa_pubkey)
{
	int i, rc, len, opcode;
	kssl_header *h;
	kssl_header sign;
	kssl_operation req, resp;
	
	opcode = ecdsa_digest_nid_to_opcode(type);
	if(opcode == 0)
	{
		return 0; 
	}

	sign.version_maj = KSSL_VERSION_MAJ;
	sign.id = 0x1234567a;
	zero_operation(&req);
	req.is_opcode_set = 1;
	req.is_payload_set = 1;
	req.is_digest_set = 1;
	//req.is_ip_set = 1;
	//req.ip = ipv4;
	//req.ip_len = 4;
	req.digest = OPENSSL_malloc(KSSL_DIGEST_SIZE);
	digest_public_ec(ecdsa_pubkey, req.digest);
	req.payload = m;
	req.payload_len = m_len;
	req.opcode = opcode;

	h = kssl(kl_conn->ssl, &sign, &req);
	if(h == NULL)
	{
		OPENSSL_free(req.digest);
		return 0;
	}

	if(parse_message_payload(h->data, h->length, &resp) != KSSL_ERROR_NONE)
	{
		OPENSSL_free(req.digest);
		OPENSSL_free(h->data);
		OPENSSL_free(h);
		return 0;

	}

	memcpy(sigret, resp.payload, resp.payload_len);
	*siglen = resp.payload_len;
	
	OPENSSL_free(req.digest);
	OPENSSL_free(h->data);
	OPENSSL_free(h);

	return *siglen;

}

// kssl: send a KSSL message to the server and read the response
static kssl_header *kssl(SSL *ssl, kssl_header *k, kssl_operation *r)
{
	BYTE buf[KSSL_HEADER_SIZE];
	BYTE *req;
	int req_len;
	int n;
	kssl_header h;
	kssl_header *to_return;


	if(flatten_operation(k, r, &req, &req_len) != KSSL_ERROR_NONE)
	{
		return NULL;
	}

	//dump_header(k, "send");
	//dump_request(r);

	n = SSL_write(ssl, req, req_len);
	if (n != req_len)
	{
		//fatal_error("Failed to send KSSL header");
		return NULL;
	}

	OPENSSL_free(req);

	while (1) 
	{
		n = SSL_read(ssl, buf, KSSL_HEADER_SIZE);
		if (n <= 0)
		{
			int x = SSL_get_error(ssl, n);
			if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
			{
				continue;
			}
			else if (x == SSL_ERROR_ZERO_RETURN) 
			{
				//fatal_error("Connection closed while reading header\n");
				return NULL;
			} 
			else
			{
				//fatal_error("Error performing SSL_read: %x\n", x);
				return NULL;
			}
		} 
		else 
		{
			if (n != KSSL_HEADER_SIZE)
			{
				//fatal_error("Error receiving KSSL header, size: %d", n);
				return NULL;
			}
		}

		break;
	}

	parse_header(buf, &h);
	if (h.version_maj != KSSL_VERSION_MAJ) 
	{
		//fatal_error("Version mismatch %d != %d", h.version_maj, KSSL_VERSION_MAJ);
		return NULL;
	}
	if (k->id != h.id) 
	{
		//fatal_error("ID mismatch %08x != %08x", k->id, h.id);
		return NULL;
	}

	// dump_header(&h, "recv");

	to_return = (kssl_header *)OPENSSL_malloc(sizeof(kssl_header));
	if(to_return == NULL)
	{
		return NULL;
	}
	memcpy(to_return, &h, sizeof(kssl_header));

	if (h.length > 0) 
	{
	    BYTE *payload = (BYTE *)OPENSSL_malloc(h.length);
		if(payload == NULL)
		{
			OPENSSL_free(to_return);
			return NULL;
		}
		
	    while (1) 
		{
			n = SSL_read(ssl, payload, h.length);
			if (n <= 0)
			{
				int x = SSL_get_error(ssl, n);
				if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE) 
				{
					continue;
				}
				else if (x == SSL_ERROR_ZERO_RETURN)
				{
					//fatal_error("Connection closed while reading payload\n");
					OPENSSL_free(payload);
					OPENSSL_free(to_return);
					return NULL;
				}
				else 
				{
					//fatal_error("Error performing SSL_read: %x\n", x);
					OPENSSL_free(payload);
					OPENSSL_free(to_return);
					return NULL;
				}
			} 
			else 
			{
				if (n != h.length)
				{
					//fatal_error("Error receiving KSSL payload, size: %d", n);
					OPENSSL_free(payload);
					OPENSSL_free(to_return);
					return NULL;
				}
			}

			break;
	    }

	    if (n != h.length) 
		{
	      	//fatal_error("Failed to read payload got length %d wanted %d", n, h.length);
	      	OPENSSL_free(payload);
			OPENSSL_free(to_return);
	      	return NULL;
	    }

		//dump_payload(h.length, payload);
		to_return->data = payload;
  	}

  	return to_return;
}


// digest_public_rsa: calculates the SHA256 digest of the
// hexadecimal representation of the public modulus of an RSA
// key. digest must be initialized with at least 32 bytes of
// space.
static void digest_public_rsa(RSA *key, BYTE *digest)
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
static void digest_public_ec(EC_KEY *ec_key, BYTE *digest) 
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

static BYTE rsa_decrypt_padding_to_opcode(int padding)
{
	switch(padding)
	{
		case RSA_NO_PADDING
			return KSSL_OP_RSA_DECRYPT_RAW;
		case RSA_PKCS1_PADDING
			return KSSL_OP_RSA_DECRYPT;
	}
	return 0;
}

static BYTE rsa_digest_nid_to_opcode(int digest_nid)
{
	switch (digest_nid)
	{
		case NID_md5_sha1:
			return KSSL_OP_RSA_SIGN_MD5SHA1;
		case NID_sha1:
			return KSSL_OP_RSA_SIGN_SHA1; 
		case NID_sha224:
			return KSSL_OP_RSA_SIGN_SHA224;
		case NID_sha256:
			return KSSL_OP_RSA_SIGN_SHA256;
		case NID_sha384:
			return KSSL_OP_RSA_SIGN_SHA384;
		case NID_sha512:
			return KSSL_OP_RSA_SIGN_SHA512;
	}

	return 0;
}

static BYTE ecdsa_digest_nid_to_opcode(int digest_nid)
{
	switch (digest_nid)
	{
		case NID_md5_sha1:
			return KSSL_OP_ECDSA_SIGN_MD5SHA1;
		case NID_sha1:
			return KSSL_OP_ECDSA_SIGN_SHA1; 
		case NID_sha224:
			return KSSL_OP_ECDSA_SIGN_SHA224;
		case NID_sha256:
			return KSSL_OP_ECDSA_SIGN_SHA256;
		case NID_sha384:
			return KSSL_OP_ECDSA_SIGN_SHA384;
		case NID_sha512:
			return KSSL_OP_ECDSA_SIGN_SHA512;
	}

	return 0;
}



