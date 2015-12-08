#include ""

KEY_LESS_CTX  *key_less_ctx == NULL;
char *KEY_LESS_ca_file = ;
char *KEY_LESS_client_cert = ;
char *KEY_LESS_client_key = ;
unsigned short KEY_LESS_port =;
char *KEY_LESS_ip = "";




int KEY_LESS_init()
{
	key_less_ctx = KEY_LESS_CTX_new();
}

KEY_LESS_CTX* KEY_LESS_CTX_new()
{
	KEY_LESS_CTX *kl_ctx == NULL;
	SSL_CTX *ssl_ctx == NULL;
	const char * cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH";
	char *ec_curve_name = "prime256v1";

	kl_ctx = OPENSSL_malloc(sizeof(KEY_LESS_CTX));
	if(kl_ctx == NULL)
	{
		goto err;
	}
	
	ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
	if(ssl_ctx == NULL)
	{
		goto err;
	}
	
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	if (SSL_CTX_set_cipher_list(ssl_ctx, cipher_list) == 0) 
	{
		goto err;
	}

	int nid = OBJ_sn2nid(ec_curve_name);
	if (NID_undef == nid) 
	{
		SSL_CTX_free(ctx);
		fatal_error("ECDSA curve not present");
	}
	EC_KEY *ecdh = EC_KEY_new_by_curve_name(nid);
	if (NULL == ecdh)
	{
		SSL_CTX_free(ctx);
		fatal_error("ECDSA new curve error");
	}
	if(SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1) 
	{
		SSL_CTX_free(ctx);
		fatal_error("Call to SSL_CTX_set_tmp_ecdh failed");
	}

	if (SSL_CTX_load_verify_locations(ssl_ctx, KEY_LESS_ca_file, 0) != 1)
	{
		//fatal_error("Failed to load CA file %s", ca_file);
		goto err;
	}

	if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1)
	{
		//fatal_error("Call to SSL_CTX_set_default_verify_paths failed");
		goto err;
	}

	if (SSL_CTX_use_certificate_file(ssl_ctx, KEY_LESS_client_cert, SSL_FILETYPE_PEM) != 1)
	{
		//fatal_error("Failed to load client certificate from %s", client_cert);
		goto err;
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_LESS_client_key, SSL_FILETYPE_PEM) != 1)
	{
		//fatal_error("Failed to load client private key from %s", client_key);
		goto err;
	}

	if (SSL_CTX_check_private_key(ctx) != 1) 
	{
		//fatal_error("SSL_CTX_check_private_key failed");
		goto err;
	}

	kl_ctx->ssl_ctx = ssl_ctx;
	
	return 1;
err:
	if(klc != NULL)
		OPENSSL_free(klc);
	if(sc != NULL)
		SSL_CTX_free(sc);

	return 0;
	
}


KEY_LESS_CONNECTION* KEY_LESS_CONNECTION_new(KEY_LESS_CTX *kl_ctx, int fd)
{
	KEY_LESS_CONNECTION  *kl_conn;

	if(kl_ctx == NULL || fd == -1)
	{
		return NULL;
	}
	
    kl_conn = OPENSSL_malloc(sizeof(KEY_LESS_CONNECTION));
	if(kl_conn == NULL)
	{
		return NULL;
	}
	
	if(KEY_LESS_CONNECTION_init(kl_conn, kl_ctx, fd) == 0)
	{
		OPENSSL_free(kl_conn);
		return NULL;
	}

	return kl_conn;
	
}

int KEY_LESS_CONNECTION_init(KEY_LESS_CONNECTION* kl_conn, KEY_LESS_CTX *kl_ctx, int fd)
{
	SSL *ssl;
	
	ssl = SSL_new(kl_ctx->ssl_ctx)
	if(ssl == NULL)
	{
		return 0;
	}
	
	if(SSL_set_fd(ssl, fd) == 0)
	{
		SSL_free(ssl)
		return 0;
		
	}
		
	SSL_set_connect_state(ssl);

	kl_conn->ssl_ctx = kl_ctx->ssl_ctx;
	kl_conn->ssl = ssl;
	kl_conn->fd = fd;
	return 1;
}



void KEY_LESS_CONNECTION_free(KEY_LESS_CONNECTION *kl_conn)
{
	if(kl_conn->ssl != NULL)
	{
		SSL_free(kl_conn->ssl);
	}
	if(kl_conn->fd != -1)
	{
		close(fd);
	}
	OPENSSL_free(kl_conn);
}


int KEY_LESS_client_new(int *sock)
//int init_tcp_client(int *sock,  int port, char *ip)
{
	struct socketaddr_in server;
	int s = -1;
	unsigned short port;
	
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	servr.sin_port = htons((unsigned short) port);
	
	
	if((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
	{
		goto err;
	}
	if(connect(s, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
		goto err;
	}
	*sock = s;
	
	return 1;
		
err:
	if( s != -1)
	{
		close(s);
	}
		
	return 0;
}





// kssl: send a KSSL message to the server and read the response
kssl_header *kssl(SSL *ssl, kssl_header *k, kssl_operation *r)
{
  BYTE buf[KSSL_HEADER_SIZE];
  BYTE *req;
  int req_len;
  int n;
  kssl_header h;
  kssl_header *to_return;
  
  

  flatten_operation(k, r, &req, &req_len);

  //dump_header(k, "send");
  //dump_request(r);

  n = SSL_write(ssl, req, req_len);
  if (n != req_len)
  {
    //fatal_error("Failed to send KSSL header");
	return NULL;
  }

  free(req);

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
    fatal_error("ID mismatch %08x != %08x", k->id, h.id);
	return NULL;
  }

 // dump_header(&h, "recv");

  to_return = (kssl_header *)malloc(sizeof(kssl_header));
  memcpy(to_return, &h, sizeof(kssl_header));


  if (h.length > 0) 
  {
    BYTE *payload = (BYTE *)malloc(h.length);
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
		return NULL;
		}
		else 
		{
          //fatal_error("Error performing SSL_read: %x\n", x);
          return NULL;
        }
      } else 
     	{
        if (n != h.length)
		{
          //fatal_error("Error receiving KSSL payload, size: %d", n);
          return NULL;
        }
      }

      break;
    }

    if (n != h.length) 
	{
      //fatal_error("Failed to read payload got length %d wanted %d", n, h.length);
      	return NULL;
    }

    dump_payload(h.length, payload);
    to_return->data = payload;
  }

  return to_return;
}



