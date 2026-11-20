#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1


#include "axil-internal.h"

void axil_ssl_drop(struct descr *d)
{
	if (!d->cSSL)
		return;
	/* Best-effort close_notify first: tearing TLS down with a bare
	 * shutdown()/close() leaves strict clients (OpenSSL 3.5+, current
	 * browsers) reporting truncation and discarding the response they
	 * already received -- observed live as a login 303 + Set-Cookie
	 * that never took effect. Non-blocking: at most two SSL_shutdown
	 * calls, never wait on the peer. */
	for (int i = 0; i < 2; i++) {
		int r = SSL_shutdown(d->cSSL);
		if (r == 1)
			break;
		int e = SSL_get_error(d->cSSL, r);
		if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
			break;
	}
	SSL_free(d->cSSL);
	d->cSSL = NULL;
}

int ssl_accept(socket_t fd)
{
	/* fprintf(stderr, "ssl_accept %d\n", fd); */
	struct descr *d = &descr_map[fd];
	int res = SSL_accept(d->cSSL);

	d->flags &= ~DF_ACCEPTED;

	if (res > 0) {
		d->flags |= DF_ACCEPTED;
		return 0;
	}

	int ssl_err = SSL_get_error(d->cSSL, res);
	/* A non-blocking handshake needs to be resumed from descr_proc_writes
	 * when either side of the socket is not ready. */
	if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
		return 0;

	ERR("SSL_accept %d %d %d %d %s\n", fd, res, ssl_err, errno,
	    ERR_error_string(ssl_err, NULL));

	unsigned long openssl_err;
	while ((openssl_err = ERR_get_error()) != 0) {
		char buf[256];
		ERR_error_string_n(openssl_err, buf, sizeof(buf));
		ERR("OpenSSL: %s\n", buf);
	}

	ERR_clear_error();
	axil_close(fd);
	return 1;
}

io_ssize_t
axil_ssl_low_read(socket_t fd, void *to, io_size_t len, int flags UNUSED)
{
	return SSL_read(descr_map[fd].cSSL, to, len);
}

io_ssize_t
axil_ssl_lower_write(socket_t fd, void *from, io_size_t len, int flags UNUSED)
{
	struct descr *d = &descr_map[fd];
	if (!d->cSSL)
		return -1;
	return SSL_write(d->cSSL, from, len);
}

static int axil_sni(SSL *ssl, int *ad UNUSED, void *arg UNUSED)
{
	const char *servername =
	        SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername)
		return SSL_TLSEXT_ERR_NOACK; // no SNI

	const cert_t *cert = corm_get(cert_hd, servername);

	if (cert == NULL)
		return SSL_TLSEXT_ERR_NOACK;

	SSL_set_SSL_CTX(ssl, cert->ctx);

	return SSL_TLSEXT_ERR_OK;
}

/* Speak what we implement. Add h2 here when HTTP/2 exists. */
static int axil_alpn_select(
        SSL *ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *arg)
{
	const unsigned char *p;
	const unsigned char *end;
	unsigned int len;

	(void)ssl;
	(void)arg;
	p = in;
	end = in + inlen;
	while (p < end) {
		len = *p++;
		if (p + len > end)
			break;
		if (len == 8 && !memcmp(p, "http/1.1", 8)) {
			*out = p;
			*outlen = (unsigned char)len;
			return SSL_TLSEXT_ERR_OK;
		}
		p += len;
	}
	return SSL_TLSEXT_ERR_NOACK;
}

SSL_CTX *axil_ctx_new(char *crt, char *key)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	CBUG(!ctx, "SSL_CTX_new\n");

	SSL_CTX_set_alpn_select_cb(ctx, axil_alpn_select, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, axil_sni);

	CBUG(!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION),
	     "set_min_proto_version\n");

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	CBUG(!SSL_CTX_set_cipher_list(
	             ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4"),
	     "set_cipher_list\n");

	(void)SSL_CTX_set_ciphersuites(
	        ctx, "TLS_AES_256_GCM_SHA384:"
	             "TLS_AES_128_GCM_SHA256:"
	             "TLS_CHACHA20_POLY1305_SHA256");

	CBUG(!SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384:P-521"),
	     "set1_groups_list\n");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	SSL_CTX_set_ecdh_auto(ctx, 1);
	SSL_CTX_set_dh_auto(ctx, 1);
#else
	FILE *fp = fopen("/etc/ssl/dhparam.pem", "r");
	CBUG(!fp, "open dhparam.pem\n");
	DH *dh = PEM_read_DHparams(fp, NULL, NULL, NULL);
	CBUG(!dh, "PEM_read_DHparams\n");
	SSL_CTX_set_tmp_dh(ctx, dh);
#endif

	CBUG(SSL_CTX_use_certificate_chain_file(ctx, crt) <= 0,
	     "use_certificate_chain_file\n");
	CBUG(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0,
	     "use_privatekey_file\n");
	CBUG(!SSL_CTX_check_private_key(ctx),
	     "private key does not match certificate\n");

	return ctx;
}

int openssl_error_callback(const char *str, size_t len, void *u)
{
	(void)u;
	ERR("%.*s\n", (int)len, str);
	return 0;
}

void _axil_cert_add(char *domain, char *crt, char *key)
{
	SSL_CTX *ssl_ctx = axil_ctx_new(crt, key);
	cert_t cert = {
		.crt = crt,
		.key = key,
		.domain = domain,
		.ctx = ssl_ctx,
	};

	unsigned id = corm_put(cert_hd, domain, &cert);
	WARN("%u '%s' '%s' '%s'\n", id, domain, crt, key);
	if (!domain_default)
		domain_default = domain;
}
