/*
 * (C) 2016 by Enrique Rodriguez Valencia <erguezvalencia@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <timer.h>

#include "ssl.h"
#include "logging.h"



struct ssl_client {
	int			fd;
	enum ssl_client_state	state;
	union {
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	} addr;
	socklen_t		socklen;
	struct nft_timer	timer;
	void 			*data;
	SSL_CTX			*ctx;
	BIO			*sbio;
	SSL			*ssl;
};

static int ssl_client_init(struct ssl_client *c, struct ssl_conf *conf)
{
	int ret, err;
	const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;;

	c->fd = socket(conf->ipproto, SOCK_STREAM, 0);
	if (c->fd < 0)
		return -1;

	switch (conf->ipproto) {
	case AF_INET:
		c->addr.ipv4.sin_family = AF_INET;
		c->addr.ipv4.sin_port = htons(conf->port);
		c->addr.ipv4.sin_addr = conf->client.inet_addr;
		c->socklen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		c->addr.ipv6.sin6_family = AF_INET6;
		c->addr.ipv6.sin6_port = htons(conf->port);
		c->addr.ipv6.sin6_addr = conf->client.inet_addr6;
		c->socklen = sizeof(struct sockaddr_in6);
		break;
	default:
		ret = -1;
		break;
	}

	init_openssl();


	if ((c->ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL) {
		nfts_log(NFTS_LOG_SSL,"error creating SSL context");
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_load_verify_locations(c->ctx, nfts_inst.ssl_ca, NULL)) {
		nfts_log(NFTS_LOG_SSL,"CA %s does not exist or incorrect" , nfts_inst.ssl_ca);
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_use_certificate_file(c->ctx, nfts_inst.ssl_ca_client, SSL_FILETYPE_PEM)) {
		nfts_log(NFTS_LOG_SSL,"client certificate %s does not exists or incorrect" ,nfts_inst.ssl_ca_client);
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_use_PrivateKey_file(c->ctx, nfts_inst.ssl_ca_client_key, SSL_FILETYPE_PEM)) {
		nfts_log(NFTS_LOG_SSL,"client key %s does not exists or incorrect" , nfts_inst.ssl_ca_client_key);
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_check_private_key(c->ctx)) {
		nfts_log(NFTS_LOG_SSL,"problem checking cert/key");
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_mode(c->ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(c->ctx, 1);
	SSL_CTX_set_options(c->ctx,flags);

	c->fd = socket (AF_INET, SOCK_STREAM, 0);
	if (c->fd < 0)
		return c->fd;
	err = connect(c->fd, (struct sockaddr*)&c->addr,c->socklen);
	if (err < 0)
		goto err1;

	c->ssl = SSL_new(c->ctx);
	SSL_set_fd (c->ssl, c->fd);
	ret = SSL_connect(c->ssl);
	if (ret < 0) {
		switch (errno) {
		case EINPROGRESS:
			c->state = SSL_CONNECTING;
			break;
		default: /* ECONNREFUSED */
			c->state = SSL_DISCONNECTED;
			goto err1;
		}
	} else {
		/* very unlikely at this stage. */
		c->state = SSL_CONNECTED;
	}

	return 0;
err1:
	close(c->fd);
	return ret;
}

struct ssl_server *ssl_server_create(struct ssl_conf *conf)
{
	int ret;
	struct ssl_server *c;

	init_openssl();
	c = calloc(1, sizeof(struct ssl_server));
	if (c == NULL)
		return NULL;

	if ((c->ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL){
		nfts_log(NFTS_LOG_SSL,"error creating SSL context");
		exit(EXIT_FAILURE);
	}

	if (!SSL_CTX_load_verify_locations(c->ctx, nfts_inst.ssl_ca, NULL)){
		nfts_log(NFTS_LOG_SSL,"CA %s does not exist or incorrect" , nfts_inst.ssl_ca);
		exit(EXIT_FAILURE);
	}

	if (!SSL_CTX_use_certificate_file(c->ctx, nfts_inst.ssl_ca_server, SSL_FILETYPE_PEM)){
		nfts_log(NFTS_LOG_SSL,"server certificate %s does not exists or incorrect" ,nfts_inst.ssl_ca_server);
		exit(EXIT_FAILURE);
	}

	if (!SSL_CTX_use_PrivateKey_file(c->ctx, nfts_inst.ssl_ca_server_key, SSL_FILETYPE_PEM)){
		nfts_log(NFTS_LOG_SSL,"server key %s does not exists or incorrect" , nfts_inst.ssl_ca_server_key);
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_check_private_key(c->ctx)){
		nfts_log(NFTS_LOG_SSL,"problem checking cert/key");
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_mode(c->ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify_depth(c->ctx, 1);

	/* setup socket – socket()/bind()/listen() +*/
	switch (conf->ipproto) {
	case AF_INET:
		c->addr.ipv4.sin_family = AF_INET;
		c->addr.ipv4.sin_port = htons(conf->port);
		c->addr.ipv4.sin_addr = conf->server.ipv4.inet_addr;
		c->socklen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		c->addr.ipv6.sin6_family = AF_INET6;
		c->addr.ipv6.sin6_port = htons(conf->port);
		c->addr.ipv6.sin6_addr = conf->server.ipv6.inet_addr6;
		c->addr.ipv6.sin6_scope_id = conf->server.ipv6.scope_id;
		c->socklen = sizeof(struct sockaddr_in6);
		break;
	}

	ret = ssl_listen(conf);
	if (ret < 0)
		goto err;
	c->fd = ret;
	return c;
err:
	close(c->fd);
	return NULL;
}


struct ssl_client *ssl_client_create(struct ssl_conf *conf)
{
	struct ssl_client *c;

	c = calloc(1, sizeof(struct ssl_client));
	if (c == NULL)
		return NULL;

	if (ssl_client_init(c, conf) < 0) {
		free(c);
		return NULL;
	}
	return c;
}

int ssl_listen(struct ssl_conf *conf)
{
	int sock;
	struct sockaddr_in sin;

	sock=socket(conf->ipproto,SOCK_STREAM,0);
	if (sock < 0)
		goto err1;
	memset(&sin,0,sizeof(sin));
	sin.sin_addr.s_addr=INADDR_ANY;
	sin.sin_family=conf->ipproto;
	sin.sin_port=htons(conf->port);

	if (bind(sock,(struct sockaddr *)&sin,sizeof(sin))<0)
		nfts_log(NFTS_LOG_FATAL,"Unable to bind");
	listen(sock,5);

	return(sock);
err1:
	return -1;
}

void ssl_server_destroy(struct ssl_server *c)
{
	close(c->fd);
	free(c);
}

int ssl_server_get_fd(struct ssl_server *c)
{
	return c->fd;
}

int ssl_server_accept(struct ssl_server *c, struct sockaddr_in *addr)
{
	int err;
	socklen_t socklen = sizeof(struct sockaddr_in);

	c->sd = accept(c->fd, (struct sockaddr *)addr, &socklen);
	err = fcntl(c->fd, F_SETFL, O_NONBLOCK);
	if (err < 0) {
		close(c->fd);
		return -1;
	}
	c->ssl=SSL_new(c->ctx);
	SSL_set_fd(c->ssl,c->sd);

err = SSL_accept(c->ssl);
	return err;
}

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

int ssl_client_get_fd(struct ssl_client *c)
{
	return c->fd;
}

ssize_t ssl_client_send(struct ssl_client *c, const void *data, int size)
{
	int ret=0;

	switch (c->state) {
	case SSL_DISCONNECTED:
		ret = -1;
		break;
	case SSL_CONNECTING:
		connect(c->fd, (struct sockaddr *)&c->addr, c->socklen);
		c->sbio=BIO_new_socket(c->fd, BIO_NOCLOSE);
		c->ssl=SSL_new(c->ctx);
		SSL_set_bio(c->ssl, c->sbio, c->sbio);
		ret = SSL_connect(c->ssl);

		if (ret < 0)
			return ret;

		c->state = SSL_CONNECTED;
		/* fall through ... */
	case SSL_CONNECTED:

		ret = SSL_write (c->ssl, data,size);
		if (ret <= 0) {
			/* errno == EPIPE || errno == ECONNRESET */
			c->state = SSL_DISCONNECTED;
			return ret;
		}
		break;
	}
	return ret;
}

ssize_t ssl_client_recv(struct ssl_client *c, void *data, int size)
{
	int ret=0;

	switch (c->state) {
	case SSL_DISCONNECTED:
		ret = -1;
		break;
	case SSL_CONNECTING:
		connect(c->fd, (struct sockaddr *)&c->addr, c->socklen);
		c->sbio=BIO_new_socket(c->fd, BIO_NOCLOSE);
		c->ssl=SSL_new(c->ctx);
		SSL_set_bio(c->ssl, c->sbio, c->sbio);
		ret = SSL_connect(c->ssl);

		if (ret < 0)
			return ret;

		c->state = SSL_CONNECTED;
		/* fall through ... */
	case SSL_CONNECTED:

		ret = SSL_read (c->ssl, data,size);
		if (ret <= 0) {
			/* errno == EPIPE || errno == ECONNRESET */
			c->state = SSL_DISCONNECTED;
			return ret;
		}
		break;
	}
	return ret;
}

void *ssl_client_get_data(struct ssl_client *c)
{
	return c->data;
}

void ssl_client_set_data(struct ssl_client *c, void *data)
{
	c->data = data;
}

void ssl_client_destroy(struct ssl_client *c)
{
	cleanup_openssl();
	close(c->fd);
	free(c);
}
