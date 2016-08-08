#ifndef _SSL_H_
#define _SSL_H_

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tcp.h"

struct ssl_conf {
	int ipproto;
	unsigned short port;
	union {
		struct {
			struct 	in_addr inet_addr;
		} ipv4;
		struct {
			struct 	in6_addr inet_addr6;
			int 	scope_id;
		} ipv6;
	} server;
	union {
		struct		in_addr inet_addr;
	struct 			in6_addr inet_addr6;
	} client;
};

struct ssl_server {
	int 			fd;
	int 			sd;
	union {
		struct 		sockaddr_in ipv4;
		struct		sockaddr_in6 ipv6;
	} addr;
	socklen_t		socklen;
	SSL_CTX			*ctx;
	BIO			*sbio;
	SSL			*ssl;
};

enum ssl_client_state {
	SSL_DISCONNECTED	= 0,
	SSL_CONNECTING,
	SSL_CONNECTED
};


#define SSL_SERVER_LISTEN 20

struct ssl_server;

struct ssl_server *ssl_server_create(struct ssl_conf *conf);
int ssl_listen(struct ssl_conf *conf);
void ssl_server_destroy(struct ssl_server *c);
int ssl_server_get_fd(struct ssl_server *c);
int ssl_server_accept(struct ssl_server *c, struct sockaddr_in *addr);
void configure_context(SSL_CTX *ctx);
void init_openssl(void);
void cleanup_openssl(void);



struct ssl_client;

struct ssl_client *ssl_client_create(struct ssl_conf *conf);
void ssl_client_destroy(struct ssl_client *c);
int ssl_client_get_fd(struct ssl_client *c);
ssize_t ssl_client_send(struct ssl_client *c, const void *data, int size);
ssize_t ssl_client_recv(struct ssl_client *c, void *data, int size);
void ssl_client_set_data(struct ssl_client *c, void *data);
void *ssl_client_get_data(struct ssl_client *c);
SSL_CTX *create_context(void);

#endif /*_SSL_H_ */
