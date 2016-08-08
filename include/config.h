#ifndef _NFT_CONFIG_H_
#define _NFT_CONFIG_H_

#include <limits.h>
#include <stdbool.h>
#include "tcp.h"
#include "fd.h"
#include "proto.h"

#include <libmnl/libmnl.h>
enum nft_protocol {
	NFTS_PROTOCOL_TCP = 0,
	NFTS_PROTOCOL_SSL = 1,
};

enum nft_sync_mode {
	NFTS_MODE_SERVER	= (1 << 0),
	NFTS_MODE_CLIENT	= (1 << 1),
};

enum nft_sync_cmd {
	NFTS_CMD_NONE		= 0,
	NFTS_CMD_FETCH,
	NFTS_CMD_MAX,
	NFTS_CMD_PULL
};

struct nft_sync_inst {
	enum nft_sync_mode	mode;
	enum nft_sync_cmd	cmd;
	enum nft_protocol protocol;
	bool			stop;
	struct {
		bool		color;
		int		type;
		char		filename[PATH_MAX];
		FILE		*fd;
	} log;
	struct tcp_conf		tcp;
	struct nft_fd		tcp_client_nfd;
	struct nft_fd		tcp_server_fd;
	struct mnl_socket	*nl_query_sock;
	char			*rule;
	char			*rules_dir;
	char			*ssl_ca;
	char			*ssl_ca_server;
	char			*ssl_ca_server_key;
	char			*ssl_ca_client;
	char			*ssl_ca_client_key;
};

extern struct nft_sync_inst nfts_inst;

int nft_sync_config_parse(const char *filename);


#define NFTS_RULES_DIR_DEFAULT	"/etc/nft-sync/rules/"

#define SSL_CA 			"/etc/nft-sync/ca/ca.crt"
#define SSL_CA_SERVER 		"/etc/nft-sync/ca/server.crt"
#define SSL_CA_SERVER_KEY 	"/etc/nft-sync/ca/private/server.key"
#define SSL_CA_CLIENT 		"/etc/nft-sync/ca/client.crt"
#define SSL_CA_CLIENT_KEY 	"/etc/nft-sync/ca/private/client.key"



#endif /* _NFT_CONFIG_H_ */
