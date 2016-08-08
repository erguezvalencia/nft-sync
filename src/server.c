/*
 * (C) 2014 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fd.h>
#include <tcp.h>
#include <unistd.h>
#include <config.h>
#include <string.h>
#include <errno.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


#include "init.h"
#include "logging.h"
#include "msg_buff.h"
#include "proto.h"
#include "config.h"
#include "proto.h"
#include "mnl.h"
#include "utils.h"
#include "ssl.h"


static struct ssl_server *sserver;

static int send_ruleset_offline(struct nft_fd *nfd, char *rule, enum nft_protocol type)
{
	struct msg_buff *msgb;
	struct nft_sync_hdr *hdr;
	int ret, ruleset_len;
	char filename[255];
	char *ruleset;
	long fsize;
	FILE *fp;

	sprintf(filename,nfts_inst.rules_dir);
	sprintf(filename + strlen(filename),rule);

	/* TODO: check if filename is vulnerable to local file inclusion */
	fp = fopen(filename, "r");
	if (!fp) {
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	ruleset=malloc(sizeof(char) * (fsize));
	fseek(fp, 0, SEEK_SET);
	fread(ruleset,fsize,1,fp);
	ruleset[strcspn(ruleset, "\n")] = '\0';
	fclose(fp);

	if (ruleset == NULL)
		return 0;

	ruleset_len = strlen(ruleset);

	msgb = msgb_alloc(sizeof(struct nft_sync_hdr) + ruleset_len);
	if (msgb == NULL) {
		xfree(ruleset);
		return -1;
	}

	hdr = msgb_put(msgb, sizeof(struct nft_sync_hdr) + ruleset_len);
	hdr->len = htonl(sizeof(struct nft_sync_hdr) + ruleset_len);
	memcpy(hdr->data, ruleset, ruleset_len);
	if (type == NFTS_PROTOCOL_TCP)
			ret = send(nfd->fd, msgb_data(msgb), msgb_len(msgb), 0);
	if (type == NFTS_PROTOCOL_SSL)
			ret = SSL_write (sserver->ssl, msgb_data(msgb), msgb_len(msgb));
	msgb_free(msgb);

	return ret;
}


static int send_ruleset(struct nft_fd *nfd, enum nft_protocol type)
{
	struct msg_buff *msgb;
	struct nft_sync_hdr *hdr;
	int ret=0, ruleset_len;
	const char *ruleset = netlink_dump_ruleset(nfts_inst.nl_query_sock);

	if (ruleset == NULL)
		return 0;

	ruleset_len = strlen(ruleset);

	msgb = msgb_alloc(sizeof(struct nft_sync_hdr) + ruleset_len);
	if (msgb == NULL) {
		xfree(ruleset);
		return -1;
	}

	hdr = msgb_put(msgb, sizeof(struct nft_sync_hdr) + ruleset_len);
	hdr->len = htonl(sizeof(struct nft_sync_hdr) + ruleset_len);
	memcpy(hdr->data, ruleset, ruleset_len);
	xfree(ruleset);

	if (type == NFTS_PROTOCOL_TCP)
		ret = send(nfd->fd, msgb_data(msgb), msgb_len(msgb), 0);
	if (type == NFTS_PROTOCOL_SSL)
		ret = SSL_write (sserver->ssl, msgb_data(msgb), msgb_len(msgb));
	msgb_free(msgb);

	return ret;
}


static int nfts_parse_request(struct nft_fd *nfd, const char *req, enum nft_protocol type)
{
	int ret = -1;
	char cmd[256];
	char *rule;
	const char *separator = ";";

	strncpy(cmd,req,sizeof(cmd)-1);
	if (strncmp(req, "fetch", strlen("fetch")) == 0)
		ret = send_ruleset(nfd, type);
	if (strncmp(req, "pull", strlen("pull")) == 0) {
		if(strstr(req, ";") != NULL) {
			rule = strtok(cmd, separator);
			rule = strtok(NULL, "");
			ret = send_ruleset_offline(nfd,rule,type);
		}
		else {
			ret = send_ruleset(nfd, type);
		}
	}

	return ret;
}


static void tcp_server_established_cb(struct nft_fd *nfd, uint32_t mask)
{
	struct msg_buff *msgb;
	struct nft_sync_hdr *hdr;
	uint32_t len;
	int ret;

	msgb = msgb_alloc(NFTS_MAX_REQUEST);
	ret = recv(nfd->fd, msgb_tail(msgb),
		msgb_size(msgb) - msgb_len(msgb), 0);
	if (ret == 0)
		goto err1;
	else if (ret < 0) {
		nfts_log(NFTS_LOG_ERROR, "cannot receive from client");
		goto err1;
	}
	msgb_put(msgb, ret);

	/* Not enough room for header yet, grab more bytes later */
	if (msgb_len(msgb) < sizeof(struct nft_sync_hdr))
		return;

	hdr = (struct nft_sync_hdr *) msgb_data(msgb);

	len = ntohl(hdr->len);

	if (len >= NFTS_MAX_REQUEST) {
		nfts_log(NFTS_LOG_ERROR, "discarding message too large %d",
			 len, NFTS_MAX_REQUEST);
		goto err1;
	}

	/* Not enough data to process this request yet */
	if (len < (uint32_t)ret)
		return;

	hdr = msgb_pull(msgb, len);
	if (hdr == NULL) {
		nfts_log(NFTS_LOG_FATAL, "cannot pull out header");
		goto err1;
	}
	ret = nfts_parse_request(nfd, hdr->data, NFTS_PROTOCOL_TCP);
	if (ret < 0) {
		if (ret == -1) {
			nfts_log(NFTS_LOG_ERROR, "cannot find rule");
			goto err1;
		}
		else {
			nfts_log(NFTS_LOG_ERROR, "discarding malformed request");
			goto err1;
		}
	}

	/* There's still some pending bytes from the stream in the message,
	 * move them at the head of the message buffer.
	 */
	if (msgb_len(msgb) > 0)
		msgb_burp(msgb);
	return;
err1:
	nfts_log(NFTS_LOG_NOTICE, "closing connection");
	msgb_free(msgb);
	close(nfd->fd);
	nft_fd_unregister(nfd);
	nft_fd_free(nfd);
}

static void ssl_server_established_cb(struct nft_fd *nfd, uint32_t mask)
{
	struct msg_buff *msgb;
	struct nft_sync_hdr *hdr;
	uint32_t len;
	int ret;

	msgb = msgb_alloc(NFTS_MAX_REQUEST);
	ret = SSL_read (sserver->ssl,  msgb_tail(msgb),
			   msgb_size(msgb) - msgb_len(msgb));
	if (ret == 0){
		ret=SSL_get_error(sserver->ssl,ret);
		goto err1;
	}
	else if (ret < 0) {
		nfts_log(NFTS_LOG_ERROR, "cannot receive from client");
		ret=SSL_get_error(sserver->ssl,ret);
		nfts_log(NFTS_LOG_ERROR, "%d", ret);

		goto err1;
	}
	msgb_put(msgb, ret);

	/* Not enough room for header yet, grab more bytes later */
	if (msgb_len(msgb) < sizeof(struct nft_sync_hdr))
		return;

	hdr = (struct nft_sync_hdr *) msgb_data(msgb);

	len = ntohl(hdr->len);

	if (len >= NFTS_MAX_REQUEST) {
		nfts_log(NFTS_LOG_ERROR, "discarding message too large %d",
			 len, NFTS_MAX_REQUEST);
		goto err1;
	}

	/* Not enough data to process this request yet */
	if (len < (uint32_t)ret)
		return;

	hdr = msgb_pull(msgb, len);
	if (hdr == NULL) {
		nfts_log(NFTS_LOG_FATAL, "cannot pull out header");
		goto err1;
	}

	ret = nfts_parse_request(nfd, hdr->data, NFTS_PROTOCOL_SSL);
	if (ret < 0) {
		if (ret == -1) {
			nfts_log(NFTS_LOG_ERROR, "cannot find rule");
			goto err1;
		}
		else {
			nfts_log(NFTS_LOG_ERROR, "discarding malformed request");
			goto err1;
		}
	}

	/* There's still some pending bytes from the stream in the message,
	 * move them at the head of the message buffer.
	 */
	if (msgb_len(msgb) > 0)
		msgb_burp(msgb);

	return;
err1:
	nfts_log(NFTS_LOG_NOTICE, "closing connection");
	msgb_free(msgb);
	close(sserver->sd);
	close(nfd->fd);
	nft_fd_unregister(nfd);
	nft_fd_free(nfd);
}

static void tcp_server_cb(struct nft_fd *nfd, uint32_t mask)
{
	struct nft_fd *accept_nfd;
	struct msg_buff *msgb;
	struct sockaddr_in addr;
	int fd;

	msgb = msgb_alloc(NFTS_MAX_REQUEST);
	if (msgb == NULL) {
		nfts_log(NFTS_LOG_ERROR, "OOM");
		return;
	}

	fd = tcp_server_accept(nfd->data, &addr);
	if (fd < 0) {
		msgb_free(msgb);
		nfts_log(NFTS_LOG_ERROR, "failed to accept socket");
		return;
	}
	nfts_log(NFTS_LOG_NOTICE, "accepted new connection from %s",
		 inet_ntoa(addr.sin_addr));

	accept_nfd = nft_fd_alloc();
	nft_fd_setup(accept_nfd, fd, tcp_server_established_cb, msgb);
	nft_fd_register(accept_nfd, EV_READ | EV_PERSIST);
}

static void ssl_server_cb(struct nft_fd *nfd, uint32_t mask)
{
	struct nft_fd *accept_nfd;
	struct msg_buff *msgb;
	struct sockaddr_in addr;
	int fd;

	msgb = msgb_alloc(NFTS_MAX_REQUEST);
	if (msgb == NULL) {
		nfts_log(NFTS_LOG_ERROR, "OOM");
		return;
	}

	fd = ssl_server_accept(nfd->data, &addr);
	if (fd < 0) {
		msgb_free(msgb);
		nfts_log(NFTS_LOG_ERROR, "failed to accept socket");
		close(sserver->sd);
		return;
	}
	nfts_log(NFTS_LOG_NOTICE, "accepted new connection from %s",
		 inet_ntoa(addr.sin_addr));

	accept_nfd = nft_fd_alloc();
	nft_fd_setup(accept_nfd, sserver->sd, ssl_server_established_cb, msgb);
	nft_fd_register(accept_nfd, EV_READ | EV_PERSIST);
}

int tcp_server_start(struct nft_sync_inst *inst)
{
	struct tcp_server *s;

	nfts_inst.tcp.ipproto = AF_INET;
	nfts_inst.tcp.port = 1234;

	s = tcp_server_create(&inst->tcp);
	if (s == NULL)
		return -1;

	nft_fd_setup(&inst->tcp_server_fd, tcp_server_get_fd(s),
		     tcp_server_cb, s);
	nft_fd_register(&inst->tcp_server_fd, EV_READ | EV_PERSIST);

	return 0;
}

int ssl_server_start(struct nft_sync_inst *inst)
{
	nfts_inst.tcp.ipproto = AF_INET;
	nfts_inst.tcp.port = 1234;

	sserver = ssl_server_create((struct ssl_conf *)&inst->tcp);
	if (sserver == NULL)
		return -1;

	nft_fd_setup(&inst->tcp_server_fd, ssl_server_get_fd(sserver),
			ssl_server_cb, sserver);
	nft_fd_register(&inst->tcp_server_fd, EV_READ | EV_PERSIST);

	return 0;
}
