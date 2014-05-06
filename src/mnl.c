/*
 * Copyright (c) 2013 Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * Almost copied from 'nftables' project:
 *
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * TODO: provide abstract of these functions in libnftnl, later.
 */

#include <errno.h>
#include <stdlib.h>

#include "mnl.h"
#include "linux/netfilter/nf_tables.h"
#include "linux/netfilter.h"

static int seq;

static int
nfts_mnl_talk(struct mnl_socket *nf_sock, const void *data, unsigned int len,
	      int (*cb)(const struct nlmsghdr *nlh, void *data), void *cb_data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t portid = mnl_socket_get_portid(nf_sock);
	int ret;

	if (mnl_socket_sendto(nf_sock, data, len) < 0)
		return -1;

	ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, cb, cb_data);
		if (ret <= 0)
			goto out;

		ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
	}
out:
	if (ret < 0 && errno == EAGAIN)
		return 0;

	return ret;
}

/*
 * Rule
 */
static int rule_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_rule_list *nlr_list = data;
	struct nft_rule *r;

	r = nft_rule_alloc();
	if (r == NULL)
		return -1;

	if (nft_rule_nlmsg_parse(nlh, r) < 0)
		goto err_free;

	nft_rule_list_add_tail(r, nlr_list);
	return MNL_CB_OK;

err_free:
	nft_rule_free(r);
	return MNL_CB_OK;
}

struct nft_rule_list *mnl_rule_dump(struct mnl_socket *nf_sock, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_rule_list *nlr_list;
	int ret;

	nlr_list = nft_rule_list_alloc();
	if (nlr_list == NULL)
		return NULL;

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
				       NLM_F_DUMP, seq);

	ret = nfts_mnl_talk(nf_sock, nlh, nlh->nlmsg_len, rule_cb, nlr_list);
	if (ret < 0)
		goto err;

	return nlr_list;
err:
	nft_rule_list_free(nlr_list);
	return NULL;
}

/*
 * Chain
 */
static int chain_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_chain_list *nlc_list = data;
	struct nft_chain *c;

	c = nft_chain_alloc();
	if (c == NULL)
		return -1;

	if (nft_chain_nlmsg_parse(nlh, c) < 0)
		goto err_free;

	nft_chain_list_add_tail(c, nlc_list);
	return MNL_CB_OK;

err_free:
	nft_chain_free(c);
	return MNL_CB_OK;
}

struct nft_chain_list *mnl_chain_dump(struct mnl_socket *nf_sock, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_chain_list *nlc_list;
	int ret;

	nlc_list = nft_chain_list_alloc();
	if (nlc_list == NULL)
		return NULL;

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, family,
					NLM_F_DUMP, seq);

	ret = nfts_mnl_talk(nf_sock, nlh, nlh->nlmsg_len, chain_cb, nlc_list);
	if (ret < 0)
		goto err;

	return nlc_list;
err:
	nft_chain_list_free(nlc_list);
	return NULL;
}

/*
 * Table
 */

static int table_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_table_list *nlt_list = data;
	struct nft_table *t;

	t = nft_table_alloc();
	if (t == NULL)
		return -1;

	if (nft_table_nlmsg_parse(nlh, t) < 0)
		goto err_free;

	nft_table_list_add_tail(t, nlt_list);
	return MNL_CB_OK;

err_free:
	nft_table_free(t);
	return MNL_CB_OK;
}

struct nft_table_list *mnl_table_dump(struct mnl_socket *nf_sock, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_table_list *nlt_list;
	int ret;

	nlt_list = nft_table_list_alloc();
	if (nlt_list == NULL)
		return NULL;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, family,
					NLM_F_DUMP, seq);

	ret = nfts_mnl_talk(nf_sock, nlh, nlh->nlmsg_len, table_cb, nlt_list);
	if (ret < 0)
		goto err;

	return nlt_list;
err:
	nft_table_list_free(nlt_list);
	return NULL;
}

/*
 * Set
 */

static int set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_set_list *nls_list = data;
	struct nft_set *s;

	s = nft_set_alloc();
	if (s == NULL)
		return -1;

	if (nft_set_nlmsg_parse(nlh, s) < 0)
		goto err_free;

	nft_set_list_add_tail(s, nls_list);
	return MNL_CB_OK;

err_free:
	nft_set_free(s);
	return MNL_CB_OK;
}

struct nft_set_list *
mnl_set_dump(struct mnl_socket *nf_sock, int family, const char *table)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_set *s;
	struct nft_set_list *nls_list;
	int ret;

	s = nft_set_alloc();
	if (s == NULL)
		return NULL;

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET, family,
				      NLM_F_DUMP|NLM_F_ACK, seq);
	nft_set_attr_set(s, NFT_SET_ATTR_TABLE, table);
	nft_set_nlmsg_build_payload(nlh, s);
	nft_set_free(s);

	nls_list = nft_set_list_alloc();
	if (nls_list == NULL)
		goto err;

	ret = nfts_mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_cb, nls_list);
	if (ret < 0)
		goto err;

	return nls_list;
err:
	nft_set_list_free(nls_list);
	return NULL;
}

static void
nft_set_list_merge(struct nft_set_list *dest, struct nft_set_list *orig)
{
	struct nft_set_list_iter *it;
	struct nft_set *o;

	it = nft_set_list_iter_create(orig);
	if (it == NULL)
		return;

	o = nft_set_list_iter_next(it);
	while (o != NULL) {
		nft_set_list_add_tail(o, dest);
		o = nft_set_list_iter_next(it);
	}

	nft_set_list_iter_destroy(it);
}


/*
 * Set elements
 */

static int set_elem_cb(const struct nlmsghdr *nlh, void *data)
{
	nft_set_elems_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

int mnl_setelem_get(struct mnl_socket *nf_sock, struct nft_set *nls)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t family = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY);

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM, family,
				      NLM_F_DUMP|NLM_F_ACK, seq);
	nft_set_nlmsg_build_payload(nlh, nls);

	return nfts_mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_elem_cb, nls);
}

/*
 * ruleset
 */

struct nft_ruleset *mnl_ruleset_dump(struct mnl_socket *nf_sock)
{
	struct nft_ruleset *rs;
	struct nft_rule_list *r;
	struct nft_chain_list *c;
	struct nft_set_list *complete_set_list = NULL, *s;
	struct nft_table_list *t;
	struct nft_table_list_iter *it;
	struct nft_table *o;
	const char *table;
	uint16_t family;

	t = mnl_table_dump(nf_sock, NFPROTO_UNSPEC);
	if (t == NULL)
		return NULL;

	rs = nft_ruleset_alloc();
	if (rs == NULL)
		return NULL;

	nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_TABLELIST, t);

	c = mnl_chain_dump(nf_sock, NFPROTO_UNSPEC);
	if (c != NULL)
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_CHAINLIST, c);

	r = mnl_rule_dump(nf_sock, NFPROTO_UNSPEC);
	if (r != NULL)
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_RULELIST, r);

	it = nft_table_list_iter_create(t);
	if (it == NULL)
		return NULL;

	o = nft_table_list_iter_next(it);
	while (o != NULL) {
		table = nft_table_attr_get_str(o, NFT_TABLE_ATTR_NAME);
		family = nft_table_attr_get_u32(o, NFT_TABLE_ATTR_FAMILY);

		s = mnl_set_dump(nf_sock, family, table);
		if (s != NULL) {
			if (complete_set_list == NULL) {
				complete_set_list = nft_set_list_alloc();
				if (complete_set_list == NULL)
					return NULL;
			}

			nft_set_list_merge(complete_set_list, s);
			nft_set_list_free(s);
		}
		o = nft_table_list_iter_next(it);
	}
	nft_table_list_iter_destroy(it);

	if (complete_set_list != NULL)
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_SETLIST,
				     complete_set_list);

	return rs;
}

/*
 * netlink
 */
static struct mnl_socket *netlink_socket_open(void)
{
	return mnl_socket_open(NETLINK_NETFILTER);
}

int nfts_socket_open(struct nft_sync_inst *inst)
{
	struct mnl_socket *s = netlink_socket_open();
	if (s == NULL)
		return -1;

	inst->nl_query_sock = s;
	return 0;
}

void nfts_socket_close(struct nft_sync_inst *inst)
{
	mnl_socket_close(inst->nl_query_sock);
}

#define SNPRINTF_BUFSIZ 4096

const char *netlink_dump_ruleset(struct mnl_socket *s)
{
	struct nft_ruleset *rs;
	size_t bufsiz = SNPRINTF_BUFSIZ;
	char *buf;
	int ret;

	buf = calloc(1, bufsiz);
	if (buf == NULL)
		return NULL;

	rs = mnl_ruleset_dump(s);
	if (rs == NULL) {
		free(buf);
		return NULL;
	}

	ret = nft_ruleset_snprintf(buf, bufsiz, rs, NFT_OUTPUT_XML, 0);
	if (ret > SNPRINTF_BUFSIZ) {
		free(buf);
		buf = calloc(1, ret);
		if (buf == NULL) {
			nft_ruleset_free(rs);
			return NULL;
		}

		bufsiz = ret;
		ret = nft_ruleset_snprintf(buf, bufsiz, rs, NFT_OUTPUT_XML, 0);
	}

	nft_ruleset_free(rs);
	return buf;
}
