#include <stdio.h>
#include <stdlib.h>
#include <fd.h>
#include <tcp.h>
#include <unistd.h>
#include <config.h>
#include <string.h>
#include <errno.h>

#include "init.h"
#include "logging.h"
#include "msg_buff.h"
#include "proto.h"
#include "config.h"
#include "mnl.h"

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include "ruleset_parser.h"

struct mnl_nlmsg_batch *batch;
uint32_t seq;

int nftnl_ruleset_set_elems(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_set_elems_iter *iter_elems;
	uint16_t nl_type, nl_flags;
	uint32_t cmd;
	struct nlmsghdr *nlh;
	struct nftnl_set *set;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	set = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_SET);
	if (set == NULL)
		return -1;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWSETELEM;
		nl_flags = NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELSETELEM;
		/* This will generate an ACK message for each request. When
		 * removing NLM_F_ACK, the kernel will only report when things
		 * go wrong
		 */
		nl_flags = NLM_F_ACK;
		break;
	default:
		goto err;
	}

	iter_elems = nftnl_set_elems_iter_create(set);
	if (iter_elems == NULL)
		goto err;

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), nl_type,
				      nftnl_set_get_u32(set,
							   NFTNL_SET_FAMILY),
				      nl_flags, seq++);

	nftnl_set_elems_nlmsg_build_payload_iter(nlh, iter_elems);
	mnl_nlmsg_batch_next(batch);

	nftnl_set_elems_iter_destroy(iter_elems);
	return 0;
err:
	return -1;
}

int nftnl_ruleset_parse_set(const struct nftnl_parse_ctx *ctx)
{

	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;
	struct nftnl_set *set;
	uint32_t cmd;
	int ret;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	set = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_SET);
	if (set == NULL)
		return -1;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWSET;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELSET;
		nl_flags = NLM_F_ACK;
		break;
	default:
		goto err;
	}

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      nl_type,
				      nftnl_set_get_u32(set,
							   NFTNL_SET_FAMILY),
				      nl_flags,
				      seq++);

	nftnl_set_nlmsg_build_payload(nlh, set);
	mnl_nlmsg_batch_next(batch);

	ret = nftnl_ruleset_set_elems(ctx);
	return ret;
err:
	return -1;
}

int nftnl_ruleset_rule_build_msg(const struct nftnl_parse_ctx *ctx,
				      uint32_t cmd, struct nftnl_rule *rule)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK;
		nftnl_rule_unset(rule, NFTNL_RULE_HANDLE);
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELRULE;
		nl_flags = NLM_F_ACK;
		break;
	case NFTNL_CMD_REPLACE:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_REPLACE|NLM_F_ACK;
		break;
	case NFTNL_CMD_INSERT:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		nftnl_rule_unset(rule, NFTNL_RULE_HANDLE);
		break;
	default:
		return -1;
	}

	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				       nl_type,
				       nftnl_rule_get_u32(rule,
							  NFTNL_RULE_FAMILY),
				       nl_flags,
				       seq++);

	nftnl_rule_nlmsg_build_payload(nlh, rule);
	mnl_nlmsg_batch_next(batch);

	return 0;
}

int nftnl_ruleset_rule(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_rule *rule;
	int ret;
	uint32_t cmd;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	rule = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_RULE);
	if (rule == NULL)
		return -1;

	ret = nftnl_ruleset_rule_build_msg(ctx, cmd, rule);

	return ret;
}

int nftnl_ruleset_flush_rules(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_rule *nlr;
	struct nftnl_table *nlt;
	struct nftnl_chain *nlc;
	uint32_t type;
	int ret;

	nlr = nftnl_rule_alloc();
	if (nlr == NULL)
		return -1;

	type = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_TYPE);
	switch (type) {
	case NFTNL_RULESET_TABLE:
		nlt = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_TABLE);
		nftnl_rule_set(nlr, NFTNL_RULE_TABLE,
				  nftnl_table_get(nlt, NFTNL_TABLE_NAME));
		nftnl_rule_set(nlr, NFTNL_RULE_FAMILY,
				nftnl_table_get(nlt, NFTNL_TABLE_FAMILY));
		break;
	case NFTNL_RULESET_CHAIN:
		nlc = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_CHAIN);
		nftnl_rule_set(nlr, NFTNL_RULE_TABLE,
				  nftnl_chain_get(nlc,
						     NFTNL_CHAIN_TABLE));
		nftnl_rule_set(nlr, NFTNL_RULE_CHAIN,
				  nftnl_chain_get(nlc,
						     NFTNL_CHAIN_NAME));
		nftnl_rule_set(nlr, NFTNL_RULE_FAMILY,
				nftnl_chain_get(nlc, NFTNL_TABLE_FAMILY));
		break;
	default:
		goto err;
	}

	ret = nftnl_ruleset_rule_build_msg(ctx, NFTNL_CMD_DELETE, nlr);
	nftnl_rule_free(nlr);

	return ret;
err:
	nftnl_rule_free(nlr);
	return -1;
}

int nftnl_ruleset_chain(const struct nftnl_parse_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;
	uint32_t cmd;
	struct nftnl_chain *chain;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	chain = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_CHAIN);
	if (chain == NULL)
		return -1;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWCHAIN;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELCHAIN;
		nl_flags = NLM_F_ACK;
		break;
	case NFTNL_CMD_FLUSH:
		return nftnl_ruleset_flush_rules(ctx);
	default:
		goto err;
	}

	nftnl_chain_unset(chain, NFTNL_CHAIN_HANDLE);
	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					nl_type,
					nftnl_chain_get_u32(chain,
							 NFTNL_CHAIN_FAMILY),
					nl_flags,
					seq++);

	nftnl_chain_nlmsg_build_payload(nlh, chain);
	mnl_nlmsg_batch_next(batch);

	return 0;
err:
	return -1;
}

int nftnl_ruleset_table_build_msg(const struct nftnl_parse_ctx *ctx,
				       uint32_t cmd, struct nftnl_table *table)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWTABLE;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELTABLE;
		nl_flags = NLM_F_ACK;
		break;
	case NFTNL_CMD_FLUSH:
		return nftnl_ruleset_flush_rules(ctx);
	default:
		return -1;
	}

	nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					nl_type,
					nftnl_table_get_u32(table,
							 NFTNL_TABLE_FAMILY),
					nl_flags,
					seq++);

	nftnl_table_nlmsg_build_payload(nlh, table);
	mnl_nlmsg_batch_next(batch);

	return 0;
}

int nftnl_ruleset_table(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_table *table;
	uint32_t cmd;
	int ret;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	table = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_TABLE);
	if (table == NULL)
		return -1;

	ret = nftnl_ruleset_table_build_msg(ctx, cmd, table);

	return ret;
}

int nftnl_ruleset_flush_ruleset(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_table *table;
	int ret;

	table = nftnl_table_alloc();
	if (table == NULL)
		return -1;

	ret = nftnl_ruleset_table_build_msg(ctx, NFTNL_CMD_DELETE, table);
	nftnl_table_free(table);

	return ret;
}

int ruleset_elems_cb(const struct nftnl_parse_ctx *ctx)
{
	uint32_t type;
	int ret;

	type = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_TYPE);

	switch (type) {
	case NFTNL_RULESET_TABLE:
		ret = nftnl_ruleset_table(ctx);
		break;
	case NFTNL_RULESET_CHAIN:
		ret = nftnl_ruleset_chain(ctx);
		break;
	case NFTNL_RULESET_RULE:
		ret = nftnl_ruleset_rule(ctx);
		break;
	case NFTNL_RULESET_SET:
		ret = nftnl_ruleset_parse_set(ctx);
		break;
	case NFTNL_RULESET_SET_ELEMS:
		ret = nftnl_ruleset_set_elems(ctx);
		break;
	case NFTNL_RULESET_RULESET:
		ret = nftnl_ruleset_flush_ruleset(ctx);
		break;
	default:
		return -1;
	}

	nftnl_ruleset_ctx_free(ctx);
	return ret;
}
