/*
 * ruleset_parser.h
 *
 *  Created on: 7 de jul. de 2016
 *      Author: sokolik
 */

#ifndef SRC_RULESET_PARSER_H_
#define SRC_RULESET_PARSER_H_



int nftnl_ruleset_set_elems(const struct nftnl_parse_ctx *ctx);
int nftnl_ruleset_parse_set(const struct nftnl_parse_ctx *ctx);

int nftnl_ruleset_rule_build_msg(const struct nftnl_parse_ctx *ctx,
				      uint32_t cmd, struct nftnl_rule *rule);

int nftnl_ruleset_rule(const struct nftnl_parse_ctx *ctx);

int nftnl_ruleset_flush_rules(const struct nftnl_parse_ctx *ctx);

int nftnl_ruleset_chain(const struct nftnl_parse_ctx *ctx);

int nftnl_ruleset_table_build_msg(const struct nftnl_parse_ctx *ctx,
				       uint32_t cmd, struct nftnl_table *table);
int nftnl_ruleset_table(const struct nftnl_parse_ctx *ctx);

int nftnl_ruleset_flush_ruleset(const struct nftnl_parse_ctx *ctx);

int ruleset_elems_cb(const struct nftnl_parse_ctx *ctx);


#endif /* SRC_RULESET_PARSER_H_ */
