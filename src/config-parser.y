%{
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
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <dirent.h>

#include "config.h"
#include "logging.h"

extern char *yytext;
extern int yylineno;

static int parse_addr(const char *text, struct in_addr *addr,
			 uint16_t *port)
{
	char *colon = strchr(text, ':');

	if (colon == NULL) {
		fprintf(stderr, "missing `:' to indicate port\n");
		return -1;
	}
	*colon = '\0';

	if (inet_pton(AF_INET, text, addr) < 0) {
		fprintf(stderr, "%s not valid IPv4 address\n", text);
		return -1;
	}
	*port = atoi(colon + 1);

	return 0;
}

%}

%union {
	int	val;
	char	*string;
	char 	*dir;
}


%token T_LOCAL_ADDR
%token T_REMOTE_ADDR
%token T_ADDR
%token T_NUMBER
%token T_LOG
%token T_MODE
%token T_RULES_DIR
%token T_PROTOCOL
%token T_SSL_CA
%token T_SSL_CA_SERVER
%token T_SSL_CA_SERVER_KEY
%token T_SSL_CA_CLIENT
%token T_SSL_CA_CLIENT_KEY

%token <string> T_STRING
%token <val>	T_INTEGER
%token <dir>	T_DIR

%%

configfile	:
		| sections
		;

sections	: section
		| sections section
		;

section		: network
		| log
		;

network		: local_addr
		| remote_addr
		| protocol
		| ca
		| ca_server
		| ca_server_key
		| ca_client
		| ca_client_key
		| rules_dir
		;
		

local_addr	: T_LOCAL_ADDR T_STRING
		{
			nfts_inst.tcp.ipproto = AF_INET;
			if (parse_addr($2,
				       &nfts_inst.tcp.server.ipv4.inet_addr,
				       &nfts_inst.tcp.port) < 0)
				break;

			nfts_inst.mode = NFTS_MODE_SERVER;
		}
		;

remote_addr	: T_REMOTE_ADDR T_STRING
		{
			nfts_inst.tcp.ipproto = AF_INET;
			if (parse_addr($2, &nfts_inst.tcp.client.inet_addr,
				       &nfts_inst.tcp.port) < 0)
				break;

			nfts_inst.mode = NFTS_MODE_CLIENT;
		}
		;
		
protocol : T_PROTOCOL T_STRING
		{
			if (strcmp($2, "ssl") == 0) {
				nfts_inst.protocol = NFTS_PROTOCOL_SSL;
				break;
			}
			nfts_inst.protocol = NFTS_PROTOCOL_TCP;
		}
		;
	
ca : T_SSL_CA T_DIR
	{
		nfts_inst.ssl_ca = (char *)SSL_CA;
		if (!$2)
			break;

		nfts_inst.ssl_ca = $2;
	}
	;
		
ca_server : T_SSL_CA_SERVER T_DIR
		{
			nfts_inst.ssl_ca_server = (char *)SSL_CA_SERVER;
			if (!$2)
				break;

			nfts_inst.ssl_ca_server = $2;
		}
		;

ca_server_key : T_SSL_CA_SERVER_KEY T_DIR
		{
			nfts_inst.ssl_ca_server_key = (char *)SSL_CA_SERVER_KEY;
			if (!$2)
				break;

			nfts_inst.ssl_ca_server_key = $2;
		}
		;


ca_client : T_SSL_CA_CLIENT T_DIR
		{
			nfts_inst.ssl_ca_client = (char *)SSL_CA_CLIENT;
			if (!$2)
				break;

			nfts_inst.ssl_ca_client = $2;
		}
		;

ca_client_key : T_SSL_CA_CLIENT_KEY T_DIR
		{
			nfts_inst.ssl_ca_client_key = (char *)SSL_CA_CLIENT_KEY;
			if (!$2)
				break;

			nfts_inst.ssl_ca_client_key = $2;
		}
		;


rules_dir	: T_RULES_DIR T_DIR
		{
			nfts_inst.rules_dir = (char *)NFTS_RULES_DIR_DEFAULT;
			if (!$2)
				break;

			nfts_inst.rules_dir = $2;
			DIR* dir = opendir(nfts_inst.rules_dir);
			
			if (!dir) {
					fprintf(stderr, "Directory %s does not exists\n",nfts_inst.rules_dir);
				 	exit(EXIT_FAILURE);
			}
			xfree(dir);
		}
		;

log		: T_LOG T_STRING
		{
			if (strcmp($2, "syslog") == 0) {
				nfts_inst.log.type = NFTS_LOG_T_SYSLOG;
			} else if (strcmp($2, "stdout") == 0) {
				nfts_inst.log.type = NFTS_LOG_T_FILE;
				nfts_inst.log.color = true;
			} else {
				nfts_inst.log.type = NFTS_LOG_T_FILE;
				strncpy(nfts_inst.log.filename, $2, PATH_MAX);
				nfts_inst.log.filename[PATH_MAX - 1] = '\0';
			}
		}
		;

%%

int __attribute__((noreturn)) yyerror(char *msg)
{
	fprintf(stderr, "parsing config file in line (%d), symbol '%s': %s\n",
			 yylineno, yytext, msg);
	exit(EXIT_FAILURE);
}

int nft_sync_config_parse(const char *filename)
{
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open configuration file %s\n",
			filename);
		return -1;
	}

	yyrestart(fp);
	yyparse();
	fclose(fp);

	return 0;
}
