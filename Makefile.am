include Make_global.am

ACLOCAL_AMFLAGS  = -I m4

man_MANS =
EXTRA_DIST = $(man_MANS) Make_global.am m4 contrib

SUBDIRS   = src
DIST_SUBDIRS = include src tests
LIBS = @LIBMNL_LIBS@ @LIBNFTNL_LIBS@ @LIBSSL_LIBS@

INST_DIR = /etc/nft-sync

install-exec-hook:
	mkdir -p $(INST_DIR)/rules
	mkdir -p $(INST_DIR)/ca/private
	cp contrib/nft-sync.conf.server $(INST_DIR)/nft-sync.conf
