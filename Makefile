include config.mk

APP_NAME=stepca
PACKAGE=acf-$(APP_NAME)
VERSION=0.1.4

APP_DIST=\
	$(APP_NAME)*.lua \
	$(APP_NAME)*.lsp \
	$(APP_NAME).roles \
	$(APP_NAME).menu

# Support scripts and helpers
SUPPORT_SCRIPTS=

# doas configuration (source file has .doas suffix)
DOAS_CONF_SRC=stepca-download.conf.doas
DOAS_CONF_DEST=stepca-download.conf

EXTRA_DIST=README Makefile config.mk lsp-check.awk

DISTFILES=$(APP_DIST) $(SUPPORT_SCRIPTS) $(CGI_SCRIPT) $(DOAS_CONF_SRC) $(EXTRA_DIST)

TAR=tar

P=$(PACKAGE)-$(VERSION)
tarball=$(P).tar.bz2
install_dir=$(DESTDIR)/$(appdir)/$(APP_NAME)

all:
clean:
	rm -rf $(tarball) $(P)

check:
	# Lint Lua files
	luacheck $(APP_NAME)*.lua
	# Syntax check LSP files: extract statement blocks only (see lsp-check.awk)
	for f in $(APP_NAME)*.lsp; do \
		awk -f lsp-check.awk "$$f" | luac -p - || exit 1; \
	done
	# Lint shell scripts (if any)
	if [ -n "$(SUPPORT_SCRIPTS)" ]; then shellcheck -s ash $(SUPPORT_SCRIPTS); fi

dist: $(tarball)

install:
	mkdir -p "$(install_dir)"
	# Use sed to inject libexecdir path into Lua files
	for f in $(APP_NAME)*.lua; do \
		sed 's|@@LIBEXECDIR@@|$(libexecdir)|g' "$$f" > "$(install_dir)/$$f"; \
	done
	# Copy LSP and other files
	cp $(APP_NAME)*.lsp $(APP_NAME).roles $(APP_NAME).menu "$(install_dir)/"

	# doas configuration
	# Install doas configuration (strip .doas suffix and inject libexecdir)
	mkdir -p "$(DESTDIR)/etc/doas.d"
	sed 's|@@LIBEXECDIR@@|$(libexecdir)|g' $(DOAS_CONF_SRC) > "$(DESTDIR)/etc/doas.d/$(DOAS_CONF_DEST)"
	chmod 0600 "$(DESTDIR)/etc/doas.d/$(DOAS_CONF_DEST)"

$(tarball):	$(DISTFILES)
	rm -rf $(P)
	mkdir -p $(P)
	cp -a $(DISTFILES) $(P)
	$(TAR) -jcf $@ $(P)
	rm -rf $(P)


dist-install: $(tarball)
	$(TAR) -jxf $(tarball)
	$(MAKE) -C $(P) install DESTDIR=$(DESTDIR)
	rm -rf $(P)

.PHONY: all clean dist install dist-install
