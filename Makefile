#
# Copyright (c) 2013, Joyent, Inc. All rights reserved.
#
# FWAPI Makefile
#


#
# Tools
#
NODEUNIT		:= ./node_modules/.bin/nodeunit


#
# Files
#
DOC_FILES	 = index.restdown rules.restdown
JS_FILES	:= $(shell ls *.js) $(shell find lib test -name '*.js') bin/wait-for-job
JSL_CONF_NODE	 = tools/jsl.node.conf
JSL_FILES_NODE   = $(JS_FILES)
JSSTYLE_FILES	 = $(JS_FILES)
JSSTYLE_FLAGS    = -o indent=4,doxygen,unparenthesized-return=0
SMF_MANIFESTS_IN = smf/manifests/fwapi.xml.in


NODE_PREBUILT_VERSION=v0.8.23
ifeq ($(shell uname -s),SunOS)
	NODE_PREBUILT_TAG=zone
	# Allow building on a smartos with a GCC version other than the
	# sdcnode GCC build boxes.
	NODE_PREBUILT_CC_VERSION=4.6.2
endif

include ./tools/mk/Makefile.defs
include ./tools/mk/Makefile.node_prebuilt.defs
ifeq ($(shell uname -s),SunOS)
	# Use an 'sdcnode' build on SmartOS.
	include ./tools/mk/Makefile.node_prebuilt.defs
else
	# Build a node locally on non-SmartOS (e.g. Mac).
	include ./tools/mk/Makefile.node.defs
endif
include ./tools/mk/Makefile.smf.defs


TOP             := $(shell pwd)
RELEASE_TARBALL := fwapi-pkg-$(STAMP).tar.bz2
PKGDIR          := $(TOP)/$(BUILD)/pkg
INSTDIR         := $(PKGDIR)/root/opt/smartdc/fwapi


#
# Repo-specific targets
#
.PHONY: all
all: $(SMF_MANIFESTS) | $(NODEUNIT) $(REPO_DEPS)
	$(NPM) rebuild

$(NODEUNIT): | $(NPM_EXEC)
	$(NPM) install

.PHONY: test
test: $(NODEUNIT)
	$(NODEUNIT) --reporter=tap test/unit/*.test.js

node_modules/fwrule/docs/rules.md: | $(NPM_EXEC)
	$(NPM) install fwrule

docs/rules.restdown: node_modules/fwrule/docs/rules.md
	cp docs/header.restdown docs/rules.restdown
	cat node_modules/fwrule/docs/rules.md >> docs/rules.restdown

CLEAN_FILES += ./node_modules $(BUILD)/docs docs/rules.restdown


#
# Packaging targets
#
.PHONY: release
release: $(RELEASE_TARBALL)

.PHONY: pkg
pkg: all $(SMF_MANIFESTS)
	@echo "Building $(RELEASE_TARBALL)"
	@rm -rf $(PKGDIR)
	@mkdir -p $(PKGDIR)/site
	@mkdir -p $(INSTDIR)/smf/manifests
	@touch $(PKGDIR)/site/.do-not-delete-me
	cp -r $(TOP)/server.js \
		$(TOP)/bin \
		$(TOP)/sbin \
		$(TOP)/lib \
		$(TOP)/node_modules \
		$(TOP)/sapi_manifests \
		$(INSTDIR)/
	cp -P smf/manifests/*.xml $(INSTDIR)/smf/manifests
	cp -PR $(NODE_INSTALL) $(INSTDIR)/node
	# Clean up some dev / build bits
	find $(INSTDIR) -name "*.pyc" | xargs rm -f
	find $(INSTDIR) -name "*.o" | xargs rm -f
	find $(INSTDIR) -name c4che | xargs rm -rf   # waf build file
	find $(INSTDIR) -name .wafpickle* | xargs rm -rf   # waf build file
	find $(INSTDIR) -name .lock-wscript | xargs rm -rf   # waf build file
	find $(INSTDIR) -name config.log | xargs rm -rf   # waf build file
	find $(INSTDIR) -name test | xargs rm -rf   # waf build file
	rm -rf $(INSTDIR)/node_modules/tap	# we don't need to run tests
	rm -rf $(INSTDIR)/node_modules/jison	# or to regenerate the parser

$(RELEASE_TARBALL): pkg
	(cd $(PKGDIR) && $(TAR) -jcf $(TOP)/$(RELEASE_TARBALL) root site)

.PHONY: publish
publish: release
	@if [[ -z "$(BITS_DIR)" ]]; then \
    echo "error: 'BITS_DIR' must be set for 'publish' target"; \
    exit 1; \
  fi
	mkdir -p $(BITS_DIR)/fwapi
	cp $(TOP)/$(RELEASE_TARBALL) $(BITS_DIR)/fwapi/$(RELEASE_TARBALL)


#
# Includes
#
include ./tools/mk/Makefile.deps
ifeq ($(shell uname -s),SunOS)
	include ./tools/mk/Makefile.node_prebuilt.targ
else
	include ./tools/mk/Makefile.node.targ
endif
include ./tools/mk/Makefile.smf.targ
include ./tools/mk/Makefile.targ
