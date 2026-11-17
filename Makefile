# USBWatch for Linux
#
#   make install        install + enable autostart + start (root; detects systemd / OpenRC / SysV)
#   make uninstall      remove program and services, keep config/data/logs (root)
#   make purge          remove everything incl. config, database, vault, logs, account (root)
#   make test           unit tests (no root needed)
#   make lint           byte-compile for every supported syntax level + shell syntax check
#   make run-dev        run daemon + console from the source tree with a scratch data dir
#   make dist           source tarball            -> dist/usbwatch-linux-VERSION.tar.gz
#   make run-installer  self-extracting installer -> dist/usbwatch-VERSION.run
#   make deb            Debian/Ubuntu package     -> dist/usbwatch_VERSION_all.deb  (needs dpkg-deb)
#   make rpm            RHEL/Fedora/SUSE package  -> dist/usbwatch-VERSION-1.noarch.rpm (needs rpmbuild)
#
# Variables: PREFIX (default /usr/local), INIT (auto|systemd|openrc|sysvinit|none),
#            INSTALL_ARGS (extra install.sh options, e.g. INSTALL_ARGS="--password 'S3cret-pass!'")

PREFIX       ?= /usr/local
INIT         ?= auto
INSTALL_ARGS ?=
PYTHON       ?= python3
VERSION      := $(shell sed -n 's/^VERSION = "\(.*\)"/\1/p' usbwatch/__init__.py)
DIST         := dist
DEVDATA      := $(CURDIR)/build/devdata

.PHONY: all install uninstall purge test lint run-dev dist run-installer deb rpm packages clean help

all: help

help:
	@sed -n '3,16p' Makefile | sed 's/^# \{0,1\}//'

install:
	sh scripts/install.sh --prefix "$(PREFIX)" --init "$(INIT)" $(INSTALL_ARGS)

uninstall:
	sh scripts/uninstall.sh --prefix "$(PREFIX)"

purge:
	sh scripts/uninstall.sh --prefix "$(PREFIX)" --purge

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	$(PYTHON) -m compileall -q usbwatch tests packaging/launcher.py
	@for f in scripts/*.sh packaging/pkg-*.sh packaging/debian/postinst packaging/debian/prerm \
	          packaging/debian/postrm packaging/sysvinit/usbwatch packaging/sysvinit/usbwatch-web; do \
	    sh -n $$f || exit 1; done
	@command -v shellcheck >/dev/null && shellcheck -s sh scripts/*.sh packaging/pkg-*.sh || true
	@echo "lint ok"

# Unprivileged dev run: no blocking / fanotify, console on http://127.0.0.1:8790 (user admin / devpassword1)
run-dev:
	mkdir -p $(DEVDATA)
	USBWATCH_DATA=$(DEVDATA) USBWATCH_CONF=/nonexistent $(PYTHON) -c "from usbwatch import db; c=db.init('$(DEVDATA)/usbwatch.db'); \
	  c.execute('SELECT 1 FROM users').fetchone() or db.set_password(c,'admin','devpassword1'); c.commit()"
	USBWATCH_DATA=$(DEVDATA) USBWATCH_CONF=/nonexistent $(PYTHON) -m usbwatch daemon & \
	  USBWATCH_DATA=$(DEVDATA) USBWATCH_CONF=/nonexistent $(PYTHON) -m usbwatch web; kill %1

dist:
	mkdir -p $(DIST) build/usbwatch-linux-$(VERSION)
	cp -R usbwatch packaging scripts docs tests Makefile README.md build/usbwatch-linux-$(VERSION)/
	find build/usbwatch-linux-$(VERSION) -name __pycache__ -prune -exec rm -rf {} +
	tar -C build -czf $(DIST)/usbwatch-linux-$(VERSION).tar.gz usbwatch-linux-$(VERSION)
	rm -rf build/usbwatch-linux-$(VERSION)
	@echo "built $(DIST)/usbwatch-linux-$(VERSION).tar.gz"

run-installer:
	sh scripts/build_run.sh

deb:
	sh scripts/build_deb.sh

rpm: dist
	mkdir -p build/rpm/SOURCES build/rpm/SPECS
	cp $(DIST)/usbwatch-linux-$(VERSION).tar.gz build/rpm/SOURCES/
	sed 's/@VERSION@/$(VERSION)/' packaging/rpm/usbwatch.spec > build/rpm/SPECS/usbwatch.spec
	rpmbuild --define "_topdir $(CURDIR)/build/rpm" -bb build/rpm/SPECS/usbwatch.spec
	cp build/rpm/RPMS/noarch/usbwatch-$(VERSION)-*.rpm $(DIST)/
	@ls $(DIST)/*.rpm

packages: dist run-installer deb

clean:
	rm -rf build $(DIST)
	find . -name __pycache__ -prune -exec rm -rf {} +
