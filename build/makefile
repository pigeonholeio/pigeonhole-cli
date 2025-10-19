# # -----------------------
# # Configuration
# # -----------------------

NAME := pigeonhole-cli
ARCH := amd64
MAINTAINER := "GPG <gpg@pigeono.io>"
GPG_KEY := "gpg@pigeono.io"

DEB_DIR := /repo/apt
RPM_DIR := /repo/rpm
WIN_DIR := /repo/choco
DIST_DIR := /dist
# BIN := $(DIST_DIR)/$(NAME)
BIN :=  /dist/default_linux_amd64_v1/pigeonhole
BIN_WIN := $(DIST_DIR)/$(NAME).exe

DEB_TMP_DIR := /tmp/deb_build

.SILENT: build-deb

copy-gpg:
	cp -r /root/.gnupgx /root/.gnupg

build-deb: copy-gpg
	@echo "==> Building .deb"
	rm -rf $(DEB_TMP_DIR)
	mkdir -p /release
	mkdir -p $(DEB_TMP_DIR)/DEBIAN
	mkdir -p $(DEB_TMP_DIR)/usr/local/bin
	cp $(BIN) $(DEB_TMP_DIR)/usr/local/bin/$(NAME)
	echo "Package: $(NAME)" > $(DEB_TMP_DIR)/DEBIAN/control
	echo "Version: $(VERSION)" >> $(DEB_TMP_DIR)/DEBIAN/control
	echo "Section: utils" >> $(DEB_TMP_DIR)/DEBIAN/control
	echo "Priority: optional" >> $(DEB_TMP_DIR)/DEBIAN/control
	echo "Architecture: amd64" >> $(DEB_TMP_DIR)/DEBIAN/control
	echo "Description: PigeonHole cli is the modern way to securely send secrets, files or any text" >> $(DEB_TMP_DIR)/DEBIAN/control
	echo "Maintainer: PigeonHole <info@pigeono.io>" >> $(DEB_TMP_DIR)/DEBIAN/control
	dpkg-deb --build $(DEB_TMP_DIR) /release/$(NAME)_$(VERSION)_amd64.deb

package-deb:
	reprepro -b /repo/apt includedeb noble /release/$(NAME)_*
	reprepro -b /repo/apt includedeb oracular /release/$(NAME)_*
	reprepro -b /repo/apt includedeb plucky /release/$(NAME)_*
	reprepro -b /repo/apt includedeb questing /release/$(NAME)_*

sign-deb:
	reprepro -b /repo/apt export
release-deb: build-deb package-deb sign-deb
	cd /repo/apt && git add . && git commit -m"Release $(VERSION)" && git push

import-gpg:
	gpg --import repo/gpg_secret.asc
	gpg-agent --daemon
	
# # -----------------------
# # RPM
# # -----------------------
# build-rpm:
# 	@echo "==> Building .rpm"
# 	mkdir -p $(RPM_DIR)/usr/local/bin
# 	cp $(BIN) $(RPM_DIR)/usr/local/bin/$(NAME)
# 	tar czf ~/rpmbuild/SOURCES/$(NAME)-$(VERSION).tar.gz -C $(RPM_DIR)/ .
# 	cat > ~/rpmbuild/SPECS/$(NAME).spec <<EOF
# Name:           $(NAME)
# Version:        $(VERSION)
# Release:        1%{?dist}
# Summary:        $(NAME) CLI tool

# License:        MIT
# URL:            https://pigeono.io
# Source0:        $(NAME)-$(VERSION).tar.gz
# BuildArch:      x86_64

# %description
# $(NAME) CLI tool built in Go.

# %install
# mkdir -p %{buildroot}/usr/local/bin
# cp -a usr/local/bin/$(NAME) %{buildroot}/usr/local/bin/$(NAME)

# %files
# /usr/local/bin/$(NAME)
# EOF
# 	rpmbuild -bb ~/rpmbuild/SPECS/$(NAME).spec
# 	cp ~/rpmbuild/RPMS/x86_64/$(NAME)-$(VERSION)-1.x86_64.rpm build/

# # -----------------------
# # Chocolatey
# # -----------------------
# build-choco:
# 	@echo "==> Building .nupkg"
# 	mkdir -p $(WIN_DIR)/tools
# 	cp $(BIN_WIN) $(WIN_DIR)/tools/
# 	cat > $(WIN_DIR)/tools/chocolateyinstall.ps1 <<EOF
# \$toolsDir = Split-Path -Parent \$MyInvocation.MyCommand.Definition
# \$exePath  = Join-Path \$toolsDir "$(NAME).exe"
# Copy-Item \$exePath "\$env:ChocolateyInstall\bin\$(NAME).exe" -Force
# EOF
# 	cat > $(WIN_DIR)/$(NAME).nuspec <<EOF
# <?xml version="1.0"?>
# <package>
#   <metadata>
#     <id>$(NAME)</id>
#     <version>$(VERSION)</version>
#     <title>$(NAME)</title>
#     <authors>Rhys Evans</authors>
#     <owners>Rhys Evans</owners>
#     <description>$(NAME) — Go-based CLI tool</description>
#     <summary>$(NAME) CLI</summary>
#     <requireLicenseAcceptance>false</requireLicenseAcceptance>
#   </metadata>
#   <files>
#     <file src="tools\**" target="tools" />
#   </files>
# </package>
# EOF
# 	(cd $(WIN_DIR) && choco pack $(NAME).nuspec)

# # -----------------------
# # Signing
# # -----------------------
# sign-all:
# 	@echo "==> Signing all packages with GPG key $(GPG_KEY)"
# 	@if [ -f build/$(NAME)_$(VERSION)_amd64.deb ]; then \
# 		dpkg-sig --sign builder -k $(GPG_KEY) build/$(NAME)_$(VERSION)_amd64.deb; \
# 	fi
# 	@if [ -f build/$(NAME)-$(VERSION)-1.x86_64.rpm ]; then \
# 		rpm --addsign build/$(NAME)-$(VERSION)-1.x86_64.rpm; \
# 	fi
# 	@if [ -f $(WIN_DIR)/$(NAME).$(VERSION).nupkg ]; then \
# 		gpg --detach-sign --armor --local-user $(GPG_KEY) $(WIN_DIR)/$(NAME).$(VERSION).nupkg; \
# 	fi

.PHONY: all clean build-deb build-rpm build-choco sign-all
