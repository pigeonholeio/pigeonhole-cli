# # -----------------------
# # Configuration
# # -----------------------

NAME := pigeonhole-cli
ARCH := amd64
MAINTAINER := "GPG <gpg@pigeono.io>"
GPG_KEY := "gpg@pigeono.io"
GPG_KEY_ID := BCF5FB0D9B5BAB90

DEB_DIR := /repo/apt
RPM_DIR := /repo/rpm
WIN_DIR := /repo/choco
DIST_DIR := /dist
# BIN := $(DIST_DIR)/$(NAME)
BIN :=  /dist/default_linux_amd64_v1/pigeonhole
BIN_WIN := $(DIST_DIR)/$(NAME).exe

DEB_TMP_DIR := /tmp/deb_build
RPM_TMP_DIR := /tmp/rpm_build


DESCRIPTION := "PigeonHole cli is the modern way to send secrets, files or any text securely"

.SILENT: build-deb

copy-gpg:
	mkdir -p /root/.gnupg
	-cp -r /root/.gnupgx/* /root/.gnupg

build-deb: copy-gpg
	@echo "==> Building for $${XVERSION}: $(DESCRIPTION)"
	@fpm -s dir -t deb \
		-n pigeonhole-cli \
		-v "$${XVERSION}" \
		--architecture amd64 \
		--description $(DESCRIPTION) \
		--license "MIT" \
		--maintainer "PigeonHole <info@pigeono.io>" \
		--url "https://pigeono.io" \
		/dist/default_linux_amd64_v1/pigeonhole=/usr/local/bin/pigeonhole

# 	cp $(BIN) $(DEB_TMP_DIR)/usr/local/bin/pigeonhole
# 	echo "Package: $(NAME)" > $(DEB_TMP_DIR)/DEBIAN/control
# 	echo "Version: $(XVERSION)" >> $(DEB_TMP_DIR)/DEBIAN/control
# 	echo "Section: utils" >> $(DEB_TMP_DIR)/DEBIAN/control
# 	echo "Priority: optional" >> $(DEB_TMP_DIR)/DEBIAN/control
# 	echo "Architecture: amd64" >> $(DEB_TMP_DIR)/DEBIAN/control
# 	echo "Description: $(DESCRIPTION)" >> $(DEB_TMP_DIR)/DEBIAN/control
# 	echo "Maintainer: PigeonHole <info@pigeono.io>" >> $(DEB_TMP_DIR)/DEBIAN/control
# 	dpkg-deb --build $(DEB_TMP_DIR) /release/$(NAME)_$(XVERSION)_amd64.deb 

	reprepro -b /repo/apt includedeb noble ./$(NAME)_*
	reprepro -b /repo/apt includedeb oracular ./$(NAME)_*
	reprepro -b /repo/apt includedeb plucky ./$(NAME)_*
	reprepro -b /repo/apt includedeb questing ./$(NAME)_*
	reprepro -b /repo/apt export

build-rpm: copy-gpg
	@mkdir -p /repo/rpm/dist
	@echo "==> Building rpm"	
	@fpm -s dir -t rpm \
		-n pigeonhole-cli \
		-v "$(XVERSION)" \
		--architecture amd64 \
		--description $(DESCRIPTION) \
		--license "MIT" \
		--maintainer "PigeonHole <info@pigeono.io>" \
		--url "https://pigeono.io" \
		/dist/default_linux_amd64_v1/pigeonhole=/usr/local/bin/pigeonhole
	@mv ./*.rpm /repo/rpm/dist/
	@createrepo --update /repo/rpm
	@rpm --define "_gpg_name $(GPG_KEY_ID)" --addsign /repo/rpm/dist/*.rpm
	@gpg --batch --pinentry-mode=loopback --yes --detach-sign --armor --local-user $(GPG_KEY_ID) /repo/rpm/repodata/repomd.xml

push-repo:
	cd /repo && git add . && git commit -m"Release $(XVERSION)" && git push

# -----------------------
# Chocolatey
# -----------------------

build-choco: copy-gpg
	@echo "==> Building Chocolatey package (.nupkg) for version $(XVERSION)"
	@mkdir -p /tmp/choco_build/tools
	@mkdir -p /repo/choco

	# Copy Windows binary to choco build directory
	@cp /dist/default_windows_amd64_v1/pigeonhole.exe /tmp/choco_build/tools/

	# Calculate SHA256 checksum of the binary
	@CHECKSUM=$$(sha256sum /dist/default_windows_amd64_v1/pigeonhole.exe | awk '{print $$1}') && \
	  sed -e "s|{{VERSION}}|$(XVERSION)|g" \
	      -e "s|{{CHECKSUM}}|$$CHECKSUM|g" \
	      /app/build/choco/pigeonhole-cli.nuspec.template > /tmp/choco_build/pigeonhole-cli.nuspec && \
	  echo "Generated nuspec with checksum: $$CHECKSUM"


	# Generate VERIFICATION.txt with actual version and checksum
	@CHECKSUM=$$(sha256sum /dist/default_windows_amd64_v1/pigeonhole.exe | awk '{print $$1}') && \
	  sed -e "s|{{VERSION}}|$(XVERSION)|g" \
	      -e "s|{{CHECKSUM}}|$$CHECKSUM|g" \
	      -e "s|{{GOVERSION}}|1.21|g" \
	      /app/build/choco/tools/VERIFICATION.txt > /tmp/choco_build/tools/VERIFICATION.txt

	# Copy license file
	@cp /app/build/choco/LICENSE.txt /tmp/choco_build/

	# Build the package using nuget (nuget.exe requires mono on Linux)
	@cd /tmp/choco_build && mono /usr/local/bin/nuget pack pigeonhole-cli.nuspec -OutputDirectory /repo/choco
	@echo "✓ Chocolatey package built successfully"

	# Sign the package with GPG
	@if [ -f /repo/choco/pigeonhole-cli.$(XVERSION).nupkg ]; then \
	  echo "Signing Chocolatey package..."; \
	  gpg --batch --pinentry-mode=loopback --yes --detach-sign --armor \
	      --local-user $(GPG_KEY_ID) /repo/choco/pigeonhole-cli.$(XVERSION).nupkg; \
	  echo "✓ Package signed successfully"; \
	fi

push-choco:
	@echo "==> Pushing Chocolatey package to community repository"
	@if [ -z "$(CHOCO_API_KEY)" ]; then \
	  echo "Error: CHOCO_API_KEY environment variable not set"; \
	  exit 1; \
	fi
	@if [ ! -f /repo/choco/pigeonhole-cli.$(XVERSION).nupkg ]; then \
	  echo "Error: Package not found at /repo/choco/pigeonhole-cli.$(XVERSION).nupkg"; \
	  exit 1; \
	fi
	@docker run --rm \
	  -e CHOCO_API_KEY=$(CHOCO_API_KEY) \
	  -v /repo/choco:/packages:ro \
	  chocolatey/choco:latest \
	  choco push /packages/pigeonhole-cli.$(XVERSION).nupkg \
	    --source https://push.chocolatey.org/ \
	    --api-key $(CHOCO_API_KEY)
	@echo "✓ Package pushed successfully"

# -----------------------
# MSI Package
# -----------------------

build-msi: copy-gpg
	@echo "==> Building MSI package (.msi) for version $(XVERSION)"
	@mkdir -p /tmp/msi_build
	@mkdir -p /repo/msi

	# Copy Windows binary to msi build directory
	@cp /dist/default_windows_amd64_v1/pigeonhole.exe /tmp/msi_build/

	# Copy wix.json and LICENSE
	@cp /app/build/msi/wix.json /tmp/msi_build/
	@cp /app/build/msi/LICENSE /tmp/msi_build/

	# Generate MSI using go-msi
	@cd /tmp/msi_build && \
	  go-msi make --msi pigeonhole-cli-$(XVERSION)-amd64.msi \
	               --version $(XVERSION) \
	               --arch amd64 \
	               --src /tmp/msi_build \
	               --out /repo/msi

	@echo "✓ MSI package built successfully at /repo/msi/pigeonhole-cli-$(XVERSION)-amd64.msi"

	# Sign the MSI with GPG (optional, for integrity verification)
	@if [ -f /repo/msi/pigeonhole-cli-$(XVERSION)-amd64.msi ]; then \
	  echo "Signing MSI package..."; \
	  gpg --batch --pinentry-mode=loopback --yes --detach-sign --armor \
	      --local-user $(GPG_KEY_ID) /repo/msi/pigeonhole-cli-$(XVERSION)-amd64.msi; \
	  echo "✓ MSI signed successfully"; \
	fi

	# Calculate SHA256 checksum
	@sha256sum /repo/msi/pigeonhole-cli-$(XVERSION)-amd64.msi > /repo/msi/pigeonhole-cli-$(XVERSION)-amd64.msi.sha256
	@echo "✓ Checksum generated"

push-msi:
	@echo "==> MSI packages are distributed via GitHub releases"
	@echo "    No separate push required - they will be uploaded during 'make release'"

# 	@echo "==> Building .rpm"
# 	mkdir -p $(RPM_TMP_DIR)/usr/local/bin
# 	cp $(BIN) $(RPM_TMP_DIR)/usr/local/bin/$(NAME)
	
# 	cat > ~/rpmbuild/SPECS/$(NAME).spec <<EOF
# 	Name:           $(NAME)
# 	Version:        $(VERSION)
# 	Release:        1%{?dist}
# 	Summary:        $(NAME) tool

# 	License:        MIT
# 	URL:            https://pigeono.io
# 	Source0:        $(NAME)-$(XVERSION).tar.gz
# 	BuildArch:      x86_64

# 	%description
# 	$(DESCRIPTION)

# 	%install
# 	mkdir -p %{buildroot}/usr/local/bin
# 	cp -a usr/local/bin/$(NAME) %{buildroot}/usr/local/bin/$(NAME)

# 	%files
# 	/usr/local/bin/$(NAME)
# 	EOF

# 	rpmbuild -bb ~/rpmbuild/SPECS/$(NAME).spec
# 	cp ~/rpmbuild/RPMS/x86_64/$(NAME)-$(VERSION)-1.x86_64.rpm repo/rpm/

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

.PHONY: all clean copy-gpg build-deb build-rpm build-choco build-msi push-repo push-choco push-msi
